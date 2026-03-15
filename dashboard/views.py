import json
import os
from pathlib import Path

from django.conf import settings as django_settings
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Sum, Count

from scanner.models import ScanTarget, Scan, Alert, MonthlySummary, OrganizationProfile, AlertAIAnalysis, PentestAgreement, TeamCertificate
from scanner.services import ZAPClient


@login_required
def index(request):
    """Dashboard homepage with summary stats and recent scans."""
    scans = Scan.objects.select_related('target').all()[:20]

    # Overall stats
    completed = Scan.objects.filter(status=Scan.Status.COMPLETED)
    stats = completed.aggregate(
        total_scans=Count('id'),
        avg_risk=Avg('risk_score'),
        total_high=Sum('high_count'),
        total_medium=Sum('medium_count'),
        total_low=Sum('low_count'),
        total_info=Sum('info_count'),
    )
    stats['total_alerts'] = (
        (stats.get('total_high') or 0) +
        (stats.get('total_medium') or 0) +
        (stats.get('total_low') or 0) +
        (stats.get('total_info') or 0)
    )

    # ZAP status
    zap_ok = False
    zap_version = ''
    try:
        client = ZAPClient()
        zap_version = client.get_version()
        zap_ok = True
    except Exception:
        pass

    targets = ScanTarget.objects.annotate(scan_count=Count('scans'))

    return render(request, 'dashboard/index.html', {
        'scans': scans,
        'stats': stats,
        'targets': targets,
        'zap_ok': zap_ok,
        'zap_version': zap_version,
    })


@login_required
def scan_new(request):
    """Form to start a new scan."""
    if request.method == 'POST':
        tool = request.POST.get('tool', 'zap')
        scan_type = request.POST.get('scan_type', 'full')
        tool_label = dict(Scan.ToolSource.choices).get(tool, tool)

        # ── File Upload tools (Trivy / SonarQube) ─────────────────────────
        if tool in ('trivy', 'sonarqube'):
            return _handle_file_upload(request, tool, tool_label)

        # ── Server-fetch tools (OpenVAS / Wazuh) ──────────────────────────
        if tool in ('openvas', 'wazuh'):
            target_url = tool
            target_name = tool_label
        else:
            target_url = request.POST.get('target_url', '').strip()
            target_name = request.POST.get('target_name', '').strip() or target_url
            if not target_url:
                messages.error(request, 'Target URL is required.')
                return render(request, 'dashboard/scan_new.html')

        from scanner.views import _run_scan_background
        from django.utils import timezone
        import threading

        target, _ = ScanTarget.objects.get_or_create(
            url=target_url,
            defaults={'name': target_name}
        )
        scan = Scan.objects.create(
            target=target,
            scan_type=scan_type,
            tool=tool,
            status=Scan.Status.PENDING,
            started_at=timezone.now(),
        )

        agent_id = request.POST.get('agent_id', '').strip() or None
        task_id = request.POST.get('task_id', '').strip() or None

        thread = threading.Thread(
            target=_run_scan_background,
            args=(scan.id, target_url, scan_type, tool),
            kwargs={'agent_id': agent_id, 'task_id': task_id},
            daemon=True,
        )
        thread.start()

        messages.success(request, f'{tool_label} scan started for {target_url}')
        return redirect('dashboard-scan-detail', scan_id=scan.id)

    return render(request, 'dashboard/scan_new.html')


def _handle_file_upload(request, tool, tool_label):
    """Parse uploaded Trivy/SonarQube report file and create a completed Scan."""
    from django.utils import timezone
    from scanner.views import _store_findings, _update_monthly_summary

    uploaded_file = request.FILES.get('result_file')
    if not uploaded_file:
        messages.error(request, f'กรุณาอัปโหลดไฟล์ผล {tool_label}')
        return render(request, 'dashboard/scan_new.html')

    # Size guard: 50 MB
    if uploaded_file.size > 50 * 1024 * 1024:
        messages.error(request, 'ไฟล์ใหญ่เกิน 50 MB')
        return render(request, 'dashboard/scan_new.html')

    try:
        content = uploaded_file.read().decode('utf-8')
    except UnicodeDecodeError:
        messages.error(request, 'ไฟล์ต้องเป็น UTF-8 encoding')
        return render(request, 'dashboard/scan_new.html')

    # Parse
    try:
        if tool == 'trivy':
            from scanner.trivy_scanner import TrivyClient
            findings = TrivyClient.parse_file_content(content)
        else:
            from scanner.sonarqube_client import SonarQubeClient
            findings = SonarQubeClient.parse_file_content(content, uploaded_file.name)
    except ValueError as exc:
        messages.error(request, f'Parse ล้มเหลว: {exc}')
        return render(request, 'dashboard/scan_new.html')

    target_name = request.POST.get('target_name', '').strip() or uploaded_file.name
    target_url = f'{tool}://{uploaded_file.name}'

    target, _ = ScanTarget.objects.get_or_create(
        url=target_url,
        defaults={'name': target_name}
    )
    scan = Scan.objects.create(
        target=target,
        scan_type='full',
        tool=tool,
        status=Scan.Status.RUNNING,
        started_at=timezone.now(),
    )

    try:
        _store_findings(scan, findings, tool)
        scan.status = Scan.Status.COMPLETED
        scan.completed_at = timezone.now()
        scan.save()
        _update_monthly_summary(scan)
        messages.success(
            request,
            f'{tool_label}: import {len(findings)} findings จาก {uploaded_file.name}'
        )
    except Exception as exc:
        scan.status = Scan.Status.FAILED
        scan.save(update_fields=['status'])
        messages.error(request, f'Import ล้มเหลว: {exc}')

    return redirect('dashboard-scan-detail', scan_id=scan.id)


@login_required
def scan_detail(request, scan_id):
    """Scan detail with alerts table and charts."""
    scan = get_object_or_404(Scan.objects.select_related('target'), id=scan_id)

    # Only load High + Medium — Low/Info shown as counts only
    alerts_qs = scan.alerts.filter(risk__gte=2).order_by('-risk', '-cvss_score')

    # Group by (name, cwe_id, cvss_score) → parent with list of child URLs
    seen = {}
    for alert in alerts_qs:
        key = (alert.name, alert.cwe_id, alert.cvss_score)
        if key not in seen:
            seen[key] = {
                'name': alert.name,
                'risk': alert.risk,
                'severity': alert.severity,
                'cvss_score': alert.cvss_score,
                'cvss_vector': alert.cvss_vector,
                'cwe_id': alert.cwe_id,
                'wasc_id': alert.wasc_id,
                'owasp_category': alert.owasp_category,
                'description': alert.description,
                'solution': alert.solution,
                'evidence': alert.evidence,
                'urls': [],
                'url_entries': [],
                'cve_ids': set(),
                'has_public_exploit': False,
                'in_cisa_kev': False,
                'exploit_refs': [],
            }
        if alert.url and alert.url not in seen[key]['urls']:
            seen[key]['urls'].append(alert.url)
            seen[key]['url_entries'].append({'url': alert.url, 'param': alert.param or ''})
        seen[key]['cve_ids'].update(alert.cve_ids or [])
        if alert.has_public_exploit:
            seen[key]['has_public_exploit'] = True
        if alert.in_cisa_kev:
            seen[key]['in_cisa_kev'] = True
        for ref in (alert.exploit_refs or []):
            if ref not in seen[key]['exploit_refs']:
                seen[key]['exploit_refs'].append(ref)

    grouped_alerts = list(seen.values())
    for g in grouped_alerts:
        g['cve_ids'] = sorted(g['cve_ids'])

    # Merge AI analyses (keyed by name + cwe_id)
    ai_lookup = {
        (a.name, a.cwe_id): a
        for a in scan.ai_analyses.all()
    }
    for g in grouped_alerts:
        g['ai'] = ai_lookup.get((g['name'], g['cwe_id'] or 0))

    has_ai = bool(ai_lookup)

    # Severity distribution for chart
    severity_data = {
        'High': scan.high_count,
        'Medium': scan.medium_count,
        'Low': scan.low_count,
        'Info': scan.info_count,
    }

    # Top vulnerabilities by CVSS (unique)
    top_vulns = alerts_qs.order_by('-cvss_score')[:10]
    top_vulns_json = json.dumps([
        {'name': v.name[:30], 'cvss_score': v.cvss_score, 'severity': v.severity}
        for v in top_vulns
    ])

    openai_configured = bool(getattr(django_settings, 'OPENAI_API_KEY', ''))

    # Spider scan: pass discovered URL list
    spider_urls = []
    if scan.scan_type == 'spider' and isinstance(scan.raw_json, dict):
        spider_urls = scan.raw_json.get('spider_urls', [])

    return render(request, 'dashboard/scan_detail.html', {
        'scan': scan,
        'grouped_alerts': grouped_alerts,
        'severity_data': json.dumps(severity_data),
        'top_vulns': top_vulns,
        'top_vulns_json': top_vulns_json,
        'has_ai': has_ai,
        'openai_configured': openai_configured,
        'spider_urls': spider_urls,
    })


@login_required
def scan_stop(request, scan_id):
    """Stop a running scan via dashboard."""
    if request.method == 'POST':
        from scanner.views import stop_scan as _stop_scan
        from rest_framework.test import APIRequestFactory
        try:
            factory = APIRequestFactory()
            api_req = factory.post(f'/api/scans/{scan_id}/stop/')
            response = _stop_scan(api_req, scan_id=scan_id)
            data = response.data
            if response.status_code == 200:
                alerts = data.get('alerts_collected', 0)
                messages.success(request, f'Scan stopped. {alerts} alerts collected.')
            else:
                messages.warning(request, data.get('error', 'Failed to stop scan.'))
        except Exception as e:
            messages.error(request, f'Error stopping scan: {e}')
    return redirect('dashboard-scan-detail', scan_id=scan_id)


@login_required
def scan_ai_analyze(request, scan_id):
    """Trigger AI analysis for grouped High/Medium alerts and save to DB."""
    if request.method != 'POST':
        return redirect('dashboard-scan-detail', scan_id=scan_id)

    scan = get_object_or_404(Scan.objects.select_related('target'), id=scan_id)

    if not getattr(django_settings, 'OPENAI_API_KEY', ''):
        messages.error(request, 'OPENAI_API_KEY ยังไม่ได้ตั้งค่า กรุณาใส่ใน Settings > OpenAI')
        return redirect('dashboard-scan-detail', scan_id=scan_id)

    # Rebuild grouped_alerts — High (3) and Medium (2) only
    alerts_qs = scan.alerts.filter(risk__in=[2, 3]).order_by('-risk', '-cvss_score')
    seen = {}
    for alert in alerts_qs:
        key = (alert.name, alert.cwe_id, alert.cvss_score)
        if key not in seen:
            seen[key] = {
                'name': alert.name, 'risk': alert.risk,
                'cvss_score': alert.cvss_score, 'cwe_id': alert.cwe_id,
                'description': alert.description, 'evidence': alert.evidence,
                'urls': [],
            }
        if alert.url and alert.url not in seen[key]['urls']:
            seen[key]['urls'].append(alert.url)
    grouped_alerts = list(seen.values())

    if not grouped_alerts:
        messages.warning(request, 'ไม่มี High/Medium alerts ให้วิเคราะห์')
        return redirect('dashboard-scan-detail', scan_id=scan_id)

    try:
        from scanner.ai_analyst import analyze_scan
        count = analyze_scan(scan, grouped_alerts)
        messages.success(request, f'AI วิเคราะห์สำเร็จ {count} ช่องโหว่ ใช้โมเดล {django_settings.OPENAI_MODEL}')
    except ValueError as exc:
        messages.error(request, str(exc))
    except Exception as exc:
        messages.error(request, f'AI วิเคราะห์ล้มเหลว: {exc}')

    return redirect('dashboard-scan-detail', scan_id=scan_id)


@login_required
def scan_exploit_check(request, scan_id):
    """Re-run exploit enrichment (CISA KEV + searchsploit) for an existing scan."""
    if request.method != 'POST':
        return redirect('dashboard-scan-detail', scan_id=scan_id)

    scan = get_object_or_404(Scan.objects.select_related('target'), id=scan_id)

    try:
        from scanner.views import _enrich_exploits
        _enrich_exploits(scan)
        exploit_count = scan.alerts.filter(has_public_exploit=True).count()
        kev_count = scan.alerts.filter(in_cisa_kev=True).count()
        messages.success(
            request,
            f'Exploit check เสร็จสิ้น — พบ {exploit_count} alerts มี public exploit'
            + (f' ({kev_count} CISA KEV)' if kev_count else '')
        )
    except Exception as exc:
        messages.error(request, f'Exploit check ล้มเหลว: {exc}')

    return redirect('dashboard-scan-detail', scan_id=scan_id)


@login_required
def report_builder(request):
    """Select scans to combine into a multi-tool OWASP report."""
    targets = ScanTarget.objects.annotate(scan_count=Count('scans')).order_by('name')
    scans = (
        Scan.objects
        .select_related('target')
        .annotate(ai_count=Count('ai_analyses'))
        .order_by('target__name', '-started_at')
    )
    selected_target = request.GET.get('target', '')
    return render(request, 'dashboard/report_builder.html', {
        'targets': targets,
        'scans': scans,
        'selected_target': selected_target,
    })


@login_required
def scan_delete(request, scan_id):
    """Delete a scan."""
    scan = get_object_or_404(Scan, id=scan_id)
    if request.method == 'POST':
        scan.delete()
        messages.success(request, 'Scan deleted.')
        return redirect('dashboard-index')
    return render(request, 'dashboard/confirm_delete.html', {'scan': scan})


@login_required
def scans_bulk_delete(request):
    """Bulk-delete scans from report builder (POST with scan_ids list)."""
    if request.method != 'POST':
        return redirect('dashboard-report-builder')
    scan_ids = request.POST.getlist('scan_ids')
    if not scan_ids:
        messages.warning(request, 'ไม่ได้เลือก scan ใด')
        return redirect('dashboard-report-builder')
    deleted_count, _ = Scan.objects.filter(id__in=scan_ids).delete()
    messages.success(request, f'ลบ {deleted_count} scan เรียบร้อยแล้ว')
    # Preserve target filter if provided
    next_url = request.POST.get('next', '')
    if next_url:
        return redirect(next_url)
    return redirect('dashboard-report-builder')


@login_required
def trends(request):
    """Monthly trend charts."""
    summaries = MonthlySummary.objects.select_related('target').order_by('year_month')[:24]
    targets = ScanTarget.objects.all()

    target_id = request.GET.get('target')
    if target_id:
        summaries = summaries.filter(target_id=target_id)

    # Build chart data
    labels = [s.year_month.strftime('%Y-%m') for s in summaries]
    risk_scores = [s.avg_risk_score for s in summaries]
    highs = [s.high_count for s in summaries]
    mediums = [s.medium_count for s in summaries]
    lows = [s.low_count for s in summaries]

    return render(request, 'dashboard/trends.html', {
        'summaries': summaries,
        'targets': targets,
        'selected_target': target_id,
        'chart_labels': labels,
        'chart_risk_scores': risk_scores,
        'chart_highs': highs,
        'chart_mediums': mediums,
        'chart_lows': lows,
    })


@login_required
def trend_delete(request, pk):
    """Delete a MonthlySummary record (POST only). pk is UUID."""
    if request.method == 'POST':
        summary = get_object_or_404(MonthlySummary, pk=str(pk))
        summary.delete()
        messages.success(request, 'Trend record deleted.')
    return redirect('dashboard-trends')


@login_required
def organization_list(request):
    """List all organization profiles."""
    orgs = OrganizationProfile.objects.all()
    return render(request, 'dashboard/organization_list.html', {'orgs': orgs})


def _save_org_from_post(org, post, files):
    """Copy POST data into an OrganizationProfile instance (no save)."""
    org.name_th = post.get('name_th', '')
    org.name_en = post.get('name_en', '')
    org.address = post.get('address', '')
    org.phone = post.get('phone', '')
    org.email = post.get('email', '')
    org.preparer_name = post.get('preparer_name', '')
    org.preparer_title = post.get('preparer_title', '')
    org.approver_name = post.get('approver_name', '')
    org.approver_title = post.get('approver_title', '')
    org.document_number_prefix = post.get('document_number_prefix', 'VA-RPT-')
    if files.get('logo'):
        org.logo = files['logo']
    if post.get('clear_logo') == '1':
        org.logo = ''


@login_required
def organization_new(request):
    """Create a new organization profile."""
    if request.method == 'POST':
        org = OrganizationProfile()
        _save_org_from_post(org, request.POST, request.FILES)
        org.save()
        if request.POST.get('set_default') == '1':
            org.set_as_default()
        messages.success(request, 'เพิ่มหน่วยงานเรียบร้อยแล้ว')
        return redirect('dashboard-organization')
    return render(request, 'dashboard/organization.html', {'org': None})


@login_required
def organization_edit(request, pk):
    """Edit an existing organization profile."""
    org = get_object_or_404(OrganizationProfile, pk=pk)
    if request.method == 'POST':
        _save_org_from_post(org, request.POST, request.FILES)
        org.save()
        if request.POST.get('set_default') == '1':
            org.set_as_default()
        messages.success(request, 'บันทึกข้อมูลหน่วยงานเรียบร้อยแล้ว')
        return redirect('dashboard-organization')
    return render(request, 'dashboard/organization.html', {'org': org})


@login_required
def organization_delete(request, pk):
    """Delete an organization profile."""
    org = get_object_or_404(OrganizationProfile, pk=pk)
    if request.method == 'POST':
        org.delete()
        messages.success(request, 'ลบหน่วยงานเรียบร้อยแล้ว')
        return redirect('dashboard-organization')
    return render(request, 'dashboard/organization_confirm_delete.html', {'org': org})


@login_required
def organization_set_default(request, pk):
    """Set an organization as the default."""
    if request.method == 'POST':
        org = get_object_or_404(OrganizationProfile, pk=pk)
        org.set_as_default()
        messages.success(request, f'ตั้ง "{org.name_th}" เป็นหน่วยงานหลักแล้ว')
    return redirect('dashboard-organization')


# Keep old name as alias so any stale references still resolve
organization_profile = organization_list


def api_stats(request):
    """JSON endpoint for Chart.js."""
    scan_id = request.GET.get('scan')
    if scan_id:
        scan = get_object_or_404(Scan, id=scan_id)
        return JsonResponse({
            'severity': {
                'High': scan.high_count,
                'Medium': scan.medium_count,
                'Low': scan.low_count,
                'Info': scan.info_count,
            },
            'risk_score': scan.risk_score,
        })

    # Overall stats
    completed = Scan.objects.filter(status=Scan.Status.COMPLETED)
    stats = completed.aggregate(
        total_high=Sum('high_count'),
        total_medium=Sum('medium_count'),
        total_low=Sum('low_count'),
        total_info=Sum('info_count'),
    )
    return JsonResponse({
        'severity': {
            'High': stats['total_high'] or 0,
            'Medium': stats['total_medium'] or 0,
            'Low': stats['total_low'] or 0,
            'Info': stats['total_info'] or 0,
        },
    })


def scan_status_api(request, scan_id):
    """JSON endpoint to poll scan status."""
    scan = get_object_or_404(Scan, id=scan_id)
    return JsonResponse({
        'status': scan.status,
        'high_count': scan.high_count,
        'medium_count': scan.medium_count,
        'low_count': scan.low_count,
        'info_count': scan.info_count,
        'risk_score': scan.risk_score,
        'total_alerts': scan.total_alerts,
    })


@login_required
def api_wazuh_agents(request):
    """JSON endpoint to list Wazuh agents for the dropdown."""
    try:
        from scanner.wazuh_client import WazuhClient
        client = WazuhClient()
        agents = client.get_agents()
        result = [
            {
                'id': a.get('id', ''),
                'name': a.get('name', ''),
                'ip': a.get('ip', ''),
                'status': a.get('status', ''),
            }
            for a in agents
        ]
        return JsonResponse({'agents': result})
    except Exception as e:
        return JsonResponse({'error': str(e), 'agents': []}, status=500)


@login_required
def api_openvas_tasks(request):
    """JSON endpoint to list OpenVAS tasks for the dropdown."""
    try:
        from scanner.openvas_client import OpenVASClient
        client = OpenVASClient()
        tasks = client.get_tasks()
        result = [
            {
                'id': t.get('id', ''),
                'name': t.get('name', ''),
                'status': t.get('status', ''),
            }
            for t in tasks
        ]
        return JsonResponse({'tasks': result})
    except Exception as e:
        return JsonResponse({'error': str(e), 'tasks': []}, status=500)


def api_cwe_cves(request):
    """JSON endpoint: look up NVD CVEs for a given CWE ID.

    GET /api/cwe-cves/?cwe=79
    Returns: {"cves": [{"id", "cvss", "cvss_vector", "severity", "description",
                        "published", "nvd_url"}, ...]}
    Cached for 1 hour per CWE. No auth required (rate-limited by NVD).
    """
    cwe_id = request.GET.get('cwe', '').strip().lstrip('CWEcwe-')
    if not cwe_id:
        return JsonResponse({'error': 'cwe parameter required', 'cves': []}, status=400)

    from scanner.cve_enrichment import lookup_nvd_cves
    api_key = getattr(django_settings, 'NVD_API_KEY', '')
    cves = lookup_nvd_cves(cwe_id, limit=10, api_key=api_key)
    return JsonResponse({'cves': cves})


# ── Settings Page ─────────────────────────────────────────────────────────

# Fields editable via the web UI — grouped for display
SETTINGS_FIELDS = [
    {
        'group': 'OWASP ZAP',
        'tool_id': 'zap',
        'icon': 'bi-bug',
        'fields': [
            {'key': 'ZAP_BASE_URL', 'label': 'ZAP Base URL', 'type': 'url', 'placeholder': 'http://127.0.0.1:8090'},
            {'key': 'ZAP_API_KEY', 'label': 'ZAP API Key', 'type': 'text', 'placeholder': 'API key from ZAP'},
        ],
    },
    {
        'group': 'Trivy',
        'tool_id': 'trivy',
        'icon': 'bi-box-seam',
        'fields': [
            {'key': 'TRIVY_SERVER_URL', 'label': 'Trivy Server URL', 'type': 'url', 'placeholder': 'http://127.0.0.1:4954'},
        ],
    },
    {
        'group': 'SonarQube',
        'tool_id': 'sonarqube',
        'icon': 'bi-code-slash',
        'fields': [
            {'key': 'SONARQUBE_URL', 'label': 'SonarQube URL', 'type': 'url', 'placeholder': 'http://127.0.0.1:9100'},
            {'key': 'SONARQUBE_TOKEN', 'label': 'SonarQube Token', 'type': 'password', 'placeholder': 'Generate from SonarQube > My Account > Security'},
        ],
    },
    {
        'group': 'Wazuh SIEM',
        'tool_id': 'wazuh',
        'icon': 'bi-eye',
        'fields': [
            {'key': 'WAZUH_URL', 'label': 'Wazuh API URL', 'type': 'url', 'placeholder': 'https://127.0.0.1:55000'},
            {'key': 'WAZUH_USER', 'label': 'Wazuh Username', 'type': 'text', 'placeholder': 'wazuh-wui'},
            {'key': 'WAZUH_PASSWORD', 'label': 'Wazuh Password', 'type': 'password', 'placeholder': 'Wazuh API password'},
        ],
    },
    {
        'group': 'OpenVAS / GVM',
        'tool_id': 'openvas',
        'icon': 'bi-hdd-network',
        'fields': [
            {'key': 'OPENVAS_URL', 'label': 'OpenVAS URL', 'type': 'url', 'placeholder': 'http://127.0.0.1:9390'},
            {'key': 'OPENVAS_USER', 'label': 'OpenVAS Username', 'type': 'text', 'placeholder': 'admin'},
            {'key': 'OPENVAS_PASSWORD', 'label': 'OpenVAS Password', 'type': 'password', 'placeholder': 'OpenVAS admin password'},
        ],
    },
    {
        'group': 'OpenAI (AI Analysis)',
        'tool_id': 'openai',
        'icon': 'bi-stars',
        'fields': [
            {'key': 'OPENAI_API_KEY', 'label': 'OpenAI API Key', 'type': 'password', 'placeholder': 'sk-...'},
            {'key': 'OPENAI_MODEL', 'label': 'Model', 'type': 'text', 'placeholder': 'gpt-5.2'},
        ],
    },
    {
        'group': 'WPScan (WordPress)',
        'tool_id': 'wpscan',
        'icon': 'bi-wordpress',
        'fields': [
            {'key': 'WPSCAN_API_TOKEN', 'label': 'WPScan API Token', 'type': 'password', 'placeholder': 'Free token from https://wpscan.com/register'},
        ],
    },
]


def _read_env():
    """Read .env file into a dict."""
    env_path = django_settings.BASE_DIR / '.env'
    data = {}
    if env_path.is_file():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, value = line.partition('=')
                    data[key.strip()] = value.strip()
    return data


def _write_env(data):
    """Write dict back to .env, preserving comments and order."""
    env_path = django_settings.BASE_DIR / '.env'
    lines = []
    written_keys = set()

    if env_path.is_file():
        with open(env_path) as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith('#') and '=' in stripped:
                    key, _, _ = stripped.partition('=')
                    key = key.strip()
                    if key in data:
                        lines.append(f'{key}={data[key]}\n')
                        written_keys.add(key)
                        continue
                lines.append(line if line.endswith('\n') else line + '\n')

    # Append any new keys
    for key, value in data.items():
        if key not in written_keys:
            lines.append(f'{key}={value}\n')

    with open(env_path, 'w') as f:
        f.writelines(lines)


@login_required
def settings_page(request):
    """Settings page to configure tool credentials via web UI."""
    env_data = _read_env()
    test_result = None

    if request.method == 'POST':
        action = request.POST.get('action', 'save')

        if action == 'save':
            # Collect all editable fields from POST
            for group in SETTINGS_FIELDS:
                for field in group['fields']:
                    key = field['key']
                    value = request.POST.get(key, '').strip()
                    env_data[key] = value
                    # Also update os.environ so Django picks it up immediately
                    os.environ[key] = value

            _write_env(env_data)

            # Reload relevant settings
            django_settings.ZAP_BASE_URL = os.environ.get('ZAP_BASE_URL', '')
            django_settings.ZAP_API_KEY = os.environ.get('ZAP_API_KEY', '')
            django_settings.TRIVY_SERVER_URL = os.environ.get('TRIVY_SERVER_URL', '')
            django_settings.SONARQUBE_URL = os.environ.get('SONARQUBE_URL', '')
            django_settings.SONARQUBE_TOKEN = os.environ.get('SONARQUBE_TOKEN', '')
            django_settings.WAZUH_URL = os.environ.get('WAZUH_URL', '')
            django_settings.WAZUH_USER = os.environ.get('WAZUH_USER', '')
            django_settings.WAZUH_PASSWORD = os.environ.get('WAZUH_PASSWORD', '')
            django_settings.OPENVAS_URL = os.environ.get('OPENVAS_URL', '')
            django_settings.OPENVAS_USER = os.environ.get('OPENVAS_USER', '')
            django_settings.OPENVAS_PASSWORD = os.environ.get('OPENVAS_PASSWORD', '')
            django_settings.OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
            django_settings.OPENAI_MODEL = os.environ.get('OPENAI_MODEL', 'gpt-5.2')
            django_settings.WPSCAN_API_TOKEN = os.environ.get('WPSCAN_API_TOKEN', '')

            messages.success(request, 'Settings saved successfully.')
            return redirect('dashboard-settings')

        elif action == 'test':
            # Test connectivity for a specific tool
            tool = request.POST.get('tool', '')
            test_result = _test_tool(tool, request.POST)

    # Build field data with current values
    groups = []
    for group in SETTINGS_FIELDS:
        fields_with_values = []
        for field in group['fields']:
            fields_with_values.append({
                **field,
                'value': env_data.get(field['key'], ''),
            })
        groups.append({
            'group': group['group'],
            'tool_id': group['tool_id'],
            'icon': group['icon'],
            'fields': fields_with_values,
        })

    return render(request, 'dashboard/settings.html', {
        'groups': groups,
        'test_result': test_result,
    })


# ── Pentest Agreement Views ────────────────────────────────────────────────

@login_required
def agreement_list(request):
    """List all pentest scope / NDA documents."""
    agreements = PentestAgreement.objects.all()
    return render(request, 'dashboard/agreement_list.html', {'agreements': agreements})


@login_required
def agreement_new(request):
    """Create a new pentest agreement."""
    default_org = OrganizationProfile.load()
    if request.method == 'POST':
        agreement = PentestAgreement()
        _save_agreement_from_post(agreement, request.POST)
        agreement.save()
        messages.success(request, 'บันทึกเอกสารเรียบร้อยแล้ว')
        if request.POST.get('action') == 'save_pdf':
            org_qs = f'?org_id={agreement.org_id}' if agreement.org_id else ''
            from django.urls import reverse
            return redirect(reverse('reports-agreement-pdf', kwargs={'pk': agreement.pk}) + org_qs)
        return redirect('dashboard-agreement-edit', pk=agreement.pk)
    return render(request, 'dashboard/agreement_form.html', {'org': default_org, 'agreement': None})


@login_required
def agreement_edit(request, pk):
    """Edit an existing pentest agreement."""
    agreement = get_object_or_404(PentestAgreement, pk=pk)
    default_org = OrganizationProfile.load(org_id=agreement.org_id)
    if request.method == 'POST':
        _save_agreement_from_post(agreement, request.POST)
        agreement.save()
        messages.success(request, 'บันทึกเอกสารเรียบร้อยแล้ว')
        if request.POST.get('action') == 'save_pdf':
            org_qs = f'?org_id={agreement.org_id}' if agreement.org_id else ''
            from django.urls import reverse
            return redirect(reverse('reports-agreement-pdf', kwargs={'pk': agreement.pk}) + org_qs)
        return redirect('dashboard-agreement-edit', pk=agreement.pk)
    return render(request, 'dashboard/agreement_form.html', {'org': default_org, 'agreement': agreement})


@login_required
def agreement_delete(request, pk):
    """Delete a pentest agreement."""
    agreement = get_object_or_404(PentestAgreement, pk=pk)
    if request.method == 'POST':
        agreement.delete()
        messages.success(request, 'ลบเอกสารเรียบร้อยแล้ว')
        return redirect('dashboard-agreement-list')
    return render(request, 'dashboard/agreement_confirm_delete.html', {'agreement': agreement})


def _save_agreement_from_post(agreement, post):
    """Copy POST data into a PentestAgreement instance (no save)."""
    agreement.document_number = post.get('document_number', '')
    agreement.client_name_th = post.get('client_name_th', '')
    agreement.client_name_en = post.get('client_name_en', '')
    agreement.client_address = post.get('client_address', '')
    agreement.client_contact = post.get('client_contact', '')
    agreement.client_signer_name = post.get('client_signer_name', '')
    agreement.client_signer_title = post.get('client_signer_title', '')
    agreement.tester_company_th = post.get('tester_company_th', '')
    agreement.tester_company_en = post.get('tester_company_en', '')
    agreement.tester_signer_name = post.get('tester_signer_name', '')
    agreement.tester_signer_title = post.get('tester_signer_title', '')
    agreement.test_type = post.get('test_type', 'Black Box Penetration Testing (Zero-knowledge)')
    agreement.target_systems = post.get('target_systems', '')
    agreement.scope_description = post.get('scope_description', '')
    agreement.out_of_scope = post.get('out_of_scope', '')
    agreement.methodology = post.get('methodology', '')
    agreement.rules_of_engagement = post.get('rules_of_engagement', '')
    agreement.deliverables = post.get('deliverables', '')
    agreement.team_members = post.get('team_members', '')
    # Parse dynamic period rows
    dates_from = post.getlist('period_date_from')
    times_from = post.getlist('period_time_from')
    dates_to   = post.getlist('period_date_to')
    times_to   = post.getlist('period_time_to')
    periods = []
    for i, df in enumerate(dates_from):
        df = df.strip()
        if df:
            periods.append({
                'date_from': df,
                'time_from': times_from[i].strip() if i < len(times_from) else '',
                'date_to':   dates_to[i].strip()   if i < len(dates_to)   else '',
                'time_to':   times_to[i].strip()   if i < len(times_to)   else '',
            })
    agreement.test_periods = periods
    # Keep legacy fields in sync from first/last period
    import datetime as _dt
    if periods:
        try:
            agreement.test_start_date = _dt.date.fromisoformat(periods[0]['date_from'])
        except (ValueError, KeyError):
            agreement.test_start_date = None
        try:
            last_to = periods[-1].get('date_to', '')
            agreement.test_end_date = _dt.date.fromisoformat(last_to) if last_to else None
        except ValueError:
            agreement.test_end_date = None
        agreement.test_hours = f"{periods[0].get('time_from','')} – {periods[-1].get('time_to','')}"
    else:
        agreement.test_start_date = None
        agreement.test_end_date = None
        agreement.test_hours = ''
    try:
        agreement.nda_duration_years = int(post.get('nda_duration_years', 3))
    except (ValueError, TypeError):
        agreement.nda_duration_years = 3
    try:
        raw_org = post.get('org_id', '').strip()
        agreement.org_id = int(raw_org) if raw_org else None
    except (ValueError, TypeError):
        agreement.org_id = None


def _test_tool(tool, post_data):
    """Test connectivity to a specific tool using provided credentials."""
    try:
        if tool == 'zap':
            client = ZAPClient()
            version = client.get_version()
            return {'tool': 'OWASP ZAP', 'ok': True, 'message': f'Connected — v{version}'}

        elif tool == 'trivy':
            from scanner.trivy_scanner import TrivyClient
            client = TrivyClient()
            ok = client.check_health()
            ver = client.get_version() if ok else 'N/A'
            return {'tool': 'Trivy', 'ok': ok, 'message': f'Connected — v{ver}' if ok else 'Connection failed'}

        elif tool == 'sonarqube':
            from scanner.sonarqube_client import SonarQubeClient
            client = SonarQubeClient()
            ok = client.check_health()
            ver = client.get_version() if ok else 'N/A'
            return {'tool': 'SonarQube', 'ok': ok, 'message': f'Connected — v{ver}' if ok else 'Connection failed'}

        elif tool == 'wazuh':
            from scanner.wazuh_client import WazuhClient
            client = WazuhClient()
            ok = client.check_health()
            ver = client.get_version() if ok else 'N/A'
            return {'tool': 'Wazuh', 'ok': ok, 'message': f'Connected — v{ver}' if ok else 'Connection failed — check URL and credentials'}

        elif tool == 'openvas':
            from scanner.openvas_client import OpenVASClient
            client = OpenVASClient()
            ok = client.check_health()
            ver = client.get_version() if ok else 'N/A'
            return {'tool': 'OpenVAS', 'ok': ok, 'message': f'Connected — v{ver}' if ok else 'Connection failed — check URL and credentials'}

        elif tool == 'testssl':
            from scanner.ssl_scanner import SSLScannerClient
            client = SSLScannerClient()
            ok = client.check_health()
            return {'tool': 'testssl.sh', 'ok': ok, 'message': 'Installed and ready' if ok else 'Not found'}

        elif tool == 'nmap':
            from scanner.nmap_client import NmapClient
            client = NmapClient()
            ok = client.check_health()
            ver = client.get_version() if ok else 'N/A'
            return {'tool': 'Nmap', 'ok': ok, 'message': f'Installed — {ver}' if ok else 'nmap not found — install with: apt install nmap'}

        elif tool == 'httpx':
            from scanner.httpx_client import HttpxClient
            client = HttpxClient()
            ok = client.check_health()
            return {'tool': 'httpx Probe', 'ok': ok, 'message': client.get_version() if ok else 'httpx library not available'}

        elif tool == 'sqlmap':
            from scanner.sqlmap_client import SqlmapClient
            client = SqlmapClient()
            ok = client.check_health()
            ver = client.get_version() if ok else 'N/A'
            return {'tool': 'sqlmap', 'ok': ok, 'message': ver if ok else 'sqlmap not found — install with: apt install sqlmap'}

        elif tool == 'dirb':
            import scanner.dirb_client as dirb_client
            ok = dirb_client.check_health()
            ver = dirb_client.get_version() if ok else 'N/A'
            return {'tool': 'Dir Brute Force (ffuf)', 'ok': ok, 'message': ver if ok else 'ffuf not found — install with: apt install ffuf'}

        elif tool == 'wpscan':
            import scanner.wpscan_client as wpscan_client
            ok = wpscan_client.check_health()
            ver = wpscan_client.get_version() if ok else 'N/A'
            token = getattr(django_settings, 'WPSCAN_API_TOKEN', '')
            note = ' (API token configured)' if token else ' (no API token — vuln data limited)'
            return {'tool': 'WPScan (WordPress)', 'ok': ok, 'message': (ver + note) if ok else 'wpscan not found — install with: gem install wpscan'}

        return {'tool': tool, 'ok': False, 'message': 'Unknown tool'}

    except Exception as e:
        return {'tool': tool, 'ok': False, 'message': str(e)}


# ── Team Certificates ─────────────────────────────────────────────────────

@login_required
def certificate_list(request):
    """List all team certificates grouped by person."""
    from collections import defaultdict
    certs = TeamCertificate.objects.all()
    grouped = defaultdict(list)
    for c in certs:
        grouped[c.person_name].append(c)
    # Collect existing person names for datalist autocomplete
    people = sorted(grouped.keys())
    return render(request, 'dashboard/certificate_list.html', {
        'grouped': dict(grouped),
        'people': people,
    })


@login_required
def certificate_upload(request):
    """Upload a new certificate (POST only)."""
    if request.method == 'POST':
        person_name = request.POST.get('person_name', '').strip()
        course_name = request.POST.get('course_name', '').strip()
        issuer      = request.POST.get('issuer', '').strip()
        f           = request.FILES.get('file')
        if not person_name or not course_name or not f:
            messages.error(request, 'กรุณากรอกชื่อบุคคล ชื่อหลักสูตร และเลือกไฟล์')
        else:
            cert = TeamCertificate(
                person_name=person_name,
                course_name=course_name,
                issuer=issuer,
                file=f,
            )
            cert.save()
            messages.success(request, f'อัพโหลดใบประกาศนียบัตรของ {person_name} สำเร็จ')
    return redirect('dashboard-certificate-list')


@login_required
def certificate_delete(request, pk):
    """Delete a certificate and its file (POST only)."""
    if request.method == 'POST':
        cert = get_object_or_404(TeamCertificate, pk=pk)
        name = cert.person_name
        cert.file.delete(save=False)
        cert.delete()
        messages.success(request, f'ลบใบประกาศนียบัตรของ {name} แล้ว')
    return redirect('dashboard-certificate-list')


# ── Agreement Template Management ─────────────────────────────────────────

@login_required
def upload_agreement_template(request):
    """Replace the DOCX agreement template with an uploaded file."""
    import shutil, datetime
    from reports.docx_generator import TEMPLATE_PATH

    if request.method == 'POST':
        f = request.FILES.get('template_file')
        if not f:
            messages.error(request, 'กรุณาเลือกไฟล์ .docx')
            return redirect('dashboard-agreement-list')
        if not f.name.lower().endswith('.docx'):
            messages.error(request, 'ไฟล์ต้องเป็น .docx เท่านั้น')
            return redirect('dashboard-agreement-list')

        # Backup old template before replacing
        if os.path.exists(TEMPLATE_PATH):
            ts  = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            bak = TEMPLATE_PATH.replace('.docx', f'_backup_{ts}.docx')
            shutil.copy2(TEMPLATE_PATH, bak)

        with open(TEMPLATE_PATH, 'wb') as out:
            for chunk in f.chunks():
                out.write(chunk)
        messages.success(request, f'อัพโหลด template ใหม่สำเร็จ ({f.name})')

    return redirect('dashboard-agreement-list')

