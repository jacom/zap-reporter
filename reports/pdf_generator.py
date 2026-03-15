import base64
from io import BytesIO

from django.http import HttpResponse
from django.template.loader import render_to_string

import mimetypes

from scanner.models import Alert, OrganizationProfile, TeamCertificate
from scanner.owasp_mapping import get_coverage_status, get_owasp_summary, OWASP_2025


def _encode_certificates():
    """Return all TeamCertificate objects with image files encoded as base64 data URIs."""
    result = []
    for cert in TeamCertificate.objects.all():
        item = {
            'person_name': cert.person_name,
            'course_name':  cert.course_name,
            'issuer':       cert.issuer,
            'is_image':     cert.is_image,
            'is_pdf':       cert.is_pdf,
            'data_uri':     '',
        }
        if cert.is_image and cert.file:
            try:
                with open(cert.file.path, 'rb') as f:
                    data = f.read()
                mime = mimetypes.guess_type(cert.file.path)[0] or 'image/jpeg'
                item['data_uri'] = f'data:{mime};base64,{base64.b64encode(data).decode()}'
            except Exception:
                pass
        result.append(item)
    return result


def _generate_severity_chart_base64(scan):
    """Generate severity pie chart as base64 PNG."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    labels = ['High', 'Medium', 'Low', 'Info']
    sizes = [scan.high_count, scan.medium_count, scan.low_count, scan.info_count]
    colors = ['#dc3545', '#fd7e14', '#0dcaf0', '#6c757d']

    filtered = [(l, s, c) for l, s, c in zip(labels, sizes, colors) if s > 0]
    if not filtered:
        return ''
    labels, sizes, colors = zip(*filtered)

    fig, ax = plt.subplots(1, 1, figsize=(5, 4))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct='%1.0f%%',
        startangle=90, pctdistance=0.85
    )
    for t in autotexts:
        t.set_fontsize(9)
    ax.set_title('Severity Distribution', fontsize=12, fontweight='bold')

    buf = BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight', transparent=True)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def _generate_cvss_chart_base64(alerts):
    """Generate CVSS distribution bar chart as base64 PNG."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    top = alerts.filter(risk__gte=2).order_by('-cvss_score')[:10]
    if not top:
        return ''

    names = [a.name[:30] for a in top]
    scores = [a.cvss_score for a in top]
    colors = ['#dc3545' if a.risk == 3 else '#fd7e14' for a in top]

    fig, ax = plt.subplots(1, 1, figsize=(7, 4))
    ax.barh(names[::-1], scores[::-1], color=colors[::-1])
    ax.set_xlim(0, 10)
    ax.set_xlabel('CVSS Score')
    ax.set_title('Top Vulnerabilities by CVSS', fontsize=12, fontweight='bold')

    buf = BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def _generate_findings_distribution_chart(owasp_summary):
    """Bar chart: findings count per OWASP Top 10:2025 category."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    codes   = sorted(owasp_summary.keys())
    highs   = [owasp_summary[c]['high'] + owasp_summary[c]['critical'] for c in codes]
    mediums = [owasp_summary[c]['medium'] for c in codes]
    lows    = [owasp_summary[c]['low'] for c in codes]

    if not any(h + m + l for h, m, l in zip(highs, mediums, lows)):
        return ''

    x     = list(range(len(codes)))
    width = 0.26

    fig, ax = plt.subplots(figsize=(10, 3.8))
    ax.bar([i - width for i in x], highs,   width, label='High/Critical', color='#dc3545')
    ax.bar(x,                       mediums, width, label='Medium',        color='#fd7e14')
    ax.bar([i + width for i in x], lows,    width, label='Low',           color='#0dcaf0')
    ax.set_xticks(x)
    ax.set_xticklabels(codes, fontsize=8.5)
    ax.set_ylabel('Findings Count', fontsize=9)
    ax.set_title('Findings Distribution by OWASP Top 10:2025', fontsize=11, fontweight='bold')
    ax.legend(fontsize=8, loc='upper right')
    ax.yaxis.grid(True, linestyle='--', alpha=0.4)
    ax.set_axisbelow(True)

    buf = BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def _build_coverage_matrix(owasp_summary, scan_tools_set):
    """Build OWASP Top 10:2025 coverage matrix list for template rendering."""
    matrix = []
    for code in sorted(OWASP_2025.keys()):
        info = OWASP_2025[code]
        data = owasp_summary.get(code, {})
        covering_tools = [t for t in info['tools'] if t in scan_tools_set]
        high_total = data.get('high', 0) + data.get('critical', 0)
        medium     = data.get('medium', 0)
        low        = data.get('low', 0)
        total      = data.get('total', 0)
        if total > 0:
            status = 'found'
        elif covering_tools:
            status = 'clean'
        else:
            status = 'not_tested'
        matrix.append({
            'code':           info['code'],
            'name':           info['name'],
            'name_th':        info['name_th'],
            'covering_tools': covering_tools,
            'high_total':     high_total,
            'medium':         medium,
            'low':            low,
            'total':          total,
            'status':         status,
        })
    return matrix


def _parse_reference_urls(reference_text):
    """Split a ZAP reference string into individual URL strings."""
    if not reference_text:
        return []
    urls = []
    for line in reference_text.splitlines():
        line = line.strip()
        if line.startswith('http://') or line.startswith('https://'):
            if line not in urls:
                urls.append(line)
    return urls


def _group_alerts_qs(queryset):
    """Group alert queryset by (name, cwe_id, cvss_score).

    Returns list of dicts — one entry per unique vulnerability with:
    - 'urls'          : plain list of URL strings (for backward compat)
    - 'url_entries'   : list of {url, param, attack, evidence} per URL
    - 'reference_urls': parsed list of individual reference link strings
    - 'alert_ref'     : ZAP plugin ID (e.g. '10003')
    """
    seen = {}
    for alert in queryset:
        key = (alert.name, alert.cwe_id, alert.cvss_score)
        if key not in seen:
            seen[key] = {
                'name': alert.name,
                'risk': alert.risk,
                'cvss_score': alert.cvss_score,
                'cvss_vector': alert.cvss_vector,
                'cwe_id': alert.cwe_id,
                'wasc_id': alert.wasc_id,
                'description': alert.description,
                'solution': alert.solution,
                'evidence': alert.evidence,
                'param': alert.param,
                'reference': alert.reference,
                'reference_urls': _parse_reference_urls(alert.reference),
                'alert_ref': alert.alert_ref,
                'urls': [],
                'url_entries': [],
                'cve_ids': set(),
                'has_public_exploit': False,
                'in_cisa_kev': False,
                'exploit_refs': [],
            }
        if alert.url and alert.url not in seen[key]['urls']:
            seen[key]['urls'].append(alert.url)
            seen[key]['url_entries'].append({
                'url':      alert.url,
                'param':    alert.param or '',
                'attack':   alert.attack or '',
                'evidence': alert.evidence or '',
            })
        seen[key]['cve_ids'].update(alert.cve_ids or [])
        if alert.has_public_exploit:
            seen[key]['has_public_exploit'] = True
        if alert.in_cisa_kev:
            seen[key]['in_cisa_kev'] = True
        for ref in (alert.exploit_refs or []):
            if ref not in seen[key]['exploit_refs']:
                seen[key]['exploit_refs'].append(ref)
    result = list(seen.values())
    for g in result:
        g['cve_ids'] = sorted(g['cve_ids'])
    return result


def _attach_ai_to_groups(groups, ai_lookup):
    """Attach AI analysis dict to each group item (in-place)."""
    for g in groups:
        g['ai'] = ai_lookup.get((g['name'], g.get('cwe_id') or 0))


def generate_pdf(scan, org_id=None):
    """Generate professional PDF report using WeasyPrint.

    Alerts are grouped by (name, cwe_id, cvss_score) — each unique
    vulnerability appears once with a numbered list of affected URLs.
    PDF includes all High/Critical groups and up to 200 Medium groups.
    Low/Info findings are shown as a count summary only.
    AI analysis (if generated) is embedded under each finding.
    """
    alerts = scan.alerts.all()

    high_qs = alerts.filter(risk__gte=3).order_by('-cvss_score')
    medium_qs = alerts.filter(risk=2).order_by('-cvss_score')
    low_count = alerts.filter(risk=1).count()
    info_count = alerts.filter(risk=0).count()

    high_grouped = _group_alerts_qs(high_qs)
    medium_grouped_all = _group_alerts_qs(medium_qs)
    medium_grouped = medium_grouped_all[:200]
    medium_total = len(medium_grouped_all)

    # Merge AI analyses
    ai_lookup = {
        (a.name, a.cwe_id): a
        for a in scan.ai_analyses.all()
    }
    _attach_ai_to_groups(high_grouped, ai_lookup)
    _attach_ai_to_groups(medium_grouped, ai_lookup)

    severity_chart = _generate_severity_chart_base64(scan)
    cvss_chart = _generate_cvss_chart_base64(alerts)

    # OWASP distribution + coverage matrix
    owasp_summary   = get_owasp_summary(alerts)
    dist_chart      = _generate_findings_distribution_chart(owasp_summary)
    coverage_matrix = _build_coverage_matrix(owasp_summary, {scan.tool})

    # Per-severity findings summary with %
    critical_count = alerts.filter(risk=4).count()
    total_all = (critical_count + scan.high_count + scan.medium_count
                 + low_count + info_count) or 1
    findings_summary = [
        {'label': 'Critical', 'count': critical_count,    'color': '#6f1d1b'},
        {'label': 'High',     'count': scan.high_count,   'color': '#dc3545'},
        {'label': 'Medium',   'count': scan.medium_count, 'color': '#fd7e14'},
        {'label': 'Low',      'count': low_count,         'color': '#0dcaf0'},
        {'label': 'Info',     'count': info_count,        'color': '#6c757d'},
    ]
    for f in findings_summary:
        f['pct'] = round(f['count'] / total_all * 100)

    # Organization profile
    org = OrganizationProfile.load(org_id=org_id)
    org_logo_b64 = ''
    if org.logo:
        try:
            with open(org.logo.path, 'rb') as f:
                logo_data = f.read()
            import mimetypes
            mime = mimetypes.guess_type(org.logo.path)[0] or 'image/png'
            org_logo_b64 = f'data:{mime};base64,{base64.b64encode(logo_data).decode("utf-8")}'
        except FileNotFoundError:
            pass

    import datetime
    thai_year = datetime.datetime.now().year + 543
    doc_number = f'{org.document_number_prefix}{thai_year}-001'

    context = {
        'scan': scan,
        'high_alerts': high_grouped,
        'medium_alerts': medium_grouped,
        'medium_total': medium_total,
        'medium_shown': len(medium_grouped),
        'low_count': low_count,
        'info_count': info_count,
        'severity_chart': severity_chart,
        'cvss_chart': cvss_chart,
        'dist_chart': dist_chart,
        'findings_summary': findings_summary,
        'coverage_matrix': coverage_matrix,
        'total_all': total_all,
        'has_ai': bool(ai_lookup),
        'org': org,
        'org_logo_b64': org_logo_b64,
        'doc_number': doc_number,
        'certificates': _encode_certificates(),
    }

    html_string = render_to_string('reports/pdf_template.html', context)
    from weasyprint import HTML
    pdf_file = HTML(string=html_string).write_pdf()

    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="zap_report_{scan.id}.pdf"'
    return response


def _generate_owasp_bar_chart_base64(owasp_summary):
    """Generate OWASP findings bar chart as base64 PNG."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    categories = []
    highs = []
    mediums = []
    lows = []
    infos = []

    for code in sorted(owasp_summary.keys()):
        data = owasp_summary[code]
        categories.append(code)
        highs.append(data['high'] + data['critical'])
        mediums.append(data['medium'])
        lows.append(data['low'])
        infos.append(data['informational'])

    if not any(h + m + l + i for h, m, l, i in zip(highs, mediums, lows, infos)):
        return ''

    fig, ax = plt.subplots(1, 1, figsize=(8, 4))
    x = range(len(categories))
    width = 0.2

    ax.bar([i - 1.5 * width for i in x], highs, width, label='High/Critical', color='#dc3545')
    ax.bar([i - 0.5 * width for i in x], mediums, width, label='Medium', color='#fd7e14')
    ax.bar([i + 0.5 * width for i in x], lows, width, label='Low', color='#0dcaf0')
    ax.bar([i + 1.5 * width for i in x], infos, width, label='Info', color='#6c757d')

    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=8)
    ax.set_ylabel('Findings')
    ax.set_title('Findings per OWASP Top 10:2025 Category', fontsize=12, fontweight='bold')
    ax.legend(fontsize=8)

    buf = BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def _get_tools_status():
    """Check health of all security tools. Returns dict of {tool: bool}."""
    from scanner.services import ZAPClient
    from scanner.trivy_scanner import TrivyClient
    from scanner.sonarqube_client import SonarQubeClient
    from scanner.ssl_scanner import SSLScannerClient
    from scanner.wazuh_client import WazuhClient
    from scanner.openvas_client import OpenVASClient

    tools = {}
    try:
        tools['zap'] = ZAPClient().get_version() != 'unknown'
    except Exception:
        tools['zap'] = False
    for name, cls in [('trivy', TrivyClient), ('sonarqube', SonarQubeClient),
                      ('testssl', SSLScannerClient), ('wazuh', WazuhClient),
                      ('openvas', OpenVASClient)]:
        try:
            tools[name] = cls().check_health()
        except Exception:
            tools[name] = False
    return tools


def generate_owasp_coverage_pdf(org_id=None):
    """Generate OWASP Top 10:2025 Coverage PDF report."""
    tools_status = _get_tools_status()
    coverage = get_coverage_status(tools_status)
    owasp_summary = get_owasp_summary(Alert.objects.all())
    bar_chart = _generate_owasp_bar_chart_base64(owasp_summary)

    # Organization profile + logo as base64
    org = OrganizationProfile.load(org_id=org_id)
    org_logo_b64 = ''
    if org.logo:
        try:
            with open(org.logo.path, 'rb') as f:
                logo_data = f.read()
            import mimetypes
            mime = mimetypes.guess_type(org.logo.path)[0] or 'image/png'
            org_logo_b64 = f'data:{mime};base64,{base64.b64encode(logo_data).decode("utf-8")}'
        except FileNotFoundError:
            pass

    # Document number
    import datetime
    thai_year = datetime.datetime.now().year + 543
    doc_number = f'{org.document_number_prefix}{thai_year}-001'

    context = {
        'tools_status': tools_status,
        'coverage': coverage,
        'owasp_summary': owasp_summary,
        'bar_chart': bar_chart,
        'org': org,
        'org_logo_b64': org_logo_b64,
        'doc_number': doc_number,
    }

    html_string = render_to_string('reports/owasp_coverage_pdf.html', context)
    from weasyprint import HTML
    pdf_file = HTML(string=html_string).write_pdf()

    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="owasp_coverage_report.pdf"'
    return response


def _group_alerts_combined(queryset):
    """Group alerts from multiple scans by (name, cwe_id, cvss_score).

    Extends _group_alerts_qs() by also tracking which tools contributed
    to each unique finding via the 'tools' set.
    """
    seen = {}
    for alert in queryset:
        key = (alert.name, alert.cwe_id, alert.cvss_score)
        if key not in seen:
            seen[key] = {
                'name': alert.name,
                'risk': alert.risk,
                'cvss_score': alert.cvss_score,
                'cvss_vector': alert.cvss_vector,
                'cwe_id': alert.cwe_id,
                'wasc_id': alert.wasc_id,
                'owasp_category': alert.owasp_category,
                'description': alert.description,
                'solution': alert.solution,
                'evidence': alert.evidence,
                'param': alert.param,
                'reference': alert.reference,
                'reference_urls': _parse_reference_urls(alert.reference),
                'alert_ref': alert.alert_ref,
                'urls': [],
                'url_entries': [],
                'tools': set(),
                'cve_ids': set(),
                'has_public_exploit': False,
                'in_cisa_kev': False,
                'exploit_refs': [],
            }
        if alert.url and alert.url not in seen[key]['urls']:
            seen[key]['urls'].append(alert.url)
            seen[key]['url_entries'].append({
                'url':      alert.url,
                'param':    alert.param or '',
                'attack':   alert.attack or '',
                'evidence': alert.evidence or '',
            })
        if alert.tool:
            seen[key]['tools'].add(alert.tool)
        seen[key]['cve_ids'].update(alert.cve_ids or [])
        if alert.has_public_exploit:
            seen[key]['has_public_exploit'] = True
        if alert.in_cisa_kev:
            seen[key]['in_cisa_kev'] = True
        for ref in (alert.exploit_refs or []):
            if ref not in seen[key]['exploit_refs']:
                seen[key]['exploit_refs'].append(ref)
    # Convert sets → sorted lists for template
    result = list(seen.values())
    for g in result:
        g['tools'] = sorted(g['tools'])
        g['cve_ids'] = sorted(g['cve_ids'])
    return result


def _aggregate_counts(scans):
    """Sum up severity counts across multiple scans."""
    totals = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'risk_score': 0.0}
    for s in scans:
        totals['critical']   += s.critical_count
        totals['high']       += s.high_count
        totals['medium']     += s.medium_count
        totals['low']        += s.low_count
        totals['info']       += s.info_count
        totals['risk_score'] += s.risk_score
    return totals


def _generate_combined_severity_chart(totals):
    """Generate severity pie chart from aggregated totals dict."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    labels = ['Critical', 'High', 'Medium', 'Low', 'Info']
    sizes  = [totals['critical'], totals['high'], totals['medium'], totals['low'], totals['info']]
    colors = ['#6f1d1b', '#dc3545', '#fd7e14', '#0dcaf0', '#6c757d']

    filtered = [(l, s, c) for l, s, c in zip(labels, sizes, colors) if s > 0]
    if not filtered:
        return ''
    labels, sizes, colors = zip(*filtered)

    fig, ax = plt.subplots(figsize=(5, 4))
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%',
           startangle=90, pctdistance=0.85)
    ax.set_title('Severity Distribution', fontsize=12, fontweight='bold')
    buf = BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight', transparent=True)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def generate_combined_pdf(scan_ids, report_title='', org_id=None):
    """Generate combined multi-tool OWASP report from multiple scan IDs.

    Args:
        scan_ids: list of Scan UUID strings
        report_title: optional custom report title

    Returns:
        HttpResponse with PDF content
    """
    from scanner.models import Scan, Alert
    scans = list(
        Scan.objects.select_related('target')
        .filter(id__in=scan_ids, status='completed')
        .order_by('target__name', 'started_at')
    )
    if not scans:
        from django.http import HttpResponseBadRequest
        return HttpResponseBadRequest('ไม่พบ scan ที่เลือก หรือยังไม่ completed')

    # Aggregate alerts from all selected scans
    all_alerts = Alert.objects.filter(scan__in=scans)

    high_qs   = all_alerts.filter(risk__gte=3).order_by('-cvss_score')
    medium_qs = all_alerts.filter(risk=2).order_by('-cvss_score')
    low_count  = all_alerts.filter(risk=1).count()
    info_count = all_alerts.filter(risk=0).count()

    high_grouped          = _group_alerts_combined(high_qs)
    medium_grouped_all    = _group_alerts_combined(medium_qs)
    medium_grouped        = medium_grouped_all[:200]

    # Merge AI analyses from all selected scans keyed by (name, cwe_id)
    from scanner.models import AlertAIAnalysis
    ai_lookup = {
        (a.name, a.cwe_id): a
        for a in AlertAIAnalysis.objects.filter(scan__in=scans)
    }
    _attach_ai_to_groups(high_grouped, ai_lookup)
    _attach_ai_to_groups(medium_grouped, ai_lookup)

    totals        = _aggregate_counts(scans)
    severity_chart = _generate_combined_severity_chart(totals)
    cvss_chart     = _generate_cvss_chart_base64(all_alerts)

    # OWASP distribution + coverage matrix
    owasp_summary   = get_owasp_summary(all_alerts)
    dist_chart      = _generate_findings_distribution_chart(owasp_summary)
    scan_tools_set  = {s.tool for s in scans}
    coverage_matrix = _build_coverage_matrix(owasp_summary, scan_tools_set)

    # Per-scan findings summary table
    per_scan_summary = []
    for s in scans:
        per_scan_summary.append({
            'target':   s.target.name,
            'tool':     s.get_tool_display(),
            'critical': s.critical_count,
            'high':     s.high_count,
            'medium':   s.medium_count,
            'low':      s.low_count,
            'info':     s.info_count,
            'total':    s.total_alerts,
        })
    total_all = (totals['critical'] + totals['high'] + totals['medium']
                 + totals['low'] + totals['info']) or 1

    # Determine primary target for report header
    unique_targets = {s.target for s in scans}
    primary_target = scans[0].target if len(unique_targets) == 1 else None
    target_label   = primary_target.name if primary_target else 'Multiple Targets'

    # Organization profile
    org = OrganizationProfile.load(org_id=org_id)
    org_logo_b64 = ''
    if org.logo:
        try:
            with open(org.logo.path, 'rb') as f:
                logo_data = f.read()
            import mimetypes
            mime = mimetypes.guess_type(org.logo.path)[0] or 'image/png'
            org_logo_b64 = f'data:{mime};base64,{base64.b64encode(logo_data).decode("utf-8")}'
        except FileNotFoundError:
            pass

    import datetime
    thai_year  = datetime.datetime.now().year + 543
    doc_number = f'{org.document_number_prefix}{thai_year}-{len(scans):03d}'

    context = {
        'scans': scans,
        'target_label': target_label,
        'primary_target': primary_target,
        'report_title': report_title or f'รายงาน VA — {target_label}',
        'high_alerts': high_grouped,
        'medium_alerts': medium_grouped,
        'medium_total': len(medium_grouped_all),
        'medium_shown': len(medium_grouped),
        'low_count': low_count,
        'info_count': info_count,
        'totals': totals,
        'severity_chart': severity_chart,
        'cvss_chart': cvss_chart,
        'dist_chart': dist_chart,
        'per_scan_summary': per_scan_summary,
        'coverage_matrix': coverage_matrix,
        'total_all': total_all,
        'org': org,
        'org_logo_b64': org_logo_b64,
        'doc_number': doc_number,
        'has_ai': bool(ai_lookup),
        'certificates': _encode_certificates(),
    }

    html_string = render_to_string('reports/combined_pdf_template.html', context)
    from weasyprint import HTML
    pdf_file = HTML(string=html_string).write_pdf()

    safe_name = target_label[:30].replace(' ', '_').replace('/', '-')
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="VA_Report_{safe_name}.pdf"'
    return response


def generate_agreement_pdf(agreement, org_id=None):
    """Generate Pentest Scope of Work + NDA PDF for a PentestAgreement."""
    from scanner.models import OrganizationProfile

    org = OrganizationProfile.load(org_id=org_id)
    org_logo_b64 = ''
    if org.logo:
        try:
            with open(org.logo.path, 'rb') as f:
                logo_data = f.read()
            import mimetypes
            mime = mimetypes.guess_type(org.logo.path)[0] or 'image/png'
            org_logo_b64 = f'data:{mime};base64,{base64.b64encode(logo_data).decode("utf-8")}'
        except FileNotFoundError:
            pass

    _THAI_MONTHS = ['มกราคม','กุมภาพันธ์','มีนาคม','เมษายน',
                    'พฤษภาคม','มิถุนายน','กรกฎาคม','สิงหาคม',
                    'กันยายน','ตุลาคม','พฤศจิกายน','ธันวาคม']

    def _fmt_date(date_str):
        if not date_str:
            return '............................................'
        import datetime as _dt
        try:
            d = _dt.date.fromisoformat(date_str)
            return f'{d.day} {_THAI_MONTHS[d.month-1]} พ.ศ. {d.year + 543}'
        except ValueError:
            return date_str

    target_systems = [s.strip() for s in agreement.target_systems.splitlines() if s.strip()]
    team_members = [m.strip() for m in agreement.team_members.splitlines() if m.strip()]
    methodology = [s.strip() for s in agreement.methodology.splitlines() if s.strip()]
    rules_of_engagement = [s.strip() for s in agreement.rules_of_engagement.splitlines() if s.strip()]
    deliverables = [s.strip() for s in agreement.deliverables.splitlines() if s.strip()]

    formatted_periods = [
        {
            'date_from_str': _fmt_date(p.get('date_from', '')),
            'time_from':     p.get('time_from', ''),
            'date_to_str':   _fmt_date(p.get('date_to', '')),
            'time_to':       p.get('time_to', ''),
        }
        for p in (agreement.test_periods or [])
    ]

    context = {
        'agreement': agreement,
        'org': org,
        'org_logo_b64': org_logo_b64,
        'target_systems': target_systems,
        'team_members': team_members,
        'methodology': methodology,
        'rules_of_engagement': rules_of_engagement,
        'deliverables': deliverables,
        'formatted_periods': formatted_periods,
    }

    html_string = render_to_string('reports/agreement_pdf.html', context)
    from weasyprint import HTML
    pdf_file = HTML(string=html_string).write_pdf()

    safe_client = ''.join(c for c in agreement.client_name_th[:30] if c.isalnum() or c in '-_')
    filename = f'pentest_agreement_{agreement.pk}_{safe_client}.pdf'
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'inline; filename="{filename}"'
    return response


def generate_combined_excel(scan_ids):
    """Generate combined Excel report from multiple scan IDs."""
    from scanner.models import Scan, Alert
    from .excel_exporter import generate_excel_from_alerts
    scans = list(
        Scan.objects.select_related('target')
        .filter(id__in=scan_ids, status='completed')
        .order_by('target__name', 'started_at')
    )
    if not scans:
        from django.http import HttpResponseBadRequest
        return HttpResponseBadRequest('ไม่พบ scan ที่เลือก')

    all_alerts = Alert.objects.filter(scan__in=scans).select_related('scan__target')
    target_label = scans[0].target.name if len({s.target for s in scans}) == 1 else 'Multiple_Targets'
    return generate_excel_from_alerts(all_alerts, scans, target_label)
