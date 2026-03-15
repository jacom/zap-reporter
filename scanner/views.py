import logging
import threading
from datetime import date

from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import ScanTarget, Scan, Alert, MonthlySummary
from .serializers import ScanTargetSerializer, ScanSerializer, AlertSerializer
from .services import ZAPClient
from .trivy_scanner import TrivyClient
from .sonarqube_client import SonarQubeClient
from .ssl_scanner import SSLScannerClient
from .wazuh_client import WazuhClient
from .openvas_client import OpenVASClient
from .nuclei_client import NucleiClient
from .nmap_client import NmapClient
from .httpx_client import HttpxClient
from .sqlmap_client import SqlmapClient
import scanner.dirb_client as dirb_client
import scanner.wpscan_client as wpscan_client
from .owasp_mapping import map_to_owasp, get_owasp_summary, get_coverage_status, OWASP_2025
from .cvss_mapper import get_cvss

logger = logging.getLogger(__name__)


class ScanTargetViewSet(viewsets.ModelViewSet):
    queryset = ScanTarget.objects.all()
    serializer_class = ScanTargetSerializer


class ScanViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Scan.objects.select_related('target').all()
    serializer_class = ScanSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        tool = self.request.query_params.get('tool')
        if tool:
            qs = qs.filter(tool=tool)
        return qs


class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AlertSerializer

    def get_queryset(self):
        qs = Alert.objects.select_related('scan')
        scan_id = self.request.query_params.get('scan')
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        tool = self.request.query_params.get('tool')
        if tool:
            qs = qs.filter(tool=tool)
        owasp = self.request.query_params.get('owasp')
        if owasp:
            qs = qs.filter(owasp_category=owasp.upper())
        return qs


# ── Tool Version Helper ───────────────────────────────────────────────────

def _get_tool_version(tool):
    """Return the version string for a given tool key, or '' on failure."""
    try:
        if tool == 'zap':
            return ZAPClient().get_version()
        elif tool == 'trivy':
            return TrivyClient().get_version()
        elif tool == 'sonarqube':
            return SonarQubeClient().get_version()
        elif tool == 'testssl':
            return SSLScannerClient().get_version()
        elif tool == 'wazuh':
            return WazuhClient().get_version()
        elif tool == 'openvas':
            return OpenVASClient().get_version()
        elif tool == 'nuclei':
            return NucleiClient().get_version()
        elif tool == 'nmap':
            return NmapClient().get_version()
        elif tool == 'httpx':
            return HttpxClient().get_version()
        elif tool == 'sqlmap':
            return SqlmapClient().get_version()
        elif tool == 'dirb':
            return dirb_client.get_version()
        elif tool == 'wpscan':
            return wpscan_client.get_version()
    except Exception:
        pass
    return ''


# ── Tool Status Endpoints ─────────────────────────────────────────────────

@api_view(['GET'])
def tools_status(request):
    """Check connectivity and version of all tools."""
    results = {}

    # ZAP
    try:
        zap = ZAPClient()
        results['zap'] = {'status': 'ok', 'version': zap.get_version()}
    except Exception as e:
        results['zap'] = {'status': 'error', 'message': str(e)}

    # Trivy
    try:
        trivy = TrivyClient()
        healthy = trivy.check_health()
        results['trivy'] = {
            'status': 'ok' if healthy else 'degraded',
            'version': trivy.get_version(),
        }
    except Exception as e:
        results['trivy'] = {'status': 'error', 'message': str(e)}

    # SonarQube
    try:
        sonar = SonarQubeClient()
        healthy = sonar.check_health()
        results['sonarqube'] = {
            'status': 'ok' if healthy else 'error',
            'version': sonar.get_version(),
        }
    except Exception as e:
        results['sonarqube'] = {'status': 'error', 'message': str(e)}

    # testssl
    try:
        ssl = SSLScannerClient()
        healthy = ssl.check_health()
        results['testssl'] = {
            'status': 'ok' if healthy else 'error',
            'version': ssl.get_version(),
        }
    except Exception as e:
        results['testssl'] = {'status': 'error', 'message': str(e)}

    # Wazuh
    try:
        wazuh = WazuhClient()
        healthy = wazuh.check_health()
        results['wazuh'] = {
            'status': 'ok' if healthy else 'error',
            'version': wazuh.get_version() if healthy else 'N/A',
        }
    except Exception as e:
        results['wazuh'] = {'status': 'error', 'message': str(e)}

    # OpenVAS
    try:
        openvas = OpenVASClient()
        healthy = openvas.check_health()
        results['openvas'] = {
            'status': 'ok' if healthy else 'error',
            'version': openvas.get_version() if healthy else 'N/A',
        }
    except Exception as e:
        results['openvas'] = {'status': 'error', 'message': str(e)}

    # Nuclei
    try:
        nuclei = NucleiClient()
        healthy = nuclei.check_health()
        results['nuclei'] = {
            'status': 'ok' if healthy else 'error',
            'version': nuclei.get_version() if healthy else 'N/A',
        }
    except Exception as e:
        results['nuclei'] = {'status': 'error', 'message': str(e)}

    # Nmap
    try:
        nmap = NmapClient()
        healthy = nmap.check_health()
        results['nmap'] = {
            'status': 'ok' if healthy else 'error',
            'version': nmap.get_version() if healthy else 'N/A',
        }
    except Exception as e:
        results['nmap'] = {'status': 'error', 'message': str(e)}

    # httpx
    try:
        hx = HttpxClient()
        healthy = hx.check_health()
        results['httpx'] = {
            'status': 'ok' if healthy else 'error',
            'version': hx.get_version(),
        }
    except Exception as e:
        results['httpx'] = {'status': 'error', 'message': str(e)}

    # sqlmap
    try:
        sql = SqlmapClient()
        healthy = sql.check_health()
        results['sqlmap'] = {
            'status': 'ok' if healthy else 'error',
            'version': sql.get_version() if healthy else 'N/A',
        }
    except Exception as e:
        results['sqlmap'] = {'status': 'error', 'message': str(e)}

    # ffuf / dirb
    try:
        ok = dirb_client.check_health()
        results['dirb'] = {
            'status': 'ok' if ok else 'error',
            'version': dirb_client.get_version() if ok else 'N/A',
        }
    except Exception as e:
        results['dirb'] = {'status': 'error', 'message': str(e)}

    # WPScan
    try:
        ok = wpscan_client.check_health()
        results['wpscan'] = {
            'status': 'ok' if ok else 'error',
            'version': wpscan_client.get_version() if ok else 'N/A',
        }
    except Exception as e:
        results['wpscan'] = {'status': 'error', 'message': str(e)}

    return Response(results)


@api_view(['GET'])
def zap_status(request):
    """Check ZAP connectivity and version."""
    try:
        client = ZAPClient()
        version = client.get_version()
        return Response({'status': 'ok', 'version': version})
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ── OWASP 2025 Endpoints ──────────────────────────────────────────────────

@api_view(['GET'])
def owasp_summary(request):
    """Get OWASP Top 10:2025 summary across all scans."""
    target_id = request.query_params.get('target')
    alerts = Alert.objects.all()
    if target_id:
        alerts = alerts.filter(scan__target_id=target_id)

    summary = get_owasp_summary(alerts)
    return Response(summary)


@api_view(['GET'])
def owasp_coverage(request):
    """Check which OWASP 2025 categories are covered by active tools."""
    tools = {}
    try:
        tools['zap'] = ZAPClient().get_version() != 'unknown'
    except Exception:
        tools['zap'] = False
    tools['trivy'] = TrivyClient().check_health()
    tools['sonarqube'] = SonarQubeClient().check_health()
    tools['testssl'] = SSLScannerClient().check_health()
    tools['wazuh'] = WazuhClient().check_health()
    tools['openvas'] = OpenVASClient().check_health()

    coverage = get_coverage_status(tools)
    return Response(coverage)


# ── Scan Endpoints ─────────────────────────────────────────────────────────

@api_view(['POST'])
def stop_scan(request, scan_id):
    """Stop a running scan."""
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

    if scan.status not in (Scan.Status.RUNNING, Scan.Status.PENDING):
        return Response({'error': f'Scan is not running (status: {scan.status})'},
                        status=status.HTTP_400_BAD_REQUEST)

    tool = scan.tool or 'zap'

    # Stop ZAP scans via API
    if tool == 'zap':
        try:
            client = ZAPClient()
            if scan.zap_scan_id:
                try:
                    client.stop_spider(scan.zap_scan_id)
                except Exception:
                    pass
                try:
                    client.stop_active_scan(scan.zap_scan_id)
                except Exception:
                    pass
            else:
                client.stop_all_scans()
        except Exception as e:
            logger.warning(f'Failed to stop ZAP scan: {e}')

    # Update scan status
    scan.status = Scan.Status.FAILED
    scan.completed_at = timezone.now()
    scan.raw_json = scan.raw_json or {}
    if isinstance(scan.raw_json, dict):
        scan.raw_json['stopped'] = True
        scan.raw_json['stopped_by'] = 'user'
    scan.save(update_fields=['status', 'completed_at', 'raw_json'])

    # Collect any partial results for ZAP
    if tool == 'zap':
        try:
            client = ZAPClient()
            target_url = scan.target.url
            raw_alerts = client.get_alerts(base_url=target_url)
            if raw_alerts:
                findings = []
                for a in raw_alerts:
                    cwe_id = int(a.get('cweid', 0) or 0)
                    risk = int(a.get('risk', 0) or 0)
                    tags = a.get('tags', {})
                    tag_list = list(tags.keys()) if isinstance(tags, dict) else []
                    findings.append({
                        'name': a.get('name', a.get('alert', '')),
                        'risk': risk,
                        'confidence': int(a.get('confidence', 0) or 0),
                        'url': a.get('url', ''),
                        'param': a.get('param', ''),
                        'attack': a.get('attack', ''),
                        'evidence': a.get('evidence', ''),
                        'description': a.get('description', ''),
                        'solution': a.get('solution', ''),
                        'reference': a.get('reference', ''),
                        'otherinfo': a.get('otherinfo', ''),
                        'tags_text': ' '.join(tag_list),
                        'cwe_id': cwe_id,
                        'wasc_id': int(a.get('wascid', 0) or 0),
                        'alert_ref': a.get('pluginId', ''),
                        'tool': 'zap',
                        'owasp_category': map_to_owasp(cwe_id=cwe_id, tool='zap', tags=tag_list),
                    })
                _store_findings(scan, findings, 'zap')
                scan.status = Scan.Status.COMPLETED
                scan.save(update_fields=['status'])
        except Exception as e:
            logger.warning(f'Failed to collect partial ZAP results: {e}')

    logger.info(f'Scan {scan_id} stopped by user')
    return Response({
        'status': scan.status,
        'message': 'Scan stopped',
        'alerts_collected': scan.total_alerts,
    })


@api_view(['POST'])
def start_scan(request):
    """Start a new scan.

    POST body: {
        "target_url": "...",
        "target_name": "...",
        "scan_type": "full",
        "tool": "zap"  // zap|trivy|sonarqube|testssl|wazuh|openvas
    }
    """
    target_url = request.data.get('target_url')
    target_name = request.data.get('target_name', target_url)
    scan_type = request.data.get('scan_type', 'full')
    tool = request.data.get('tool', 'zap')

    if not target_url:
        return Response({'error': 'target_url is required'},
                        status=status.HTTP_400_BAD_REQUEST)

    if tool not in dict(Scan.ToolSource.choices):
        return Response({'error': f'Invalid tool: {tool}'},
                        status=status.HTTP_400_BAD_REQUEST)

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

    thread = threading.Thread(
        target=_run_scan_background,
        args=(scan.id, target_url, scan_type, tool),
        daemon=True,
    )
    thread.start()

    return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)


def _run_scan_background(scan_id, target_url, scan_type, tool='zap',
                         agent_id=None, task_id=None):
    """Execute scan in a background thread using the specified tool."""
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = Scan.Status.RUNNING
        scan.tool_version = _get_tool_version(tool)
        scan.save(update_fields=['status', 'tool_version'])

        if tool == 'zap':
            raw_findings = _run_zap_scan(scan, target_url, scan_type)
        elif tool == 'trivy':
            raw_findings = _run_trivy_scan(target_url, scan_type)
        elif tool == 'sonarqube':
            raw_findings = _run_sonarqube_scan(target_url)
        elif tool == 'testssl':
            raw_findings = _run_testssl_scan(target_url)
        elif tool == 'wazuh':
            raw_findings = _run_wazuh_scan(agent_id=agent_id)
        elif tool == 'openvas':
            raw_findings = _run_openvas_scan(target_url, task_id=task_id)
        elif tool == 'nuclei':
            raw_findings = _run_nuclei_scan(target_url, scan_type)
        elif tool == 'nmap':
            raw_findings = _run_nmap_scan(target_url, scan_type)
        elif tool == 'httpx':
            raw_findings = _run_httpx_scan(target_url, scan_type)
        elif tool == 'sqlmap':
            raw_findings = _run_sqlmap_scan(target_url, scan_type)
        elif tool == 'dirb':
            raw_findings = _run_dirb_scan(target_url, scan_type)
        elif tool == 'wpscan':
            raw_findings = _run_wpscan_scan(target_url, scan_type)
        else:
            raw_findings = []

        existing_raw = scan.raw_json if isinstance(scan.raw_json, dict) else {}
        existing_raw['findings_count'] = len(raw_findings)
        scan.raw_json = existing_raw
        _store_findings(scan, raw_findings, tool)
        _enrich_exploits(scan)

        scan.status = Scan.Status.COMPLETED
        scan.completed_at = timezone.now()
        scan.save()

        _update_monthly_summary(scan)
        logger.info(f'Scan {scan_id} [{tool}] completed: {scan.total_alerts} alerts')

    except Exception as e:
        logger.exception(f'Scan {scan_id} [{tool}] failed: {e}')
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.status = Scan.Status.FAILED
            scan.raw_json = {'error': str(e)}
            scan.save(update_fields=['status', 'raw_json'])
        except Exception:
            pass


# ── Tool-specific scan runners ─────────────────────────────────────────────

_ZAP_RISK_MAP = {'informational': 0, 'info': 0, 'low': 1, 'medium': 2, 'high': 3}
_ZAP_CONF_MAP = {'false positive': 0, 'low': 1, 'medium': 2, 'high': 3, 'confirmed': 3}


def _zap_int(value, label_map, default=0):
    """Convert ZAP risk/confidence value which may be int-string or label."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return label_map.get(str(value).lower(), default)


def _run_zap_scan(scan, target_url, scan_type):
    """Run ZAP scan and return raw alert dicts."""
    client = ZAPClient()

    if scan_type == 'spider':
        client._apply_scan_limits()
        sid = client.spider_scan(target_url)
        scan.zap_scan_id = sid
        scan.save(update_fields=['zap_scan_id'])
        client.poll_spider(sid)
        # Store discovered URL list for display in scan_detail
        spider_urls = client.get_spider_results(sid)
        scan.raw_json = {'spider_urls': spider_urls, 'spider_url_count': len(spider_urls)}
        scan.save(update_fields=['raw_json'])
    elif scan_type == 'active':
        client._apply_scan_limits()
        sid = client.active_scan(target_url)
        scan.zap_scan_id = sid
        scan.save(update_fields=['zap_scan_id'])
        client.poll_active_scan(sid)
    elif scan_type == 'ajax':
        client._apply_scan_limits()
        client.ajax_spider_scan(target_url)
        import time
        while client.get_ajax_spider_status() == 'running':
            time.sleep(5)
    else:  # full — _apply_scan_limits() called inside full_scan()
        sid, _ = client.full_scan(target_url)
        scan.zap_scan_id = sid
        scan.save(update_fields=['zap_scan_id'])

    raw_alerts = client.get_alerts(base_url=target_url)

    # Convert ZAP alerts to normalized format
    findings = []
    for a in raw_alerts:
        cwe_id = int(a.get('cweid', 0) or 0)
        risk = _zap_int(a.get('riskcode', a.get('risk', 0)), _ZAP_RISK_MAP)
        conf = _zap_int(a.get('confidence', 0), _ZAP_CONF_MAP)
        tags = a.get('tags', {})
        tag_list = list(tags.keys()) if isinstance(tags, dict) else []

        findings.append({
            'name': a.get('name', a.get('alert', '')),
            'risk': risk,
            'confidence': conf,
            'url': a.get('url', ''),
            'param': a.get('param', ''),
            'attack': a.get('attack', ''),
            'evidence': a.get('evidence', ''),
            'description': a.get('description', ''),
            'solution': a.get('solution', ''),
            'reference': a.get('reference', ''),
            'otherinfo': a.get('otherinfo', ''),
            'tags_text': ' '.join(tag_list),
            'cwe_id': cwe_id,
            'wasc_id': int(a.get('wascid', 0) or 0),
            'alert_ref': a.get('pluginId', ''),
            'tool': 'zap',
            'owasp_category': map_to_owasp(cwe_id=cwe_id, tool='zap', tags=tag_list),
        })

    return findings


def _run_trivy_scan(target_url, scan_type):
    """Run Trivy scan."""
    client = TrivyClient()
    if scan_type == 'image' or target_url.count('/') > 2 or ':' in target_url.split('/')[-1]:
        return client.scan_image(target_url)
    elif target_url.startswith(('http://', 'https://', 'git://')):
        return client.scan_repo(target_url)
    else:
        return client.scan_fs(target_url)


def _run_sonarqube_scan(project_key):
    """Fetch SonarQube issues for a project."""
    client = SonarQubeClient()
    return client.get_all_issues(project_key)


def _run_testssl_scan(hostname):
    """Run testssl.sh scan."""
    client = SSLScannerClient()
    return client.scan(hostname)


def _run_wazuh_scan(agent_id=None):
    """Fetch Wazuh alerts. If agent_id provided, fetch only that agent."""
    client = WazuhClient()
    findings, _ = client.get_alerts(limit=500, level_min=7, agent_id=agent_id)
    return findings


def _run_openvas_scan(target_url, task_id=None):
    """Fetch OpenVAS report. If task_id provided, fetch that specific task."""
    client = OpenVASClient()
    return client.get_latest_report(task_id=task_id)


def _run_nuclei_scan(target_url, scan_type='full'):
    """Run nuclei scan against target and return normalized findings.

    scan_type 'quick' → critical,high only
    scan_type 'full'  → critical,high,medium,low
    """
    client = NucleiClient()

    severity = 'critical,high,medium' if scan_type == 'quick' else 'critical,high,medium,low'
    raw_findings = client.scan(target_url, severity=severity)
    return client.findings_to_alerts(raw_findings)


def _run_nmap_scan(target, scan_type='quick'):
    """Run nmap port scan against target and return normalized findings.

    scan_type 'quick' → top 100 ports, version detection (-F)
    scan_type 'full'  → top 1000 ports + default NSE scripts (-sC)
    scan_type 'vuln'  → vulnerability NSE scripts (--script vuln)
    """
    client = NmapClient()
    return client.scan(target, scan_type=scan_type)


def _run_httpx_scan(target_url, scan_type='full'):
    """HTTP security probe: headers, fingerprinting, sensitive path discovery.

    scan_type 'headers' → security headers + server fingerprint only
    scan_type 'full'    → headers + sensitive path probe + HTTP methods
    """
    client = HttpxClient()
    return client.scan(target_url, scan_type=scan_type)


def _run_sqlmap_scan(target_url, scan_type='quick'):
    """Run sqlmap SQL injection scan.

    scan_type 'quick' → level 1, risk 1, fast
    scan_type 'full'  → level 3, risk 2, crawl + forms
    scan_type 'deep'  → level 5, risk 3, deep scan
    """
    client = SqlmapClient()
    return client.scan(target_url, scan_type=scan_type)


def _run_dirb_scan(target_url, scan_type='full'):
    """Directory brute-force using ffuf with DirBuster wordlists.

    scan_type 'quick' → common.txt (~4 k entries), no extensions
    scan_type 'full'  → common.txt + common web extensions
    scan_type 'deep'  → big.txt + extensions, slower
    """
    from scanner.dirb_client import run_scan

    WORDLISTS = {
        'deep':  '/usr/share/dirb/wordlists/big.txt',
        'full':  '/usr/share/dirb/wordlists/common.txt',
        'quick': '/usr/share/dirb/wordlists/small.txt',
    }
    EXTENSIONS = {
        'deep':  ['php', 'html', 'asp', 'aspx', 'txt', 'bak', 'conf', 'log', 'xml', 'json'],
        'full':  ['php', 'html', 'asp', 'aspx', 'txt', 'bak'],
        'quick': [],
    }

    wordlist   = WORDLISTS.get(scan_type, WORDLISTS['full'])
    extensions = EXTENSIONS.get(scan_type, EXTENSIONS['full'])
    timeout    = {'quick': 120, 'full': 300, 'deep': 600}.get(scan_type, 300)
    threads    = {'quick': 60, 'full': 40, 'deep': 30}.get(scan_type, 40)

    return run_scan(
        target_url,
        wordlist=wordlist,
        extensions=extensions,
        threads=threads,
        timeout=timeout,
    )


def _run_wpscan_scan(target_url, scan_type='full'):
    """WordPress vulnerability scan using WPScan.

    scan_type 'quick' → vulnerable plugins/themes + interesting findings only
    scan_type 'full'  → vulnerable plugins + all themes + users (default)
    scan_type 'deep'  → all plugins/themes (aggressive detection) + users
    """
    from django.conf import settings
    token = getattr(settings, 'WPSCAN_API_TOKEN', '')
    return wpscan_client.scan(target_url, scan_type=scan_type, api_token=token)


# ── Common helpers ─────────────────────────────────────────────────────────

def _store_findings(scan, findings, tool):
    """Store normalized findings as Alert objects."""
    from scanner.cve_enrichment import extract_cves_from_text
    alerts_to_create = []
    for f in findings:
        cwe_id = f.get('cwe_id', 0)
        risk = f.get('risk', 0)

        # Get CVSS if not provided
        cvss_score = f.get('cvss_score', 0.0)
        cvss_vector = f.get('cvss_vector', '')
        if not cvss_score and cwe_id:
            cvss_score, cvss_vector = get_cvss(cwe_id, risk)

        # Map OWASP category if not set
        owasp_cat = f.get('owasp_category', '')
        if not owasp_cat:
            owasp_cat = map_to_owasp(cwe_id=cwe_id, tool=tool)

        name      = f.get('name', '')[:500]
        reference = f.get('reference', '')
        desc      = f.get('description', '')
        evidence  = f.get('evidence', '')[:2000]
        alert_ref = f.get('alert_ref', '')
        otherinfo = f.get('otherinfo', '')
        tags_text = f.get('tags_text', '')
        cve_ids   = extract_cves_from_text(name, reference, desc, evidence, alert_ref, otherinfo, tags_text)

        alerts_to_create.append(Alert(
            scan=scan,
            alert_ref=alert_ref,
            name=name,
            risk=risk,
            confidence=f.get('confidence', 2),
            url=f.get('url', ''),
            param=f.get('param', ''),
            attack=f.get('attack', ''),
            evidence=evidence,
            description=desc,
            solution=f.get('solution', ''),
            reference=reference,
            cwe_id=cwe_id,
            wasc_id=f.get('wasc_id', 0),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            tool=tool,
            owasp_category=owasp_cat,
            cve_ids=cve_ids,
        ))

    if alerts_to_create:
        Alert.objects.bulk_create(alerts_to_create)
    scan.update_counts()


def _enrich_exploits(scan):
    """Check public exploit availability for all alerts with CVE IDs.

    Sources checked:
      - NVD API — fill CVE IDs for alerts that have CWE but no CVE (by CWE lookup)
      - CISA KEV (Known Exploited Vulnerabilities) — cached daily
      - searchsploit / Exploit-DB — if locally installed

    Updates Alert.has_public_exploit, .in_cisa_kev, .exploit_refs,
    then recalculates Scan.exploit_count and risk_score.
    """
    from scanner.exploit_checker import check_cves
    from scanner.cve_enrichment import enrich_alerts_by_cwe
    from django.conf import settings as _settings

    # Step 1: NVD CWE enrichment — fill CVEs for alerts that have CWE but no CVE
    api_key = getattr(_settings, 'NVD_API_KEY', '')
    try:
        enriched = enrich_alerts_by_cwe(scan, api_key=api_key)
        if enriched:
            logger.info('NVD CWE enrichment: filled CVEs for %d alerts in scan %s', enriched, scan.id)
    except Exception as exc:
        logger.warning('NVD CWE enrichment failed: %s', exc)

    alerts_with_cves = [a for a in scan.alerts.all() if a.cve_ids]
    if not alerts_with_cves:
        return

    all_cves = list({cve for a in alerts_with_cves for cve in a.cve_ids})
    logger.info('Exploit check: %d unique CVEs for scan %s', len(all_cves), scan.id)

    try:
        cve_results = check_cves(all_cves)
    except Exception as exc:
        logger.warning('Exploit enrichment failed: %s', exc)
        return

    updates = []
    for alert in alerts_with_cves:
        has_exploit = any(cve_results.get(c, {}).get('has_exploit') for c in alert.cve_ids)
        in_kev      = any(cve_results.get(c, {}).get('in_cisa_kev') for c in alert.cve_ids)
        refs = []
        for c in alert.cve_ids:
            refs.extend(cve_results.get(c, {}).get('sources', []))
        refs = list(dict.fromkeys(refs))[:10]   # dedupe, cap at 10

        if (has_exploit != alert.has_public_exploit
                or in_kev != alert.in_cisa_kev
                or refs != list(alert.exploit_refs or [])):
            alert.has_public_exploit = has_exploit
            alert.in_cisa_kev        = in_kev
            alert.exploit_refs       = refs
            updates.append(alert)

    if updates:
        Alert.objects.bulk_update(updates, ['has_public_exploit', 'in_cisa_kev', 'exploit_refs'])
        scan.update_counts()   # recalculates exploit_count + risk_score
        logger.info('Exploit enrichment: %d alerts updated for scan %s', len(updates), scan.id)


def _update_monthly_summary(scan):
    """Update or create MonthlySummary for this scan's month."""
    now = scan.completed_at or timezone.now()
    first_of_month = date(now.year, now.month, 1)

    summary, _ = MonthlySummary.objects.get_or_create(
        target=scan.target,
        year_month=first_of_month,
        defaults={
            'total_scans': 0, 'avg_risk_score': 0,
            'critical_count': 0, 'high_count': 0,
            'medium_count': 0, 'low_count': 0, 'info_count': 0,
        }
    )

    month_scans = Scan.objects.filter(
        target=scan.target,
        status=Scan.Status.COMPLETED,
        completed_at__year=now.year,
        completed_at__month=now.month,
    )

    summary.total_scans = month_scans.count()
    if summary.total_scans > 0:
        from django.db.models import Avg, Sum
        agg = month_scans.aggregate(
            avg_risk=Avg('risk_score'),
            total_critical=Sum('critical_count'),
            total_high=Sum('high_count'),
            total_medium=Sum('medium_count'),
            total_low=Sum('low_count'),
            total_info=Sum('info_count'),
        )
        summary.avg_risk_score = agg['avg_risk'] or 0
        summary.critical_count = agg['total_critical'] or 0
        summary.high_count = agg['total_high'] or 0
        summary.medium_count = agg['total_medium'] or 0
        summary.low_count = agg['total_low'] or 0
        summary.info_count = agg['total_info'] or 0

    summary.save()
