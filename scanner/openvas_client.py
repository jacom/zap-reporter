"""OpenVAS/GVM client — Network Vulnerability Assessment (A01/A02/A07).

Supports GSA 24.x which uses GMP XML commands via the gsad web interface.
Auth: POST /login with cmd=login → returns token + session cookie.
Commands: GET /gmp?cmd=<GMP_COMMAND>&token=<TOKEN> with session cookie.
"""
import logging
import xml.etree.ElementTree as ET

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

THREAT_MAP = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Low': 1,
    'Log': 0,
    'Debug': 0,
}


class OpenVASClient:
    """Client for OpenVAS/GVM via GSA (Greenbone Security Assistant)."""

    def __init__(self, base_url=None, user=None, password=None):
        self.base_url = (base_url or settings.OPENVAS_URL).rstrip('/')
        self.user = user or settings.OPENVAS_USER
        self.password = password or settings.OPENVAS_PASSWORD
        self.session = requests.Session()
        self.session.verify = False
        self._token = None

    def _authenticate(self):
        """Authenticate with GSA via form-based login."""
        try:
            resp = self.session.post(
                f'{self.base_url}/login',
                data={
                    'cmd': 'login',
                    'login': self.user,
                    'password': self.password,
                },
                timeout=10,
            )
            if resp.status_code != 200:
                return False

            root = ET.fromstring(resp.text)
            token = root.findtext('token', '')
            if token:
                self._token = token
                return True
            return False
        except Exception:
            logger.exception('OpenVAS authentication failed')
            return False

    def _gmp(self, cmd, extra_params=None):
        """Execute a GMP command via GSA and return parsed XML root."""
        if not self._token:
            if not self._authenticate():
                return None

        params = {'cmd': cmd, 'token': self._token}
        if extra_params:
            params.update(extra_params)

        resp = self.session.get(
            f'{self.base_url}/gmp',
            params=params,
            timeout=60,
        )
        if resp.status_code != 200:
            return None

        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError:
            logger.error('Failed to parse GMP response')
            return None

        # Check for auth error — re-auth once and retry
        err = root.findtext('.//gsad_response/title', '')
        if 'Authentication required' in err:
            self._token = None
            if not self._authenticate():
                return None
            params['token'] = self._token
            resp = self.session.get(
                f'{self.base_url}/gmp',
                params=params,
                timeout=60,
            )
            try:
                root = ET.fromstring(resp.text)
            except ET.ParseError:
                return None

        return root

    def check_health(self):
        """Check if OpenVAS/GVM is accessible."""
        try:
            resp = self.session.get(f'{self.base_url}/', timeout=5)
            return resp.status_code in (200, 302, 401)
        except Exception:
            return False

    def get_version(self):
        """Get GVM version via get_version command."""
        try:
            root = self._gmp('get_version')
            if root is None:
                return 'unknown'
            ver = root.findtext('.//version', '')
            return ver or 'connected'
        except Exception as e:
            return f'error: {e}'

    def get_tasks(self):
        """List scan tasks."""
        try:
            root = self._gmp('get_tasks')
            if root is None:
                return []
            tasks = []
            for t in root.findall('.//task'):
                lr = t.find('.//last_report/report')
                tasks.append({
                    'id': t.get('id', ''),
                    'name': t.findtext('name', ''),
                    'status': t.findtext('status', ''),
                    'last_report_id': lr.get('id', '') if lr is not None else '',
                })
            return tasks
        except Exception as e:
            logger.exception(f'OpenVAS tasks fetch failed: {e}')
            return []

    def get_report(self, report_id):
        """Get a specific report and parse all results with pagination.

        GSA 24.x nests results under:
        envelope/get_reports/get_reports_response/report/report/results/result
        GSA ignores max_results and returns ~10 per page, so we paginate.

        Returns list of normalized finding dicts.
        """
        findings = []
        seen = set()
        first = 1
        page_size = 100

        while True:
            root = self._gmp('get_reports', {
                'report_id': report_id,
                'details': '1',
                'first_result': str(first),
                'max_results': str(page_size),
                'filter': f'first={first} rows={page_size} min_qod=0 levels=hmlg',
            })
            if root is None:
                break

            results = root.findall(
                './/get_reports_response/report/report/results/result'
            )
            if not results:
                results = root.findall('.//results/result')
            if not results:
                break

            new_count = 0
            for result in results:
                finding = self._parse_result(result)
                key = (finding['alert_ref'], finding['url'])
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
                    new_count += 1

            # Get total from result_count
            full_count = root.findtext('.//result_count/filtered', '0')
            try:
                total = int(full_count)
            except ValueError:
                total = 0

            first += len(results)
            # Stop if we've fetched everything or no new unique results
            if first > total or new_count == 0:
                break

        return findings

    def get_latest_report(self, task_id=None):
        """Get the latest report from the most recent completed task.

        If task_id is provided, fetch the report from that specific task only.
        """
        try:
            tasks = self.get_tasks()
            if not tasks:
                return []

            # Find the task with a last report
            report_id = None
            if task_id:
                # Find the specific task by ID
                for task in tasks:
                    if task.get('id') == task_id:
                        report_id = task.get('last_report_id', '')
                        break
            else:
                # Default: first task with a report
                for task in tasks:
                    rid = task.get('last_report_id', '')
                    if rid:
                        report_id = rid
                        break

            if not report_id:
                return []

            return self.get_report(report_id)
        except Exception as e:
            logger.exception(f'OpenVAS latest report fetch failed: {e}')
            return []

    def _parse_result(self, result):
        """Parse a single <result> XML element into a normalized finding dict."""
        nvt = result.find('nvt') or ET.Element('nvt')
        threat = result.findtext('threat', 'Log')
        host = result.findtext('host', '')
        port = result.findtext('port', '')

        # CVSS
        cvss_text = nvt.findtext('cvss_base', '0') or '0'
        try:
            cvss_score = float(cvss_text)
        except ValueError:
            cvss_score = 0.0

        # CWE from refs
        cwe_id = 0
        ref_strs = []
        for ref in nvt.findall('.//refs/ref'):
            ref_id = ref.get('id', '')
            ref_type = ref.get('type', '')
            if ref_id.startswith('CWE-'):
                try:
                    cwe_id = int(ref_id.replace('CWE-', ''))
                except ValueError:
                    pass
            if ref_id:
                ref_strs.append(ref_id)

        # Solution
        solution_el = nvt.find('solution')
        solution = ''
        if solution_el is not None:
            solution = solution_el.text or solution_el.get('type', '')

        target = f'{host}:{port}' if port and port != 'general/tcp' else host

        return {
            'name': nvt.findtext('name', 'Unknown')[:500],
            'risk': THREAT_MAP.get(threat, 0),
            'description': result.findtext('description', ''),
            'solution': solution,
            'reference': '\n'.join(ref_strs[:20]),
            'url': target,
            'cwe_id': cwe_id,
            'cvss_score': cvss_score,
            'cvss_vector': '',
            'alert_ref': nvt.get('oid', ''),
            'evidence': result.findtext('description', '')[:500],
            'tool': 'openvas',
            'owasp_category': self._map_owasp(nvt),
        }

    def _map_owasp(self, nvt):
        """Map OpenVAS NVT family to OWASP 2025 category."""
        family = (nvt.findtext('family', '') or '').lower()
        tags = (nvt.findtext('tags', '') or '').lower()

        if any(k in family for k in ('web', 'xss', 'injection', 'sql')):
            return 'A05'
        if any(k in family for k in ('ssl', 'tls', 'crypto')):
            return 'A04'
        if any(k in family for k in ('default', 'credentials', 'brute')):
            return 'A07'
        if any(k in tags for k in ('access', 'privilege', 'traversal')):
            return 'A01'
        if any(k in family for k in ('general', 'policy', 'compliance')):
            return 'A02'
        return ''
