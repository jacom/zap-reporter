"""SonarQube client — SAST/Code Quality (A06/A08/A05/A10)."""
import json
import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    'BLOCKER': 4,
    'CRITICAL': 4,
    'MAJOR': 3,
    'MINOR': 2,
    'INFO': 0,
}

# Map SonarQube issue types/tags to OWASP 2025 categories
SONAR_OWASP_MAP = {
    'sql-injection': 'A05',
    'command-injection': 'A05',
    'xpath-injection': 'A05',
    'ldap-injection': 'A05',
    'xss': 'A05',
    'insecure-deserialization': 'A08',
    'weak-cryptography': 'A04',
    'insecure-conf': 'A02',
    'auth': 'A07',
    'csrf': 'A01',
    'ssrf': 'A01',
    'path-traversal': 'A01',
    'insecure-design': 'A06',
    'error-handling': 'A10',
}


class SonarQubeClient:
    """Client for SonarQube REST API."""

    def __init__(self, base_url=None, token=None):
        self.base_url = (base_url or settings.SONARQUBE_URL).rstrip('/')
        self.token = token or settings.SONARQUBE_TOKEN
        self.session = requests.Session()
        if self.token:
            self.session.auth = (self.token, '')

    def _get(self, endpoint, params=None):
        url = f'{self.base_url}/api{endpoint}'
        resp = self.session.get(url, params=params or {}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def check_health(self):
        """Check SonarQube status."""
        try:
            data = self._get('/system/status')
            return data.get('status') == 'UP'
        except Exception:
            return False

    def get_version(self):
        """Get SonarQube version."""
        try:
            data = self._get('/system/status')
            return data.get('version', 'unknown')
        except Exception as e:
            return f'error: {e}'

    def get_projects(self):
        """List all projects."""
        data = self._get('/projects/search', {'ps': 500})
        return data.get('components', [])

    def get_issues(self, project_key, severities=None, page=1, page_size=100):
        """Get issues for a project.

        Returns list of normalized finding dicts.
        """
        params = {
            'componentKeys': project_key,
            'ps': page_size,
            'p': page,
            'statuses': 'OPEN,CONFIRMED,REOPENED',
        }
        if severities:
            params['severities'] = severities

        try:
            data = self._get('/issues/search', params)
        except Exception as e:
            logger.exception(f'SonarQube issues fetch failed: {e}')
            return [], 0

        total = data.get('paging', {}).get('total', 0)
        issues = data.get('issues', [])
        return self._parse_issues(issues), total

    def get_all_issues(self, project_key, severities=None):
        """Fetch all pages of issues for a project."""
        all_findings = []
        page = 1
        while True:
            findings, total = self.get_issues(project_key, severities, page)
            all_findings.extend(findings)
            if len(all_findings) >= total or not findings:
                break
            page += 1
        return all_findings

    def get_measures(self, project_key):
        """Get project quality metrics."""
        metrics = (
            'bugs,vulnerabilities,code_smells,coverage,'
            'duplicated_lines_density,ncloc,sqale_rating,'
            'reliability_rating,security_rating,security_hotspots'
        )
        try:
            data = self._get('/measures/component', {
                'component': project_key,
                'metricKeys': metrics,
            })
            measures = data.get('component', {}).get('measures', [])
            return {m['metric']: m.get('value', '') for m in measures}
        except Exception as e:
            logger.exception(f'SonarQube measures fetch failed: {e}')
            return {}

    def _parse_issues(self, issues):
        """Parse SonarQube issues into normalized finding dicts."""
        findings = []
        for issue in issues:
            severity = issue.get('severity', 'INFO').upper()
            tags = issue.get('tags', [])
            owasp_cat = self._map_owasp(tags, issue.get('type', ''))

            cwe_id = 0
            for tag in tags:
                if tag.startswith('cwe-'):
                    try:
                        cwe_id = int(tag.replace('cwe-', ''))
                    except ValueError:
                        pass
                    break

            component = issue.get('component', '')
            line = issue.get('line', '')
            location = f'{component}:{line}' if line else component

            findings.append({
                'name': issue.get('message', '')[:500],
                'risk': SEVERITY_MAP.get(severity, 0),
                'description': (
                    f"Rule: {issue.get('rule', '')}\n"
                    f"Type: {issue.get('type', '')}\n"
                    f"Effort: {issue.get('effort', 'N/A')}"
                ),
                'solution': '',
                'reference': f"https://rules.sonarsource.com/search?q={issue.get('rule', '')}",
                'url': location,
                'cwe_id': cwe_id,
                'cvss_score': self._severity_to_cvss(severity),
                'cvss_vector': '',
                'alert_ref': issue.get('key', ''),
                'evidence': f"Tags: {', '.join(tags)}" if tags else '',
                'tool': 'sonarqube',
                'owasp_category': owasp_cat,
            })

        return findings

    def _map_owasp(self, tags, issue_type):
        """Map SonarQube tags to OWASP 2025 category."""
        for tag in tags:
            tag_lower = tag.lower()
            # Direct OWASP tag from SonarQube
            if tag_lower.startswith('owasp-'):
                return tag_lower.replace('owasp-', '').upper()
            for key, cat in SONAR_OWASP_MAP.items():
                if key in tag_lower:
                    return cat

        if issue_type == 'VULNERABILITY':
            return 'A06'
        if issue_type == 'BUG':
            return 'A10'
        return ''

    @classmethod
    def parse_file_content(cls, content, filename=''):
        """Parse uploaded SonarQube report without connecting to server.

        Supports:
          - SonarQube JSON API export  (issues.search API response)
          - SARIF JSON                 (sonar-scanner with SARIF reporter)
          - Generic XML issues export

        Returns normalized finding dicts compatible with _store_findings().
        """
        obj = object.__new__(cls)
        obj.base_url = ''
        obj.token = ''

        stripped = content.strip()

        # XML
        if stripped.startswith('<') or (filename and filename.lower().endswith('.xml')):
            return obj._parse_xml_content(stripped)

        # JSON
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"ไฟล์ไม่ใช่ JSON หรือ XML ที่ถูกต้อง: {exc}") from exc

        # SARIF (sonar-scanner --sarif or any SARIF tool)
        if 'runs' in data and isinstance(data.get('runs'), list):
            return obj._parse_sarif_content(data)

        # SonarQube native API JSON
        if 'issues' in data:
            return obj._parse_issues(data.get('issues', []))

        raise ValueError(
            "ไม่รู้จักรูปแบบไฟล์ — รองรับ SonarQube JSON (API export), SARIF, หรือ XML"
        )

    def _parse_sarif_content(self, data):
        """Parse SARIF format from SonarQube or compatible tools."""
        findings = []
        for run in data.get('runs', []):
            rules = {
                r['id']: r
                for r in run.get('tool', {}).get('driver', {}).get('rules', [])
            }
            for result in run.get('results', []):
                rule_id = result.get('ruleId', '')
                rule = rules.get(rule_id, {})

                level = result.get('level', 'note')
                level_risk = {'error': 3, 'warning': 2, 'note': 1, 'none': 0}
                risk = level_risk.get(level, 0)

                locations = result.get('locations', [])
                url = ''
                if locations:
                    phys = locations[0].get('physicalLocation', {})
                    al = phys.get('artifactLocation', {})
                    region = phys.get('region', {})
                    line = region.get('startLine', '')
                    uri = al.get('uri', '')
                    url = f"{uri}:{line}" if line else uri

                desc = result.get('message', {}).get('text', '') or \
                       rule.get('fullDescription', {}).get('text', '')

                severity = rule.get('properties', {}).get('severity', 'MAJOR').upper()
                cvss_score = self._severity_to_cvss(severity)

                tags = rule.get('properties', {}).get('tags', [])
                owasp_cat = self._map_owasp(tags, 'VULNERABILITY')

                findings.append({
                    'name': result.get('message', {}).get('text', rule_id)[:500],
                    'risk': SEVERITY_MAP.get(severity, risk),
                    'description': f"Rule: {rule_id}\n{desc}"[:4000],
                    'solution': '',
                    'reference': f"https://rules.sonarsource.com/search?q={rule_id}",
                    'url': url[:2000],
                    'cwe_id': 0,
                    'cvss_score': cvss_score,
                    'cvss_vector': '',
                    'alert_ref': rule_id[:50],
                    'evidence': '',
                    'tool': 'sonarqube',
                    'owasp_category': owasp_cat,
                })
        return findings

    def _parse_xml_content(self, content):
        """Parse generic SonarQube XML issues export."""
        import xml.etree.ElementTree as ET
        findings = []
        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ValueError(f"XML parse error: {exc}") from exc

        # Support <issues>/<issue> or <report>/<issues>/<issue>
        issues = root.findall('.//issue') or root.findall('.//Issue')
        for issue in issues:
            def _text(tag):
                el = issue.find(tag) or issue.find(tag.lower())
                return el.text.strip() if el is not None and el.text else ''

            severity = (_text('severity') or _text('Severity')).upper()
            rule = _text('rule') or _text('Rule') or _text('key')
            message = _text('message') or _text('Message') or _text('description')
            component = _text('component') or _text('Component') or _text('file')
            line = _text('line') or _text('Line')
            url = f"{component}:{line}" if line else component

            findings.append({
                'name': message[:500] or rule,
                'risk': SEVERITY_MAP.get(severity, 0),
                'description': f"Rule: {rule}\n{message}"[:4000],
                'solution': '',
                'reference': '',
                'url': url[:2000],
                'cwe_id': 0,
                'cvss_score': self._severity_to_cvss(severity),
                'cvss_vector': '',
                'alert_ref': rule[:50],
                'evidence': '',
                'tool': 'sonarqube',
                'owasp_category': '',
            })
        return findings

    def _severity_to_cvss(self, severity):
        scores = {
            'BLOCKER': 9.5,
            'CRITICAL': 9.0,
            'MAJOR': 7.0,
            'MINOR': 4.0,
            'INFO': 0.0,
        }
        return scores.get(severity, 0.0)
