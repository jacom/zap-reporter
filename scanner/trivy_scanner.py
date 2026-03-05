"""Trivy scanner client — Supply Chain (A03) + Integrity (A08)."""
import json
import logging
import subprocess

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'UNKNOWN': 0,
}


class TrivyClient:
    """Client for Trivy server API and CLI."""

    def __init__(self, server_url=None):
        self.server_url = (server_url or settings.TRIVY_SERVER_URL).rstrip('/')

    def check_health(self):
        """Check if Trivy server is running."""
        try:
            resp = requests.get(f'{self.server_url}/healthz', timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def get_version(self):
        """Get Trivy version via CLI."""
        try:
            result = subprocess.run(
                ['trivy', '--version'],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if line.startswith('Version:'):
                    return line.split(':', 1)[1].strip()
            return result.stdout.strip().split('\n')[0]
        except Exception as e:
            return f'error: {e}'

    def scan_fs(self, path):
        """Scan filesystem/source code for vulnerabilities.

        Returns list of normalized finding dicts.
        """
        try:
            result = subprocess.run(
                [
                    'trivy', 'fs',
                    '--format', 'json',
                    '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                    '--cache-dir', '/var/cache/trivy',
                    '--quiet',
                    path,
                ],
                capture_output=True, text=True, timeout=600,
            )
            return self._parse_results(result.stdout)
        except Exception as e:
            logger.exception(f'Trivy fs scan failed: {e}')
            return []

    def scan_image(self, image_name):
        """Scan container image for vulnerabilities."""
        try:
            result = subprocess.run(
                [
                    'trivy', 'image',
                    '--format', 'json',
                    '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                    '--cache-dir', '/var/cache/trivy',
                    '--quiet',
                    image_name,
                ],
                capture_output=True, text=True, timeout=600,
            )
            return self._parse_results(result.stdout)
        except Exception as e:
            logger.exception(f'Trivy image scan failed: {e}')
            return []

    def scan_repo(self, repo_url):
        """Scan git repository."""
        try:
            result = subprocess.run(
                [
                    'trivy', 'repo',
                    '--format', 'json',
                    '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                    '--cache-dir', '/var/cache/trivy',
                    '--quiet',
                    repo_url,
                ],
                capture_output=True, text=True, timeout=600,
            )
            return self._parse_results(result.stdout)
        except Exception as e:
            logger.exception(f'Trivy repo scan failed: {e}')
            return []

    def scan_sbom(self, path):
        """Generate SBOM (CycloneDX format)."""
        try:
            result = subprocess.run(
                [
                    'trivy', 'fs',
                    '--format', 'cyclonedx',
                    '--cache-dir', '/var/cache/trivy',
                    '--quiet',
                    path,
                ],
                capture_output=True, text=True, timeout=600,
            )
            return json.loads(result.stdout) if result.stdout else {}
        except Exception as e:
            logger.exception(f'Trivy SBOM generation failed: {e}')
            return {}

    def _parse_results(self, json_output):
        """Parse Trivy JSON output into normalized alert dicts."""
        if not json_output:
            return []

        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            logger.error('Failed to parse Trivy JSON output')
            return []

        findings = []
        results = data.get('Results', [])
        for result in results:
            target_name = result.get('Target', '')
            vulns = result.get('Vulnerabilities') or []
            for v in vulns:
                severity = v.get('Severity', 'UNKNOWN').upper()
                cvss_data = v.get('CVSS', {})
                cvss_score = 0.0
                cvss_vector = ''
                for source in cvss_data.values():
                    if isinstance(source, dict) and 'V3Score' in source:
                        cvss_score = source['V3Score']
                        cvss_vector = source.get('V3Vector', '')
                        break

                findings.append({
                    'name': f"{v.get('VulnerabilityID', '')} - {v.get('PkgName', '')}",
                    'risk': SEVERITY_MAP.get(severity, 0),
                    'description': v.get('Description', ''),
                    'solution': v.get('FixedVersion', ''),
                    'reference': '\n'.join(v.get('References', [])[:5]),
                    'url': target_name,
                    'cwe_id': self._extract_cwe(v.get('CweIDs', [])),
                    'cvss_score': cvss_score,
                    'cvss_vector': cvss_vector,
                    'alert_ref': v.get('VulnerabilityID', ''),
                    'evidence': f"Package: {v.get('PkgName', '')} "
                                f"Installed: {v.get('InstalledVersion', '')} "
                                f"Fixed: {v.get('FixedVersion', 'N/A')}",
                    'tool': 'trivy',
                    'owasp_category': 'A03',
                })

        return findings

    @classmethod
    def parse_file_content(cls, content):
        """Parse uploaded Trivy report (JSON or SARIF) without connecting to server.

        Supports:
          - Trivy native JSON  (trivy image -f json)
          - SARIF              (trivy image -f sarif)

        Returns normalized finding dicts compatible with _store_findings().
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"ไฟล์ไม่ใช่ JSON ที่ถูกต้อง: {exc}") from exc

        # Create lightweight instance (no server connection needed)
        obj = object.__new__(cls)

        # SARIF format (trivy -f sarif or any SARIF producer)
        if 'runs' in data and isinstance(data.get('runs'), list):
            return obj._parse_sarif(data)

        # Trivy native JSON
        if 'Results' in data:
            return obj._parse_results(content)

        raise ValueError(
            "ไม่รู้จักรูปแบบไฟล์ — รองรับเฉพาะ Trivy JSON (-f json) หรือ SARIF (-f sarif)"
        )

    def _parse_sarif(self, data):
        """Parse SARIF output from Trivy."""
        findings = []
        for run in data.get('runs', []):
            # Build rule metadata lookup by ruleId
            rules = {
                r['id']: r
                for r in run.get('tool', {}).get('driver', {}).get('rules', [])
            }
            for result in run.get('results', []):
                rule_id = result.get('ruleId', '')
                rule = rules.get(rule_id, {})
                rule_props = rule.get('properties', {})

                level = result.get('level', 'note')
                level_risk = {'error': 3, 'warning': 2, 'note': 1, 'none': 0}
                risk = level_risk.get(level, 0)

                locations = result.get('locations', [])
                url = ''
                if locations:
                    phys = locations[0].get('physicalLocation', {})
                    url = phys.get('artifactLocation', {}).get('uri', '')

                cvss_score = 0.0
                try:
                    cvss_score = float(
                        rule_props.get('cvss-v3-base-score') or
                        rule_props.get('security-severity') or 0
                    )
                except (ValueError, TypeError):
                    pass

                desc = (
                    result.get('message', {}).get('text', '') or
                    rule.get('fullDescription', {}).get('text', '') or
                    rule.get('shortDescription', {}).get('text', '')
                )

                findings.append({
                    'name': f"{rule_id} - {rule.get('name', rule_id)}"[:500],
                    'risk': risk,
                    'description': desc[:4000],
                    'solution': rule_props.get('solution', '')[:2000],
                    'reference': '\n'.join(rule_props.get('references', [])[:5])[:2000],
                    'url': url[:2000],
                    'cwe_id': 0,
                    'cvss_score': cvss_score,
                    'cvss_vector': '',
                    'alert_ref': rule_id[:50],
                    'evidence': '',
                    'tool': 'trivy',
                    'owasp_category': 'A03',
                })
        return findings

    def _extract_cwe(self, cwe_ids):
        """Extract first CWE ID as integer."""
        for cwe in cwe_ids:
            try:
                return int(cwe.replace('CWE-', ''))
            except (ValueError, AttributeError):
                continue
        return 0
