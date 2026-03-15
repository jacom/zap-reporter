"""testssl.sh scanner client — Cryptographic Failures (A04)."""
import json
import logging
import subprocess

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'WARN': 1,
    'OK': 0,
    'INFO': 0,
}

# CWE mapping for common TLS issues
TLS_CWE_MAP = {
    'BEAST': 310,
    'BREACH': 310,
    'CRIME': 310,
    'DROWN': 310,
    'FREAK': 310,
    'Heartbleed': 119,
    'LOGJAM': 310,
    'LUCKY13': 310,
    'POODLE': 310,
    'ROBOT': 310,
    'SWEET32': 310,
    'ticketbleed': 200,
    'CCS': 310,
    'secure_renego': 310,
    'cert_chain': 295,
    'cert_expirationStatus': 298,
    'cert_notAfter': 298,
    'cert_signatureAlgorithm': 327,
    'protocol': 326,
    'cipher_order': 326,
}


class SSLScannerClient:
    """Client wrapping testssl.sh CLI."""

    def check_health(self):
        """Check if testssl.sh is available."""
        try:
            result = subprocess.run(
                ['testssl', '--version'],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0 or 'testssl' in result.stdout.lower()
        except Exception:
            return False

    def get_version(self):
        """Get testssl.sh version (returns short version e.g. '3.3')."""
        import re
        _ansi = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
        _ver  = re.compile(r'\d+\.\d+(?:\.\d+)*(?:-[a-z]\w*)?')
        try:
            result = subprocess.run(
                ['testssl', '--version'],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                clean = _ansi.sub('', line).strip()
                if 'testssl' in clean.lower() and 'version' in clean.lower():
                    m = _ver.search(clean)
                    return m.group(0) if m else clean
            return ''
        except Exception:
            return ''

    def scan(self, hostname):
        """Run full TLS scan on a hostname.

        Args:
            hostname: hostname or hostname:port (e.g. 'example.com' or '10.0.0.1:8443')

        Returns:
            list of normalized finding dicts
        """
        try:
            result = subprocess.run(
                [
                    'testssl',
                    '--jsonfile-pretty', '/dev/stdout',
                    '--color', '0',
                    '--quiet',
                    hostname,
                ],
                capture_output=True, text=True, timeout=300,
            )
            return self._parse_results(result.stdout, hostname)
        except subprocess.TimeoutExpired:
            logger.error(f'testssl scan timed out for {hostname}')
            return []
        except Exception as e:
            logger.exception(f'testssl scan failed: {e}')
            return []

    def scan_quick(self, hostname):
        """Run quick scan (protocols + ciphers + vulns only)."""
        try:
            result = subprocess.run(
                [
                    'testssl',
                    '--protocols', '--ciphers', '--vulnerable',
                    '--jsonfile-pretty', '/dev/stdout',
                    '--color', '0',
                    '--quiet',
                    hostname,
                ],
                capture_output=True, text=True, timeout=180,
            )
            return self._parse_results(result.stdout, hostname)
        except Exception as e:
            logger.exception(f'testssl quick scan failed: {e}')
            return []

    def _parse_results(self, json_output, hostname):
        """Parse testssl.sh JSON output into normalized finding dicts."""
        if not json_output:
            return []

        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            logger.error('Failed to parse testssl JSON output')
            return []

        if not isinstance(data, list):
            data = [data]

        findings = []
        for entry in data:
            severity_str = entry.get('severity', 'INFO').upper()
            if severity_str in ('OK', 'INFO'):
                continue

            test_id = entry.get('id', '')
            finding_text = entry.get('finding', '')
            cwe = self._map_cwe(test_id)

            findings.append({
                'name': f"[TLS] {test_id}: {finding_text}"[:500],
                'risk': SEVERITY_MAP.get(severity_str, 0),
                'description': f"Test: {test_id}\nFinding: {finding_text}",
                'solution': self._suggest_fix(test_id, severity_str),
                'reference': 'https://testssl.sh/',
                'url': hostname,
                'cwe_id': cwe,
                'cvss_score': self._severity_to_cvss(severity_str),
                'cvss_vector': '',
                'alert_ref': test_id,
                'evidence': entry.get('finding', ''),
                'tool': 'testssl',
                'owasp_category': 'A04',
            })

        return findings

    def _map_cwe(self, test_id):
        """Map testssl test ID to CWE."""
        for key, cwe in TLS_CWE_MAP.items():
            if key.lower() in test_id.lower():
                return cwe
        return 326  # default: Inadequate Encryption Strength

    def _suggest_fix(self, test_id, severity):
        """Provide basic fix suggestion based on test ID."""
        fixes = {
            'BEAST': 'Disable CBC ciphers or upgrade to TLS 1.2+',
            'BREACH': 'Disable HTTP compression on HTTPS responses',
            'CRIME': 'Disable TLS compression',
            'DROWN': 'Disable SSLv2 completely',
            'FREAK': 'Remove EXPORT cipher suites',
            'Heartbleed': 'Upgrade OpenSSL immediately',
            'LOGJAM': 'Use DH parameters >= 2048 bits',
            'POODLE': 'Disable SSLv3',
            'ROBOT': 'Disable RSA key exchange',
            'SWEET32': 'Disable 3DES and other 64-bit block ciphers',
        }
        for key, fix in fixes.items():
            if key.lower() in test_id.lower():
                return fix
        if severity in ('CRITICAL', 'HIGH'):
            return 'Review TLS configuration and update to modern standards'
        return 'Consider upgrading TLS configuration'

    def _severity_to_cvss(self, severity):
        scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 3.0,
            'WARN': 3.0,
            'INFO': 0.0,
        }
        return scores.get(severity, 0.0)
