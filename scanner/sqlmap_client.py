"""sqlmap client — Automated SQL Injection detection (A03).

Runs sqlmap against a target URL and parses JSON output.
sqlmap must be installed: apt install sqlmap
"""
import json
import logging
import os
import re
import subprocess
import tempfile

logger = logging.getLogger(__name__)

SQLMAP_BIN = 'sqlmap'

# sqlmap risk/level → our risk score
INJECTION_RISK = {
    'boolean-based blind':  3,
    'time-based blind':     3,
    'error-based':          3,
    'union query':          4,
    'stacked queries':      4,
    'inline query':         3,
    'out-of-band':          4,
}

# sqlmap DBMS → description context
DBMS_OWASP = 'A03'  # All SQL injection maps to A03 (Injection)


class SqlmapClient:
    """Client for running sqlmap and parsing its JSON output."""

    def check_health(self):
        """Return True if sqlmap binary is available."""
        try:
            result = subprocess.run(
                [SQLMAP_BIN, '--version'],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_version(self):
        """Return sqlmap version string."""
        try:
            result = subprocess.run(
                [SQLMAP_BIN, '--version'],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if 'sqlmap' in line.lower():
                    return line.strip()
            return result.stdout.strip().splitlines()[0]
        except Exception as e:
            return f'error: {e}'

    def scan(self, target_url, scan_type='quick', forms=False, crawl=0):
        """Run sqlmap against target_url and return normalized findings.

        Args:
            target_url: URL to test (may include parameters: ?id=1&cat=2)
            scan_type:
              'quick'  → level 1, risk 1, 10 threads, no crawl (fast)
              'full'   → level 3, risk 2, crawl=2, test forms
              'deep'   → level 5, risk 3, crawl=3, test forms, all techniques
            forms: bool — also test HTML forms on the page
            crawl: int  — crawl depth (0 = no crawl)

        Returns:
            list of normalized finding dicts compatible with _store_findings()
        """
        level, risk, threads, techniques = self._scan_params(scan_type)

        # Output directory for sqlmap JSON results
        tmp_dir = tempfile.mkdtemp(prefix='sqlmap_')

        cmd = [
            SQLMAP_BIN,
            '--url', target_url,
            '--batch',              # Never ask for user input
            '--output-dir', tmp_dir,
            '--level', str(level),
            '--risk', str(risk),
            '--threads', str(threads),
            '--timeout', '30',
            '--retries', '2',
            '--json-output',        # Structured output
            '--technique', techniques,
        ]

        if forms or scan_type in ('full', 'deep'):
            cmd += ['--forms']

        if crawl or scan_type in ('full', 'deep'):
            cmd += ['--crawl', str(crawl or (2 if scan_type == 'full' else 3))]

        # Disable interactive prompts
        cmd += ['--no-logging']

        timeout = 300 if scan_type == 'quick' else 900

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f'sqlmap timed out after {timeout}s on {target_url}')
            output = ''
        except Exception as e:
            logger.exception(f'sqlmap failed: {e}')
            return []

        # Try to find JSON output file in tmp_dir
        findings = self._parse_json_output(tmp_dir, target_url, output)

        # Clean up temp dir
        try:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

        return findings

    def _scan_params(self, scan_type):
        """Return (level, risk, threads, techniques) for scan type."""
        return {
            'quick': (1, 1, 10, 'BEUST'),  # Boolean, Error, Union, Stacked, Time
            'full':  (3, 2,  5, 'BEUST'),
            'deep':  (5, 3,  3, 'BEUST'),
        }.get(scan_type, (1, 1, 10, 'BEUST'))

    def _parse_json_output(self, tmp_dir, target_url, raw_output):
        """Parse sqlmap JSON output files and raw stdout for findings."""
        findings = []

        # Look for JSON result files under tmp_dir/<hostname>/
        for root, _, files in os.walk(tmp_dir):
            for fname in files:
                if fname.endswith('.json') or fname == 'results':
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath) as f:
                            data = json.load(f)
                        findings.extend(self._parse_sqlmap_json(data, target_url))
                    except Exception:
                        pass

        # If no JSON files, fall back to parsing stdout
        if not findings:
            findings = self._parse_stdout(raw_output, target_url)

        return findings

    def _parse_sqlmap_json(self, data, target_url):
        """Parse sqlmap JSON result structure into normalized findings."""
        findings = []

        # sqlmap JSON: {"url": ..., "data": {"param": {...injection data...}}}
        if not isinstance(data, dict):
            return []

        url = data.get('url', target_url)
        payload_data = data.get('data', {})

        if not payload_data:
            return []

        for param, param_data in payload_data.items():
            if not isinstance(param_data, dict):
                continue

            injections = param_data.get('data', {})
            dbms = param_data.get('dbms', 'Unknown')

            for tech_id, tech_data in injections.items():
                if not isinstance(tech_data, dict):
                    continue

                title    = tech_data.get('title', f'SQL Injection in {param}')
                payload  = tech_data.get('payload', '')
                place    = tech_data.get('place', 'GET')
                vector   = tech_data.get('vector', '')

                # Map technique title to risk
                risk = 3  # default High
                for pattern, r in INJECTION_RISK.items():
                    if pattern.lower() in title.lower():
                        risk = r
                        break

                cvss_score = 9.8 if risk == 4 else 8.8  # Critical/High CVSS

                findings.append({
                    'name': f'SQL Injection — {param} ({title})',
                    'risk': risk,
                    'description': (
                        f'SQL Injection vulnerability detected in parameter "{param}" '
                        f'via {place} request.\n\n'
                        f'Database: {dbms}\n'
                        f'Technique: {title}\n'
                        f'Vector: {vector}'
                    ),
                    'solution': (
                        'Use parameterised queries (prepared statements) or an ORM. '
                        'Never concatenate user input into SQL strings. '
                        'Apply input validation and whitelist allowable characters. '
                        'Enforce least-privilege database accounts.'
                    ),
                    'reference': (
                        'https://owasp.org/www-community/attacks/SQL_Injection\n'
                        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
                    ),
                    'url': url,
                    'cwe_id': 89,
                    'cvss_score': cvss_score,
                    'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    'alert_ref': f'sqli-{param}-{tech_id}'[:50],
                    'evidence': f'Parameter: {param}\nPayload: {payload[:300]}',
                    'tool': 'sqlmap',
                    'owasp_category': DBMS_OWASP,
                })

        return findings

    def _parse_stdout(self, output, target_url):
        """Parse sqlmap stdout when JSON files are unavailable."""
        findings = []
        if not output:
            return []

        # Detect injection summary lines
        # e.g.: "Parameter: id (GET)"
        # e.g.: "    Type: boolean-based blind"
        # e.g.: "    Title: AND boolean-based blind - WHERE or HAVING clause"
        # e.g.: "    Payload: id=1 AND 1=1"

        param_blocks = re.split(r'\n(?=Parameter:)', output)
        for block in param_blocks:
            param_match = re.search(r'Parameter:\s*(\S+)\s*\((\w+)\)', block)
            if not param_match:
                continue

            param = param_match.group(1)
            place = param_match.group(2)

            type_match  = re.search(r'Type:\s*(.+)', block)
            title_match = re.search(r'Title:\s*(.+)', block)
            payload_match = re.search(r'Payload:\s*(.+)', block)
            dbms_match  = re.search(r'back-end DBMS:\s*(.+)', output, re.IGNORECASE)

            technique = type_match.group(1).strip() if type_match else 'SQL Injection'
            title     = title_match.group(1).strip() if title_match else technique
            payload   = payload_match.group(1).strip() if payload_match else ''
            dbms      = dbms_match.group(1).strip() if dbms_match else 'Unknown'

            risk = 3
            for pattern, r in INJECTION_RISK.items():
                if pattern.lower() in technique.lower():
                    risk = r
                    break

            cvss_score = 9.8 if risk == 4 else 8.8

            findings.append({
                'name': f'SQL Injection — {param} ({technique})',
                'risk': risk,
                'description': (
                    f'SQL Injection detected in parameter "{param}" ({place}).\n\n'
                    f'Technique: {title}\nDatabase: {dbms}'
                ),
                'solution': (
                    'Use parameterised queries. Never concatenate user input into SQL. '
                    'Apply input validation and use least-privilege DB accounts.'
                ),
                'reference': (
                    'https://owasp.org/www-community/attacks/SQL_Injection\n'
                    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
                ),
                'url': target_url,
                'cwe_id': 89,
                'cvss_score': cvss_score,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'alert_ref': f'sqli-{param}'[:50],
                'evidence': f'Parameter: {param}\nPayload: {payload[:300]}',
                'tool': 'sqlmap',
                'owasp_category': DBMS_OWASP,
            })

        return findings
