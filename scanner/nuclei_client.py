"""
Nuclei scanner integration.

Nuclei is a fast template-based vulnerability scanner.
Output: JSONL — one JSON object per finding when run with -jsonl flag.

Severity mapping:
  critical → risk 4
  high     → risk 3
  medium   → risk 2
  low      → risk 1
  info     → risk 0
"""
import json
import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)

_SEV_MAP = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'info': 0,
    'informational': 0,
    'unknown': 0,
}

# Default tag groups to scan (covers most OWASP Top 10)
DEFAULT_TAGS = 'cve,panel,misconfiguration,exposure,xss,sqli,ssrf,lfi,rce,auth-bypass,default-login,cors'

# Template paths that are too noisy for automated scans
EXCLUDED_TAGS = 'dos,fuzz'


class NucleiClient:
    """Wrapper around the nuclei binary."""

    def __init__(self, binary=None):
        self.binary = binary or shutil.which('nuclei') or '/usr/local/bin/nuclei'

    def check_health(self):
        try:
            r = subprocess.run(
                [self.binary, '--version'],
                capture_output=True, timeout=10,
            )
            return r.returncode == 0
        except Exception:
            return False

    def get_version(self):
        try:
            r = subprocess.run(
                [self.binary, '--version', '-nc'],
                capture_output=True, text=True, timeout=10,
            )
            output = (r.stderr or '') + (r.stdout or '')
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Strip "[INF] " prefix if present
                if '] ' in line:
                    line = line.split('] ', 1)[-1]
                return line
        except Exception:
            pass
        return 'unknown'

    def scan(self, target_url, tags=None, severity=None, timeout=600,
             rate_limit=50, concurrency=10):
        """Run nuclei scan and return list of parsed finding dicts.

        Parameters
        ----------
        target_url : str
        tags : str  comma-separated nuclei tags, default DEFAULT_TAGS
        severity : str  comma-separated severity filter e.g. 'critical,high,medium'
        timeout : int   total scan timeout in seconds
        rate_limit : int  max requests per second
        concurrency : int  max parallel template runs
        """
        cmd = [
            self.binary,
            '-target', target_url,
            '-jsonl',                     # JSONL output (one JSON per line)
            '-silent',                    # no banner
            '-nc',                        # no ANSI color codes
            '-ni',                        # disable OOB/interactsh (v3 alias)
            '-rate-limit', str(rate_limit),
            '-c', str(concurrency),
            '-timeout', '10',             # per-request timeout
            '-retries', '1',
            '-etags', EXCLUDED_TAGS,      # exclude noisy tags
            '-duc',                       # disable update check
        ]

        # Tags / severity filter
        tag_str = tags or DEFAULT_TAGS
        cmd.extend(['-tags', tag_str])

        if severity:
            cmd.extend(['-severity', severity])
        else:
            cmd.extend(['-severity', 'critical,high,medium,low'])

        logger.info("Nuclei scan starting: %s [tags=%s]", target_url, tag_str)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Nuclei scan timed out after %ds for %s", timeout, target_url)
            return []
        except FileNotFoundError:
            logger.error("nuclei binary not found at %s", self.binary)
            raise RuntimeError(f"nuclei not found at {self.binary}. Install: bash install-recon-tools.sh")

        findings = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip non-JSON lines (progress / errors)

        logger.info("Nuclei found %d findings for %s", len(findings), target_url)
        return findings

    def findings_to_alerts(self, findings):
        """Convert nuclei JSONL findings to normalized alert dicts.

        Returns list of dicts compatible with _store_findings() in views.py.
        """
        from .owasp_mapping import map_to_owasp
        alerts = []

        for f in findings:
            info = f.get('info', {})
            classification = info.get('classification', {})

            severity_str = info.get('severity', 'info').lower()
            risk = _SEV_MAP.get(severity_str, 0)

            # CWE
            cwe_raw = classification.get('cwe-id', [])
            if isinstance(cwe_raw, str):
                cwe_raw = [cwe_raw]
            cwe_id = 0
            for cwe in cwe_raw:
                try:
                    cwe_id = int(str(cwe).replace('CWE-', '').strip())
                    break
                except (ValueError, TypeError):
                    continue

            # CVSS
            cvss_score = 0.0
            try:
                cvss_score = float(classification.get('cvss-score', 0) or 0)
            except (ValueError, TypeError):
                pass

            cvss_vector = classification.get('cvss-metrics', '') or ''

            # References
            refs = info.get('reference', []) or []
            if isinstance(refs, str):
                refs = [refs]
            reference = '\n'.join(refs)

            # Description & solution
            description = info.get('description', '') or ''
            solution = info.get('remediation', '') or ''

            # URLs: matched-at (specific path) or host (base)
            matched_at = f.get('matched-at', '') or ''
            host = f.get('host', '') or ''
            url = matched_at or host

            # Evidence: extracted values or matcher info
            evidence = ''
            extracted = f.get('extracted-results', [])
            if extracted:
                evidence = ' | '.join(str(e) for e in extracted[:5])
            if not evidence:
                evidence = matched_at[:300] if matched_at else ''

            name = info.get('name', '') or f.get('template-id', 'Nuclei Finding')
            template_id = f.get('template-id', '')

            owasp_category = map_to_owasp(cwe_id=cwe_id, tool='nuclei', tags=[])

            alerts.append({
                'name': name[:500],
                'risk': risk,
                'confidence': 2,           # medium confidence by default
                'url': url[:2000],
                'param': '',
                'attack': '',
                'evidence': evidence[:1000],
                'description': description[:4000],
                'solution': solution[:2000],
                'reference': reference[:2000],
                'cwe_id': cwe_id,
                'wasc_id': 0,
                'alert_ref': template_id[:50],
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector[:200],
                'tool': 'nuclei',
                'owasp_category': owasp_category,
            })

        return alerts
