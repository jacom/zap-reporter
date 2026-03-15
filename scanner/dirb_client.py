"""Directory Brute-Force scanner using ffuf.

Discovers hidden directories and files by requesting each entry from a
wordlist and recording non-404 responses.  Results are returned as
standard finding dicts compatible with _store_findings().
"""
import json
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Wordlist candidates (first existing file wins) ───────────────────────────
_WORDLIST_CANDIDATES = [
    '/opt/SecLists/Discovery/Web-Content/common.txt',
    '/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt',
    '/usr/share/dirb/wordlists/common.txt',
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt',
    '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
]

# HTTP status codes to report (everything that is not 404 / connection error)
_MATCH_CODES = '200,204,301,302,307,401,403,405'


def _find_wordlist():
    for p in _WORDLIST_CANDIDATES:
        if Path(p).is_file():
            return p
    return None


def check_health():
    """Return True if ffuf is installed and a wordlist is available."""
    try:
        subprocess.run(['ffuf', '-V'], capture_output=True, timeout=5)
        return _find_wordlist() is not None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_version():
    import re
    _ver = re.compile(r'\d+\.\d+(?:\.\d+)*(?:-[a-z]\w*)?')
    try:
        r = subprocess.run(['ffuf', '-V'], capture_output=True, text=True, timeout=5)
        out = (r.stdout + r.stderr).strip()
        for line in out.splitlines():
            if 'version' in line.lower():
                m = _ver.search(line)
                return m.group(0) if m else line.strip()
        m = _ver.search(out)
        return m.group(0) if m else out.split('\n')[0]
    except Exception:
        return ''


# ── Risk / severity helpers ───────────────────────────────────────────────────

def _status_to_risk(status: int):
    """Map HTTP status to (risk_int, severity_str)."""
    if status == 403:
        return 2, 'Medium'    # Forbidden → restricted resource exists
    if status in (401, 405):
        return 2, 'Medium'    # Unauthorized / method not allowed
    if status in (200, 204):
        return 1, 'Low'       # Found
    if status in (301, 302, 307):
        return 0, 'Info'      # Redirect
    return 0, 'Info'


def _name_from_path(path: str) -> str:
    """Turn '/admin/config.php' into 'config.php' (or 'admin' for dirs)."""
    return path.rstrip('/').split('/')[-1] or path


# ── Main scan function ────────────────────────────────────────────────────────

def run_scan(target_url: str,
             wordlist: str | None = None,
             extensions: list[str] | None = None,
             threads: int = 40,
             timeout: int = 300) -> list[dict]:
    """Run ffuf against *target_url* and return findings.

    Args:
        target_url: Base URL, e.g. 'https://example.com'
        wordlist:   Path to wordlist file (auto-detected if None)
        extensions: Extra file extensions to probe, e.g. ['php','html']
        threads:    Concurrent requests (default 40)
        timeout:    Total wall-clock timeout in seconds

    Returns:
        List of finding dicts ready for _store_findings().
    """
    wordlist = wordlist or _find_wordlist()
    if not wordlist:
        raise RuntimeError('No wordlist found. Install dirb: apt install dirb')

    base = target_url.rstrip('/')
    fuzz_url = f'{base}/FUZZ'

    cmd = [
        'ffuf',
        '-u', fuzz_url,
        '-w', wordlist,
        '-mc', _MATCH_CODES,
        '-t', str(threads),
        '-timeout', '10',   # per-request timeout (seconds)
        '-r',               # follow redirects
        '-of', 'json',
        '-o', '/dev/stdout',
        '-s',               # silent (no progress bar)
    ]
    if extensions:
        cmd += ['-e', ',' .join(f'.{e}' for e in extensions)]

    logger.info('ffuf: %s', ' '.join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logger.warning('ffuf timed out after %s seconds', timeout)
        return []
    except FileNotFoundError:
        raise RuntimeError('ffuf not found. Install with: apt install ffuf')

    raw = proc.stdout.strip()
    if not raw:
        logger.info('ffuf: no results found')
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning('ffuf: could not parse JSON output: %s', raw[:200])
        return []

    findings = []
    seen_urls = set()

    for r in data.get('results', []):
        url     = r.get('url', '')
        status  = r.get('status', 0)
        words   = r.get('words', 0)
        length  = r.get('length', 0)
        path    = r.get('input', {}).get('FUZZ', '')

        if url in seen_urls:
            continue
        seen_urls.add(url)

        risk, severity = _status_to_risk(status)
        short_name = _name_from_path(path) if path else url.split('/')[-1]

        if status == 403:
            name = f'Restricted Resource: /{path}'
            desc = (
                f'HTTP 403 Forbidden — the resource exists but access is denied.\n'
                f'URL: {url}\n'
                f'This may indicate a sensitive directory or file that is protected '
                f'but publicly known to exist.'
            )
            solution = (
                'Verify that restricted paths do not expose sensitive information '
                'via error messages or directory listings.  Consider returning 404 '
                'for truly hidden paths to avoid information disclosure.'
            )
        elif status in (401, 405):
            name = f'Protected Resource: /{path}'
            desc = (
                f'HTTP {status} — authentication or method restriction in place.\n'
                f'URL: {url}'
            )
            solution = 'Ensure authentication is properly enforced and only necessary HTTP methods are allowed.'
        elif status in (301, 302, 307):
            name = f'Redirect Discovered: /{path}'
            desc = f'HTTP {status} redirect found at {url}'
            solution = 'Review redirect targets and ensure they do not expose internal paths.'
        else:
            name = f'Directory/File Found: /{path}'
            desc = (
                f'HTTP {status} — publicly accessible resource discovered.\n'
                f'URL: {url}\nResponse size: {length} bytes | Words: {words}'
            )
            solution = (
                'Review whether this resource should be publicly accessible. '
                'Remove backup files, test pages, and admin interfaces from '
                'production servers.'
            )

        findings.append({
            'name':           name,
            'url':            url,
            'risk':           risk,
            'severity':       severity,
            'description':    desc,
            'solution':       solution,
            'evidence':       f'HTTP {status} | Length: {length} | Words: {words}',
            'cwe_id':         538,   # CWE-538: File and Directory Information Exposure
            'wasc_id':        34,    # WASC-34: Predictable Resource Location
            'owasp_category': 'A05', # A05:2021 Security Misconfiguration
            'alert_ref':      f'dirb-{status}',
        })

    findings.sort(key=lambda x: -x['risk'])
    logger.info('ffuf: found %d resources at %s', len(findings), base)
    return findings
