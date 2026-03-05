"""WPScan client — WordPress vulnerability scanner.

Runs wpscan (Ruby gem) against a WordPress URL and returns findings
in the standard format used by _store_findings().

WPScan covers:
  - WordPress core version and known CVEs
  - Installed plugins + their vulnerabilities (needs API token for full DB)
  - Installed themes + vulnerabilities
  - User enumeration (login names)
  - Interesting files / exposed configs
  - Security misconfiguration checks

API token (free): https://wpscan.com/register
Set WP_SCAN_API_TOKEN in .env for vulnerability database lookups.
Without a token, basic enumeration still works but no vuln data.
"""
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)


def _find_wpscan_bin() -> str:
    """ค้นหา wpscan binary จากหลาย path ที่เป็นไปได้"""
    candidates = [
        '/usr/local/bin/wpscan',
        '/usr/bin/wpscan',
        '/usr/local/bundle/bin/wpscan',
    ]
    for path in candidates:
        if Path(path).is_file():
            return path
    # ค้นหาจาก PATH
    found = shutil.which('wpscan')
    if found:
        return found
    # Ruby gem bin directory (Ubuntu 24.04)
    import glob
    matches = glob.glob('/var/lib/gems/*/bin/wpscan')
    if matches:
        return matches[0]
    return 'wpscan'  # fallback — ให้ shell หาเอง


WPSCAN_BIN = _find_wpscan_bin()

# Severity mapping based on CVSS score from WPScan vuln data
def _score_to_severity(score):
    if score >= 9.0: return 4, 'Critical'
    if score >= 7.0: return 3, 'High'
    if score >= 4.0: return 2, 'Medium'
    if score >  0:   return 1, 'Low'
    return 1, 'Low'


def _wpscan_env():
    """environment สำหรับรัน wpscan ใต้ www-data"""
    import os
    env = os.environ.copy()
    # Ruby gem อาจต้องการ HOME สำหรับ cache
    if not env.get('HOME') or env.get('HOME') == '/':
        env['HOME'] = '/var/www'
    return env


def check_health():
    try:
        r = subprocess.run(
            [WPSCAN_BIN, '--version'],
            capture_output=True,
            timeout=30,
            env=_wpscan_env(),
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_version():
    import re
    _ver = re.compile(r'\d+\.\d+(?:\.\d+)*(?:-[a-z]\w*)?')
    try:
        r = subprocess.run(
            [WPSCAN_BIN, '--version'],
            capture_output=True, text=True,
            timeout=30,
            env=_wpscan_env(),
        )
        for line in r.stdout.splitlines():
            if 'version' in line.lower() or line.strip().startswith('WPScan'):
                m = _ver.search(line)
                if m:
                    return m.group(0)
        m = _ver.search(r.stdout)
        return m.group(0) if m else ''
    except Exception:
        return ''


def scan(target_url: str, scan_type: str = 'full', api_token: str = '') -> list[dict]:
    """Run wpscan and return normalized findings.

    scan_type:
      'quick' → enumerate interesting findings only (no plugin/theme enum)
      'full'  → plugins + themes + users + interesting files
      'deep'  → full + aggressive plugin detection (slower, more thorough)
    """
    api_token = api_token or getattr(settings, 'WPSCAN_API_TOKEN', '')

    # Build command
    cmd = [
        WPSCAN_BIN,
        '--url', target_url,
        '--format', 'json',
        '--random-user-agent',
        '--disable-tls-checks',
        '--no-banner',
    ]

    if api_token:
        cmd += ['--api-token', api_token]

    # Enumeration options by scan type
    if scan_type == 'quick':
        cmd += ['--enumerate', 'vp,vt,tt,cb,dbe']   # only vulnerable plugins/themes + interesting
    elif scan_type == 'deep':
        cmd += [
            '--enumerate', 'ap,at,tt,cb,dbe,u1-10',  # all plugins/themes + users
            '--plugins-detection', 'aggressive',
            '--themes-detection', 'aggressive',
        ]
    else:  # full (default)
        cmd += [
            '--enumerate', 'vp,at,tt,cb,dbe,u1-5',   # vulnerable plugins + all themes + users
            '--plugins-detection', 'mixed',
        ]

    timeout = {'quick': 120, 'full': 300, 'deep': 600}.get(scan_type, 300)

    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tf:
        out_file = tf.name

    try:
        cmd += ['--output', out_file]
        logger.info('wpscan: %s', ' '.join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        # WPScan exit code 5 = vuln found (still successful run)
        if proc.returncode not in (0, 5):
            logger.warning('wpscan exited %d: %s', proc.returncode, proc.stderr[:300])
            if proc.returncode == 1:
                # URL is not WordPress at all
                return [{
                    'name': 'WPScan: Not a WordPress site',
                    'url': target_url,
                    'risk': 0, 'severity': 'Info',
                    'description': f'WPScan could not detect WordPress at {target_url}. '
                                   f'The site may not be running WordPress or it may be hidden.',
                    'solution': '',
                    'evidence': proc.stderr[:500] if proc.stderr else '',
                    'cwe_id': 0,
                }]

        raw = Path(out_file).read_text(encoding='utf-8') if Path(out_file).exists() else ''
        if not raw:
            raw = proc.stdout

        if not raw.strip():
            return []

        data = json.loads(raw)

    except subprocess.TimeoutExpired:
        logger.warning('wpscan timed out after %d seconds', timeout)
        return []
    except json.JSONDecodeError as e:
        logger.warning('wpscan JSON parse error: %s', e)
        return []
    finally:
        Path(out_file).unlink(missing_ok=True)

    return _parse_results(data, target_url, bool(api_token))


# ── Parser ────────────────────────────────────────────────────────────────────

def _parse_results(data: dict, target_url: str, has_token: bool) -> list[dict]:
    findings = []

    # ── 1. WordPress version ─────────────────────────────────────────────────
    wp_info = data.get('version', {})
    if wp_info:
        ver = wp_info.get('number', 'unknown')
        vulns = wp_info.get('vulnerabilities', [])
        if vulns:
            for v in vulns:
                findings.extend(_vuln_to_finding(v, target_url, context=f'WordPress Core {ver}',
                                                  cwe_id=1104, owasp='A06'))
        else:
            findings.append({
                'name': f'WordPress Core Version: {ver}',
                'url': target_url,
                'risk': 0, 'severity': 'Info',
                'description': f'WordPress version {ver} detected.',
                'solution': 'Keep WordPress core up to date.',
                'evidence': f'WordPress {ver}',
                'cwe_id': 0,
                'owasp_category': 'A06',
            })

    # ── 2. Plugins ───────────────────────────────────────────────────────────
    for slug, plugin in data.get('plugins', {}).items():
        if not plugin:
            continue
        plugin_url = plugin.get('location', target_url)
        pver = plugin.get('version', {}).get('number', 'unknown')
        outdated = plugin.get('outdated', False)
        vulns = plugin.get('vulnerabilities', [])

        if vulns:
            for v in vulns:
                findings.extend(_vuln_to_finding(
                    v, plugin_url,
                    context=f'Plugin: {slug} v{pver}',
                    cwe_id=1104, owasp='A06',
                ))
        elif outdated:
            latest = plugin.get('latest_version', '?')
            findings.append({
                'name': f'Outdated Plugin: {slug} ({pver} → {latest})',
                'url': plugin_url,
                'risk': 1, 'severity': 'Low',
                'description': (
                    f'Plugin "{slug}" is outdated: installed {pver}, latest {latest}.\n'
                    f'Outdated plugins may contain known vulnerabilities.'
                ),
                'solution': f'Update {slug} to version {latest} or later.',
                'evidence': f'Installed: {pver} | Latest: {latest}',
                'cwe_id': 1104,
                'owasp_category': 'A06',
            })

    # ── 3. Themes ────────────────────────────────────────────────────────────
    for slug, theme in data.get('themes', {}).items():
        if not theme:
            continue
        theme_url = theme.get('location', target_url)
        tver = theme.get('version', {}).get('number', 'unknown')
        vulns = theme.get('vulnerabilities', [])
        if vulns:
            for v in vulns:
                findings.extend(_vuln_to_finding(
                    v, theme_url,
                    context=f'Theme: {slug} v{tver}',
                    cwe_id=1104, owasp='A06',
                ))

    # ── 4. Main theme ─────────────────────────────────────────────────────────
    main_theme = data.get('main_theme', {})
    if main_theme:
        slug = main_theme.get('slug', 'active-theme')
        tver = main_theme.get('version', {}).get('number', 'unknown')
        for v in main_theme.get('vulnerabilities', []):
            findings.extend(_vuln_to_finding(
                v, target_url,
                context=f'Active Theme: {slug} v{tver}',
                cwe_id=1104, owasp='A06',
            ))

    # ── 5. Interesting findings (exposed files, configs, etc.) ───────────────
    for item in data.get('interesting_findings', []):
        url  = item.get('url', target_url)
        desc = item.get('to_s', '') or item.get('type', 'Interesting finding')
        refs = item.get('references', {})
        ref_urls = refs.get('url', [])

        findings.append({
            'name': f'WP Exposure: {_short(desc)}',
            'url': url,
            'risk': 1, 'severity': 'Low',
            'description': desc,
            'solution': 'Remove or restrict access to exposed WordPress files and endpoints.',
            'evidence': url,
            'reference': '\n'.join(ref_urls[:3]),
            'cwe_id': 538,   # Information Exposure Through Directory Listing
            'owasp_category': 'A05',
        })

    # ── 6. Users enumerated ──────────────────────────────────────────────────
    users = data.get('users', {})
    if users:
        user_list = ', '.join(users.keys())
        findings.append({
            'name': 'WordPress User Enumeration',
            'url': target_url,
            'risk': 2, 'severity': 'Medium',
            'description': (
                f'WordPress user accounts enumerated via REST API or author archive:\n'
                f'Users found: {user_list}\n\n'
                f'An attacker can use these usernames in brute-force attacks against wp-login.php.'
            ),
            'solution': (
                'Disable user enumeration:\n'
                '• Block /wp-json/wp/v2/users/ endpoint\n'
                '• Disable author archive (?author=N)\n'
                '• Use a plugin such as "Stop User Enumeration"\n'
                '• Implement login rate limiting and 2FA'
            ),
            'evidence': f'Enumerated users: {user_list}',
            'cwe_id': 284,   # Improper Access Control
            'owasp_category': 'A01',
        })

    # ── 7. No API token note ─────────────────────────────────────────────────
    if not has_token:
        findings.append({
            'name': 'WPScan: No API Token — Vulnerability Data Limited',
            'url': target_url,
            'risk': 0, 'severity': 'Info',
            'description': (
                'WPScan ran without an API token. Plugin and theme vulnerability data is not '
                'available without a free API token from https://wpscan.com/register\n'
                'Set WP_SCAN_API_TOKEN in your .env file to enable full vulnerability scanning.'
            ),
            'solution': 'Register at https://wpscan.com/register and add WP_SCAN_API_TOKEN to .env',
            'evidence': '',
            'cwe_id': 0,
        })

    findings.sort(key=lambda x: -x['risk'])
    return findings


def _vuln_to_finding(vuln: dict, url: str, context: str,
                     cwe_id: int = 0, owasp: str = 'A06') -> list[dict]:
    title     = vuln.get('title', 'Unknown vulnerability')
    fixed_in  = vuln.get('fixed_in', '')
    refs      = vuln.get('references', {})
    cve_list  = refs.get('cve', [])
    ref_urls  = refs.get('url', [])
    wp_vuln   = refs.get('wpvulndb', [])
    cvss      = vuln.get('cvss', {}).get('score', 0.0) if vuln.get('cvss') else 0.0

    risk, severity = _score_to_severity(float(cvss)) if cvss else (2, 'Medium')
    cve_str   = ', '.join(f'CVE-{c}' for c in cve_list) if cve_list else ''
    ref_str   = '\n'.join(ref_urls[:5])
    nvd_urls  = '\n'.join(f'https://nvd.nist.gov/vuln/detail/CVE-{c}' for c in cve_list[:3])

    evidence_parts = []
    if fixed_in:
        evidence_parts.append(f'Fixed in: {fixed_in}')
    if cvss:
        evidence_parts.append(f'CVSS: {cvss}')
    if cve_str:
        evidence_parts.append(cve_str)

    return [{
        'name': f'{context} — {title[:200]}',
        'url': url,
        'risk': risk,
        'severity': severity,
        'description': (
            f'**{context}**\n\n{title}\n\n'
            + (f'Fixed in version: {fixed_in}\n' if fixed_in else '')
            + (f'CVE: {cve_str}\n' if cve_str else '')
        ),
        'solution': (
            f'Update {context.split(":")[0].strip()} to version {fixed_in} or later.'
            if fixed_in else
            f'Update {context.split(":")[0].strip()} to the latest version and review the vulnerability references.'
        ),
        'evidence': ' | '.join(evidence_parts) if evidence_parts else title[:200],
        'reference': (ref_str + '\n' + nvd_urls).strip(),
        'cwe_id': cwe_id,
        'owasp_category': owasp,
        'alert_ref': f'wpscan-wpvulndb-{wp_vuln[0]}' if wp_vuln else f'wpscan-{title[:40]}',
    }]


def _short(text: str, max_len: int = 80) -> str:
    text = text.strip()
    return text[:max_len] + '…' if len(text) > max_len else text
