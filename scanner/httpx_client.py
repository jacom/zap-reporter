"""httpx client — HTTP recon: security headers, fingerprinting, sensitive paths.

Uses the Python httpx library (no external binary required).
"""
import logging
import re

import httpx

logger = logging.getLogger(__name__)

# ── Security header checks ─────────────────────────────────────────────────
# (header_name, finding_name, description, owasp, risk)
SECURITY_HEADERS = [
    (
        'Content-Security-Policy',
        'Missing Content-Security-Policy Header',
        'The Content-Security-Policy (CSP) header is not set. CSP helps prevent '
        'Cross-Site Scripting (XSS) and data injection attacks by specifying which '
        'dynamic resources are allowed to load.',
        'A05', 2,
    ),
    (
        'Strict-Transport-Security',
        'Missing HTTP Strict Transport Security (HSTS)',
        'The Strict-Transport-Security header is not set. Without HSTS, browsers '
        'may access the site over plain HTTP, allowing SSL-stripping attacks.',
        'A02', 1,
    ),
    (
        'X-Frame-Options',
        'Missing X-Frame-Options Header',
        'X-Frame-Options is not set. The page may be rendered inside a malicious '
        'iframe, enabling Clickjacking attacks.',
        'A05', 1,
    ),
    (
        'X-Content-Type-Options',
        'Missing X-Content-Type-Options Header',
        'X-Content-Type-Options: nosniff is not set. Browsers may MIME-sniff '
        'responses away from the declared content-type.',
        'A05', 0,
    ),
    (
        'Referrer-Policy',
        'Missing Referrer-Policy Header',
        'Referrer-Policy is not set. Sensitive URL parameters may leak via the '
        'Referer header to third-party sites.',
        'A05', 0,
    ),
    (
        'Permissions-Policy',
        'Missing Permissions-Policy Header',
        'Permissions-Policy (formerly Feature-Policy) is not set. Browser features '
        'like camera and geolocation are not explicitly restricted.',
        'A05', 0,
    ),
]

# Sensitive paths to probe (path, finding_name, risk, owasp, description)
SENSITIVE_PATHS = [
    ('/.git/config',        'Exposed Git Repository (.git/config)',       4, 'A01',
     'The .git/config file is publicly accessible. Attackers can clone the entire '
     'source code repository, exposing credentials, keys, and business logic.'),
    ('/.git/HEAD',          'Exposed Git Repository (.git/HEAD)',          4, 'A01',
     'The .git/HEAD file is publicly accessible — indicates the Git repository '
     'directory is exposed to unauthenticated users.'),
    ('/.env',               'Exposed Environment File (.env)',             4, 'A02',
     'The .env file is publicly accessible. This file typically contains database '
     'credentials, API keys, and other secrets.'),
    ('/.env.local',         'Exposed Environment File (.env.local)',       4, 'A02',
     'The .env.local file is publicly accessible and may contain sensitive secrets.'),
    ('/.env.production',    'Exposed Environment File (.env.production)',  4, 'A02',
     'The .env.production file is publicly accessible and may contain production secrets.'),
    ('/config.php',         'Exposed PHP Config File',                     3, 'A02',
     'A PHP configuration file is publicly accessible and may expose database '
     'credentials or application secrets.'),
    ('/wp-config.php.bak',  'Exposed WordPress Config Backup',             4, 'A02',
     'A WordPress config backup file is publicly accessible, exposing DB credentials.'),
    ('/config.yaml',        'Exposed YAML Config File',                    3, 'A02',
     'A YAML configuration file is publicly accessible and may expose credentials.'),
    ('/config.json',        'Exposed JSON Config File',                    3, 'A02',
     'A JSON configuration file is publicly accessible and may expose secrets.'),
    ('/database.yml',       'Exposed Database Config File',                3, 'A02',
     'A database configuration file is publicly accessible, exposing DB credentials.'),
    ('/phpinfo.php',        'PHP Info Page Exposed',                       2, 'A05',
     'phpinfo() output is publicly accessible, exposing PHP version, server '
     'configuration, loaded modules, and internal paths.'),
    ('/server-status',      'Apache Server Status Exposed',                2, 'A05',
     'Apache mod_status is enabled and publicly accessible, exposing server '
     'internals, active requests, and IP addresses.'),
    ('/server-info',        'Apache Server Info Exposed',                  2, 'A05',
     'Apache mod_info is enabled and publicly accessible.'),
    ('/nginx_status',       'Nginx Status Exposed',                        1, 'A05',
     'Nginx stub_status is publicly accessible, exposing connection statistics.'),
    ('/admin',              'Admin Panel Detected',                        1, 'A07',
     'An admin panel was detected at /admin. Exposed admin interfaces should '
     'be restricted to trusted IPs only.'),
    ('/admin/',             'Admin Panel Detected',                        1, 'A07',
     'An admin panel was detected at /admin/. Exposed admin interfaces should '
     'be restricted to trusted IPs only.'),
    ('/administrator',      'Admin Panel Detected',                        1, 'A07',
     'An admin panel was detected at /administrator.'),
    ('/wp-admin/',          'WordPress Admin Panel',                       1, 'A07',
     'WordPress admin panel is accessible at /wp-admin/.'),
    ('/wp-login.php',       'WordPress Login Page Exposed',                1, 'A07',
     'WordPress login page is publicly accessible. Brute-force attacks are possible.'),
    ('/phpmyadmin/',        'phpMyAdmin Exposed',                          2, 'A07',
     'phpMyAdmin database management interface is publicly accessible. '
     'Ensure it is protected with strong authentication.'),
    ('/pma/',               'phpMyAdmin Exposed (/pma/)',                  2, 'A07',
     'phpMyAdmin (at /pma/) is publicly accessible.'),
    ('/swagger/',           'Swagger UI API Documentation Exposed',        1, 'A05',
     'Swagger/OpenAPI documentation is publicly accessible and exposes all '
     'API endpoints, parameters, and authentication methods.'),
    ('/swagger-ui.html',    'Swagger UI Exposed',                          1, 'A05',
     'Swagger UI is publicly accessible, exposing all API endpoint details.'),
    ('/api/swagger.json',   'Swagger JSON Spec Exposed',                   1, 'A05',
     'The Swagger/OpenAPI JSON specification is publicly accessible.'),
    ('/api/docs',           'API Documentation Exposed',                   1, 'A05',
     'API documentation is publicly accessible and may expose endpoint details.'),
    ('/actuator',           'Spring Boot Actuator Exposed',                2, 'A05',
     'Spring Boot Actuator endpoints are publicly accessible, potentially '
     'exposing health data, environment variables, and management endpoints.'),
    ('/actuator/env',       'Spring Actuator /env Exposed',                3, 'A05',
     'Spring Boot /actuator/env endpoint is accessible and may expose environment '
     'variables including credentials and API keys.'),
    ('/actuator/dump',      'Spring Actuator /dump Exposed',               2, 'A05',
     'Spring Boot /actuator/dump exposes thread dump information.'),
    ('/metrics',            'Metrics Endpoint Exposed',                    1, 'A05',
     'A metrics endpoint is publicly accessible, exposing application statistics.'),
    ('/console',            'Admin Console Detected',                      2, 'A07',
     'An admin/management console was detected at /console.'),
    ('/.DS_Store',          'macOS .DS_Store File Exposed',                2, 'A01',
     '.DS_Store file is publicly accessible. Attackers can enumerate directory '
     'structure from this file.'),
    ('/backup',             'Backup Directory Detected',                   2, 'A01',
     'A backup directory is accessible. May contain source code or sensitive data.'),
    ('/backup.zip',         'Backup Archive Exposed',                      3, 'A01',
     'A backup archive (backup.zip) is publicly accessible.'),
    ('/dump.sql',           'SQL Dump Exposed',                            4, 'A01',
     'A SQL database dump is publicly accessible.'),
    ('/robots.txt',         'robots.txt Found',                            0, 'A05',
     'robots.txt is present. Review for disallowed paths that may reveal '
     'sensitive directories.'),
    ('/crossdomain.xml',    'crossdomain.xml Found',                       0, 'A05',
     'crossdomain.xml is present. Review for overly permissive cross-domain policy.'),
    ('/sitemap.xml',        'sitemap.xml Found',                           0, 'A05',
     'sitemap.xml is accessible and enumerates application URLs.'),
]

# Server header version-disclosure patterns
VERSION_PATTERN = re.compile(
    r'(Apache|nginx|IIS|lighttpd|Tomcat|Jetty|gunicorn|Werkzeug|Express|'
    r'PHP|OpenSSL|Python|Ruby|Node\.js|Django|Flask|Laravel|Spring)/'
    r'([0-9]+\.[0-9]+[\w.]*)',
    re.IGNORECASE,
)

# HTTP methods that should not be allowed on a normal web server
DANGEROUS_METHODS = {'TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT'}


class HttpxClient:
    """HTTP security probe using the Python httpx library."""

    DEFAULT_TIMEOUT = 15.0
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
    }

    def check_health(self):
        """Always True — uses Python httpx library, no external binary."""
        try:
            import httpx  # noqa: F401
            return True
        except ImportError:
            return False

    def get_version(self):
        """Return Python httpx library version."""
        return f'httpx library {httpx.__version__} (Python)'

    def scan(self, target_url, scan_type='full'):
        """Probe target URL for HTTP security issues.

        scan_type:
          'headers' → security headers + server fingerprint only
          'full'    → headers + sensitive path discovery + HTTP methods check

        Returns normalized finding dicts compatible with _store_findings().
        """
        findings = []

        # Normalise URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = f'https://{target_url}'

        try:
            with httpx.Client(
                timeout=self.DEFAULT_TIMEOUT,
                headers=self.DEFAULT_HEADERS,
                follow_redirects=True,
                verify=False,  # VA tool — trust issues are findings themselves
            ) as client:
                try:
                    response = client.get(target_url)
                except httpx.RequestError as exc:
                    # Try HTTP if HTTPS fails
                    if target_url.startswith('https://'):
                        try:
                            target_url = target_url.replace('https://', 'http://', 1)
                            response = client.get(target_url)
                        except httpx.RequestError:
                            logger.error(f'httpx: cannot reach {target_url}: {exc}')
                            return []
                    else:
                        logger.error(f'httpx: cannot reach {target_url}: {exc}')
                        return []

                final_url = str(response.url)
                headers   = response.headers

                # 1. Security headers
                findings.extend(self._check_security_headers(final_url, headers))

                # 2. Server version disclosure
                findings.extend(self._check_server_fingerprint(final_url, headers))

                # 3. Sensitive cookie flags
                findings.extend(self._check_cookie_flags(final_url, headers))

                if scan_type == 'full':
                    # 4. Sensitive path probe
                    findings.extend(self._probe_sensitive_paths(final_url, client))

                    # 5. HTTP methods check (OPTIONS)
                    findings.extend(self._check_http_methods(final_url, client))

        except Exception as exc:
            logger.exception(f'httpx scan failed for {target_url}: {exc}')

        return findings

    # ── Header checks ─────────────────────────────────────────────────────

    def _check_security_headers(self, url, headers):
        """Return findings for missing security headers."""
        findings = []
        hdr_lower = {k.lower(): v for k, v in headers.items()}

        for hdr_name, finding_name, description, owasp, risk in SECURITY_HEADERS:
            if hdr_name.lower() not in hdr_lower:
                findings.append({
                    'name': finding_name,
                    'risk': risk,
                    'description': description,
                    'solution': (
                        f'Add the {hdr_name} response header to all server responses. '
                        'Configure it in your web server or application framework.'
                    ),
                    'reference': (
                        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/'
                        f'{hdr_name.replace(" ", "_")}'
                    ),
                    'url': url,
                    'cwe_id': 693 if 'CSP' in hdr_name else 0,
                    'cvss_score': 0.0,
                    'cvss_vector': '',
                    'alert_ref': f'httpx-missing-{hdr_name.lower().replace("-", "_")}',
                    'evidence': f'Header "{hdr_name}" not present in response',
                    'tool': 'httpx',
                    'owasp_category': owasp,
                })
            else:
                # Check for weak CSP values
                if hdr_name == 'Content-Security-Policy':
                    csp_val = hdr_lower[hdr_name.lower()]
                    if "unsafe-inline" in csp_val or "unsafe-eval" in csp_val:
                        findings.append({
                            'name': 'Weak Content-Security-Policy (unsafe-inline/eval)',
                            'risk': 1,
                            'description': (
                                f'Content-Security-Policy is set but contains unsafe directives: '
                                f'"{csp_val[:300]}"\n\n'
                                "'unsafe-inline' allows inline scripts/styles. "
                                "'unsafe-eval' allows eval(). Both undermine XSS protection."
                            ),
                            'solution': 'Remove unsafe-inline and unsafe-eval from CSP directives.',
                            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
                            'url': url,
                            'cwe_id': 693,
                            'cvss_score': 0.0,
                            'cvss_vector': '',
                            'alert_ref': 'httpx-weak-csp',
                            'evidence': f'CSP: {csp_val[:200]}',
                            'tool': 'httpx',
                            'owasp_category': 'A05',
                        })

        return findings

    def _check_server_fingerprint(self, url, headers):
        """Detect server/technology version disclosure in response headers."""
        findings = []
        disclosure_headers = [
            ('server', 'Server'),
            ('x-powered-by', 'X-Powered-By'),
            ('x-aspnet-version', 'X-AspNet-Version'),
            ('x-aspnetmvc-version', 'X-AspNetMvc-Version'),
            ('x-generator', 'X-Generator'),
            ('x-drupal-cache', 'X-Drupal-Cache'),
        ]
        hdr_lower = {k.lower(): v for k, v in headers.items()}

        for hdr_key, hdr_display in disclosure_headers:
            val = hdr_lower.get(hdr_key, '')
            if not val:
                continue

            match = VERSION_PATTERN.search(val)
            if match:
                software = match.group(1)
                version  = match.group(2)
                findings.append({
                    'name': f'Server Version Disclosure via {hdr_display} Header',
                    'risk': 1,
                    'description': (
                        f'The {hdr_display} response header reveals the server software '
                        f'and version: "{val}"\n\n'
                        f'Exposing {software}/{version} allows attackers to look up '
                        'known CVEs for that specific version.'
                    ),
                    'solution': (
                        f'Remove or obscure the {hdr_display} header in server configuration. '
                        f'Do not reveal version numbers.'
                    ),
                    'reference': 'https://owasp.org/www-project-web-security-testing-guide/',
                    'url': url,
                    'cwe_id': 200,
                    'cvss_score': 0.0,
                    'cvss_vector': '',
                    'alert_ref': f'httpx-version-disclosure-{hdr_key}',
                    'evidence': f'{hdr_display}: {val}',
                    'tool': 'httpx',
                    'owasp_category': 'A05',
                })
            elif val and hdr_key in ('x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'):
                # Even without version, disclosing the technology is a risk
                findings.append({
                    'name': f'Technology Disclosure via {hdr_display} Header',
                    'risk': 0,
                    'description': (
                        f'The {hdr_display} header reveals the underlying technology: "{val}"'
                    ),
                    'solution': f'Remove the {hdr_display} header.',
                    'reference': '',
                    'url': url,
                    'cwe_id': 200,
                    'cvss_score': 0.0,
                    'cvss_vector': '',
                    'alert_ref': f'httpx-tech-disclosure-{hdr_key}',
                    'evidence': f'{hdr_display}: {val}',
                    'tool': 'httpx',
                    'owasp_category': 'A05',
                })

        return findings

    def _check_cookie_flags(self, url, headers):
        """Check for missing Secure/HttpOnly/SameSite flags on cookies."""
        findings = []
        set_cookies = headers.get_list('set-cookie') if hasattr(headers, 'get_list') \
                      else [v for k, v in headers.items() if k.lower() == 'set-cookie']

        for cookie in set_cookies:
            cookie_name = cookie.split('=')[0].strip()
            issues = []
            cookie_lower = cookie.lower()

            if 'secure' not in cookie_lower and url.startswith('https://'):
                issues.append('Secure flag missing')
            if 'httponly' not in cookie_lower:
                issues.append('HttpOnly flag missing')
            if 'samesite' not in cookie_lower:
                issues.append('SameSite flag missing')

            if issues:
                findings.append({
                    'name': f'Cookie Without Security Flags: {cookie_name}',
                    'risk': 1,
                    'description': (
                        f'The cookie "{cookie_name}" is missing security flags: '
                        f'{", ".join(issues)}.\n\n'
                        'Missing HttpOnly allows JavaScript access (XSS theft). '
                        'Missing Secure allows transmission over HTTP. '
                        'Missing SameSite enables CSRF attacks.'
                    ),
                    'solution': (
                        f'Set the cookie with: Secure; HttpOnly; SameSite=Strict '
                        f'(or Lax for cross-site use).'
                    ),
                    'reference': 'https://owasp.org/www-community/controls/SecureCookieAttribute',
                    'url': url,
                    'cwe_id': 614,
                    'cvss_score': 0.0,
                    'cvss_vector': '',
                    'alert_ref': 'httpx-cookie-flags',
                    'evidence': cookie[:300],
                    'tool': 'httpx',
                    'owasp_category': 'A07',
                })

        return findings

    # ── Path probing ───────────────────────────────────────────────────────

    def _probe_sensitive_paths(self, base_url, client):
        """Probe known sensitive paths and return findings for accessible ones."""
        findings = []

        # Strip trailing slash and path from base URL
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(base_url)
        base = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))

        seen_paths = set()

        for path, finding_name, risk, owasp, description in SENSITIVE_PATHS:
            if path in seen_paths:
                continue
            seen_paths.add(path)

            full_url = base + path
            try:
                resp = client.get(full_url)

                # Consider 200, 206 as found; 401/403 as "exists but protected"
                if resp.status_code in (200, 206):
                    body_snippet = resp.text[:500] if resp.text else ''
                    findings.append({
                        'name': finding_name,
                        'risk': risk,
                        'description': description,
                        'solution': (
                            'Restrict access to this resource using web server configuration, '
                            'or remove it from the web root entirely.'
                        ),
                        'reference': '',
                        'url': full_url,
                        'cwe_id': 538 if risk >= 3 else 200,
                        'cvss_score': 0.0,
                        'cvss_vector': '',
                        'alert_ref': f'httpx-sensitive-{path.strip("/").replace("/", "-") or "root"}',
                        'evidence': (
                            f'HTTP {resp.status_code} — Content-Length: '
                            f'{resp.headers.get("content-length", "?")} bytes\n'
                            f'Preview: {body_snippet[:200]}'
                        ),
                        'tool': 'httpx',
                        'owasp_category': owasp,
                    })
                elif resp.status_code in (401, 403):
                    # Resource exists but is protected — Info finding
                    if risk >= 2:
                        findings.append({
                            'name': f'{finding_name} (Protected — HTTP {resp.status_code})',
                            'risk': 0,
                            'description': (
                                f'{description}\n\nThe resource returned HTTP {resp.status_code}, '
                                'indicating it exists but access is restricted. '
                                'Verify that authentication cannot be bypassed.'
                            ),
                            'solution': 'Confirm access controls are correctly enforced.',
                            'reference': '',
                            'url': full_url,
                            'cwe_id': 0,
                            'cvss_score': 0.0,
                            'cvss_vector': '',
                            'alert_ref': f'httpx-protected-{path.strip("/").replace("/", "-") or "root"}',
                            'evidence': f'HTTP {resp.status_code}',
                            'tool': 'httpx',
                            'owasp_category': owasp,
                        })

            except httpx.RequestError:
                continue  # Path not reachable — skip silently

        return findings

    def _check_http_methods(self, url, client):
        """Check if dangerous HTTP methods are enabled via OPTIONS."""
        findings = []
        try:
            resp = client.options(url)
            allow_header = resp.headers.get('allow', '') or resp.headers.get('Allow', '')
            if not allow_header:
                return []

            allowed_methods = {m.strip().upper() for m in allow_header.split(',')}
            dangerous_found = allowed_methods & DANGEROUS_METHODS

            if 'TRACE' in dangerous_found or 'TRACK' in dangerous_found:
                findings.append({
                    'name': 'HTTP TRACE / TRACK Method Enabled',
                    'risk': 2,
                    'description': (
                        'The server supports the HTTP TRACE or TRACK method. '
                        'This can enable Cross-Site Tracing (XST) attacks which '
                        'allow theft of cookies and credentials by sending crafted '
                        'cross-site requests.'
                    ),
                    'solution': 'Disable the TRACE and TRACK methods in the web server configuration.',
                    'reference': 'https://owasp.org/www-community/attacks/Cross_Site_Tracing',
                    'url': url,
                    'cwe_id': 16,
                    'cvss_score': 0.0,
                    'cvss_vector': '',
                    'alert_ref': 'httpx-http-trace',
                    'evidence': f'Allow: {allow_header}',
                    'tool': 'httpx',
                    'owasp_category': 'A05',
                })

            unsafe_rw = dangerous_found - {'TRACE', 'TRACK'}
            if unsafe_rw:
                findings.append({
                    'name': f'Potentially Dangerous HTTP Methods Enabled: {", ".join(unsafe_rw)}',
                    'risk': 1,
                    'description': (
                        f'The server advertises support for HTTP methods: '
                        f'{", ".join(unsafe_rw)}. '
                        'Methods like PUT and DELETE can allow unauthorised file '
                        'modification or deletion if not properly secured.'
                    ),
                    'solution': (
                        'Disable unused HTTP methods in the web server/application configuration. '
                        'Only allow GET, POST, HEAD (and others required by the application).'
                    ),
                    'reference': '',
                    'url': url,
                    'cwe_id': 16,
                    'cvss_score': 0.0,
                    'cvss_vector': '',
                    'alert_ref': 'httpx-dangerous-methods',
                    'evidence': f'Allow: {allow_header}',
                    'tool': 'httpx',
                    'owasp_category': 'A05',
                })

        except httpx.RequestError:
            pass

        return findings
