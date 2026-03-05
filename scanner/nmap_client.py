"""Nmap scanner client — Network discovery and port scanning (A05/A06)."""
import logging
import re
import subprocess
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

# Ports that indicate potential misconfigurations — marked as Low (1)
HIGH_RISK_PORTS = {
    21, 23, 111, 135, 139, 161, 445, 512, 513, 514,
    2181, 3389, 5900, 5901, 6379, 8888, 9200, 11211, 27017,
}

# Well-known port → OWASP 2025 category
OWASP_PORT_MAP = {
    21: 'A05',    # FTP — often plaintext
    22: 'A05',    # SSH
    23: 'A05',    # Telnet — plaintext protocol
    25: 'A05',    # SMTP
    53: 'A05',    # DNS
    80: 'A05',    # HTTP
    110: 'A05',   # POP3
    111: 'A05',   # RPC
    135: 'A05',   # DCOM/RPC
    139: 'A05',   # NetBIOS
    143: 'A05',   # IMAP
    161: 'A05',   # SNMP
    443: 'A02',   # HTTPS
    445: 'A05',   # SMB
    512: 'A05',   # rexec
    513: 'A05',   # rlogin
    514: 'A05',   # rsh
    1433: 'A05',  # MSSQL
    1521: 'A05',  # Oracle
    2181: 'A05',  # Zookeeper
    3306: 'A05',  # MySQL
    3389: 'A05',  # RDP
    5432: 'A05',  # PostgreSQL
    5900: 'A05',  # VNC
    6379: 'A05',  # Redis
    7001: 'A05',  # WebLogic
    8080: 'A05',  # HTTP-alt
    8443: 'A02',  # HTTPS-alt
    8888: 'A05',  # Jupyter / misc
    9200: 'A05',  # Elasticsearch
    11211: 'A05', # Memcached
    27017: 'A05', # MongoDB
}

# NSE script → (risk_min, owasp_category) based on script name prefix/keyword
_SCRIPT_RISK_TABLE = [
    (['vuln', 'cve-', 'ms', 'backdoor', 'exploit', 'rce'],    3, 'A06'),
    (['weak', 'default', 'brute', 'auth', 'anonymous'],         2, 'A07'),
    (['ssl', 'tls', 'cipher', 'cert', 'heartbleed', 'poodle'], 2, 'A02'),
    (['smb-security', 'smb-vuln'],                              3, 'A05'),
    (['http-title', 'http-server-header', 'banner', 'info'],    0, 'A05'),
]


class NmapClient:
    """Client for running nmap scans and parsing XML output."""

    NMAP_BIN = 'nmap'

    # Predefined argument sets per scan type
    SCAN_ARGS = {
        'quick': ['-sT', '-sV', '-T4', '--open', '-F'],
        'full':  ['-sT', '-sV', '-sC', '-T4', '--open'],
        'vuln':  ['-sT', '-sV', '--script', 'vuln', '-T4', '--open'],
    }

    def check_health(self):
        """Return True if nmap binary is available."""
        try:
            result = subprocess.run(
                [self.NMAP_BIN, '--version'],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_version(self):
        """Return nmap version string."""
        try:
            result = subprocess.run(
                [self.NMAP_BIN, '--version'],
                capture_output=True, text=True, timeout=5,
            )
            first_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ''
            return first_line or f'exit {result.returncode}'
        except Exception as e:
            return f'error: {e}'

    def scan(self, target, scan_type='quick'):
        """Run nmap against target and return normalized finding dicts.

        Args:
            target:    IP address, hostname, or CIDR range (e.g. 10.0.0.0/24)
            scan_type: 'quick' | 'full' | 'vuln'

        Returns:
            list of normalized finding dicts compatible with _store_findings()
        """
        args = self.SCAN_ARGS.get(scan_type, self.SCAN_ARGS['quick'])
        cmd = [self.NMAP_BIN] + args + ['-oX', '-', target]
        timeout = 600 if scan_type in ('full', 'vuln') else 300

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=timeout,
            )
            # nmap exits 0 (success) or 1 (partial — still valid output)
            if result.returncode not in (0, 1):
                logger.warning(
                    f'nmap exited with code {result.returncode}: '
                    f'{result.stderr[:300]}'
                )
            if not result.stdout.strip():
                logger.error('nmap produced no output')
                return []
            return self.parse_xml(result.stdout)
        except subprocess.TimeoutExpired:
            logger.error(f'nmap scan timed out after {timeout}s on {target}')
            return []
        except Exception as e:
            logger.exception(f'nmap scan failed: {e}')
            return []

    def parse_xml(self, xml_content):
        """Parse nmap XML output into normalized finding dicts.

        Extracts:
          - One finding per open TCP/UDP port (Info or Low risk)
          - Additional findings from NSE script output (Medium/High for vuln scripts)
        """
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            logger.error(f'nmap XML parse error: {exc}')
            return []

        findings = []

        for host in root.findall('host'):
            status_el = host.find('status')
            if status_el is None or status_el.get('state') != 'up':
                continue

            # Resolve host label (prefer PTR/hostname over raw IP)
            ip = ''
            for addr_el in host.findall('address'):
                if addr_el.get('addrtype') in ('ipv4', 'ipv6'):
                    ip = addr_el.get('addr', '')
                    break

            hostname = ''
            for hn in host.findall('.//hostname'):
                if hn.get('type') in ('PTR', 'user'):
                    hostname = hn.get('name', '')
                    break

            host_label = hostname or ip

            ports_el = host.find('ports')
            if ports_el is None:
                continue

            for port_el in ports_el.findall('port'):
                state_el = port_el.find('state')
                if state_el is None or state_el.get('state') != 'open':
                    continue

                portid   = int(port_el.get('portid', 0))
                protocol = port_el.get('protocol', 'tcp')

                # Service info
                svc_el      = port_el.find('service')
                svc_name    = ''
                svc_product = ''
                svc_version = ''
                svc_extra   = ''
                cpe_list    = []

                if svc_el is not None:
                    svc_name    = svc_el.get('name', '')
                    svc_product = svc_el.get('product', '')
                    svc_version = svc_el.get('version', '')
                    svc_extra   = svc_el.get('extrainfo', '')
                    cpe_list    = [el.text for el in svc_el.findall('cpe') if el.text]

                svc_desc = svc_product
                if svc_version:
                    svc_desc += f' {svc_version}'
                if svc_extra:
                    svc_desc += f' ({svc_extra})'
                svc_desc = svc_desc.strip()

                # Risk: high-risk ports = Low(1), others = Info(0)
                risk      = 1 if portid in HIGH_RISK_PORTS else 0
                owasp_cat = OWASP_PORT_MAP.get(portid, 'A05')

                name = f'{svc_name.upper()} on {portid}/{protocol}' if svc_name \
                       else f'Open Port {portid}/{protocol}'

                evidence_parts = [f'{host_label}:{portid}/{protocol}']
                if svc_desc:
                    evidence_parts.append(f'Service: {svc_desc}')
                if cpe_list:
                    evidence_parts.append(f'CPE: {", ".join(cpe_list[:3])}')

                findings.append({
                    'name': name[:500],
                    'risk': risk,
                    'description': (
                        f'Nmap discovered open port {portid}/{protocol} on {host_label}.\n'
                        f'Service: {svc_desc or svc_name or "unknown"}\n'
                        f'CPE: {", ".join(cpe_list) if cpe_list else "N/A"}'
                    ),
                    'solution': '',
                    'reference': '',
                    'url': f'{host_label}:{portid}',
                    'cwe_id': 0,
                    'cvss_score': 0.0,
                    'cvss_vector': '',
                    'alert_ref': f'nmap-port-{portid}'[:50],
                    'evidence': ' | '.join(evidence_parts),
                    'tool': 'nmap',
                    'owasp_category': owasp_cat,
                })

                # NSE scripts attached to this port
                for script_el in port_el.findall('script'):
                    findings.extend(
                        self._parse_script(script_el, host_label, portid, protocol)
                    )

            # Host-level scripts (smb-security-mode, os-detection, etc.)
            hostscript_el = host.find('hostscript')
            if hostscript_el is not None:
                for script_el in hostscript_el.findall('script'):
                    findings.extend(
                        self._parse_script(script_el, host_label, 0, '')
                    )

        return findings

    def _parse_script(self, script_el, host_label, portid, protocol):
        """Parse a single NSE <script> element into 0 or more findings."""
        script_id = script_el.get('id', '')
        output    = script_el.get('output', '').strip()

        # Skip non-informative outputs
        if not output or output.lower() in ('n/a', 'not vulnerable', 'no results', ''):
            return []

        script_lower = script_id.lower()

        # Determine risk + OWASP from script name
        risk      = 0
        owasp_cat = 'A05'
        for keywords, risk_val, owasp_val in _SCRIPT_RISK_TABLE:
            if any(k in script_lower for k in keywords):
                risk      = risk_val
                owasp_cat = owasp_val
                break

        # Try to extract CVE and CVSS from script output
        cve_id     = ''
        cvss_score = 0.0

        cve_match = re.search(r'CVE-(\d{4}-\d+)', output, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()

        cvss_match = re.search(r'cvss[:\s]+([0-9]+\.[0-9]+)', output, re.IGNORECASE)
        if cvss_match:
            try:
                cvss_score = float(cvss_match.group(1))
                # Upgrade risk floor based on CVSS score
                if cvss_score >= 9.0 and risk < 4:
                    risk = 4
                elif cvss_score >= 7.0 and risk < 3:
                    risk = 3
                elif cvss_score >= 4.0 and risk < 2:
                    risk = 2
                elif cvss_score > 0.0 and risk < 1:
                    risk = 1
            except ValueError:
                pass

        location = f'{host_label}:{portid}' if portid else host_label
        name = f'{cve_id} via {script_id}' if cve_id else script_id

        return [{
            'name': name[:500],
            'risk': risk,
            'description': (
                f'NSE Script: {script_id}\n'
                f'Target: {location}\n\n'
                f'{output[:3000]}'
            ),
            'solution': '',
            'reference': f'https://nmap.org/nsedoc/scripts/{script_id}.html',
            'url': location,
            'cwe_id': 0,
            'cvss_score': cvss_score,
            'cvss_vector': '',
            'alert_ref': f'nmap-{script_id}'[:50],
            'evidence': output[:500],
            'tool': 'nmap',
            'owasp_category': owasp_cat,
        }]

    @classmethod
    def parse_file_content(cls, content):
        """Parse uploaded nmap XML report without running a scan.

        Accepts nmap XML output (from nmap -oX or nmap -oA).
        Returns normalized finding dicts compatible with _store_findings().
        """
        obj = object.__new__(cls)
        stripped = content.strip()
        if not stripped.startswith('<'):
            raise ValueError('ไฟล์ต้องเป็น nmap XML (สร้างด้วย nmap -oX)')
        return obj.parse_xml(stripped)
