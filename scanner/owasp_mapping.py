"""OWASP Top 10:2025 mapping module.

Maps findings from all tools (ZAP, Trivy, SonarQube, testssl, Wazuh, OpenVAS)
to OWASP Top 10:2025 categories A01-A10.
"""

# ── OWASP Top 10:2025 Definitions ─────────────────────────────────────────
OWASP_2025 = {
    'A01': {
        'code': 'A01:2025',
        'name': 'Broken Access Control',
        'name_th': 'ระบบควบคุมการเข้าถึงชำรุด',
        'tools': ['zap', 'openvas'],
    },
    'A02': {
        'code': 'A02:2025',
        'name': 'Security Misconfiguration',
        'name_th': 'การตั้งค่าความปลอดภัยไม่ถูกต้อง',
        'tools': ['zap', 'openvas', 'testssl'],
    },
    'A03': {
        'code': 'A03:2025',
        'name': 'Software Supply Chain Failures',
        'name_th': 'ความล้มเหลวของห่วงโซ่อุปทานซอฟต์แวร์',
        'tools': ['trivy'],
    },
    'A04': {
        'code': 'A04:2025',
        'name': 'Cryptographic Failures',
        'name_th': 'ความล้มเหลวในการเข้ารหัส',
        'tools': ['testssl', 'zap'],
    },
    'A05': {
        'code': 'A05:2025',
        'name': 'Injection',
        'name_th': 'การฉีดคำสั่ง/ข้อมูลอันตราย',
        'tools': ['zap', 'sonarqube'],
    },
    'A06': {
        'code': 'A06:2025',
        'name': 'Insecure Design',
        'name_th': 'การออกแบบที่ไม่ปลอดภัย',
        'tools': ['sonarqube'],
    },
    'A07': {
        'code': 'A07:2025',
        'name': 'Authentication Failures',
        'name_th': 'การตรวจสอบสิทธิ์ล้มเหลว',
        'tools': ['zap', 'openvas'],
    },
    'A08': {
        'code': 'A08:2025',
        'name': 'Software or Data Integrity Failures',
        'name_th': 'ความล้มเหลวของซอฟต์แวร์หรือความสมบูรณ์ของข้อมูล',
        'tools': ['sonarqube', 'trivy'],
    },
    'A09': {
        'code': 'A09:2025',
        'name': 'Security Logging and Alerting Failures',
        'name_th': 'การบันทึกและการแจ้งเตือนด้านความปลอดภัยที่ล้มเหลว',
        'tools': ['wazuh'],
    },
    'A10': {
        'code': 'A10:2025',
        'name': 'Mishandling of Exceptional Conditions',
        'name_th': 'การจัดการสถานการณ์พิเศษที่ไม่เหมาะสม',
        'tools': ['zap', 'sonarqube'],
    },
}

# ── CWE → OWASP 2025 Mapping ─────────────────────────────────────────────
# Based on OWASP Top 10:2025 CWE mappings
CWE_TO_OWASP = {
    # A01 - Broken Access Control
    22: 'A01', 23: 'A01', 35: 'A01', 59: 'A01',
    200: 'A01', 201: 'A01', 219: 'A01',
    264: 'A01', 275: 'A01', 276: 'A01',
    284: 'A01', 285: 'A01',
    352: 'A01',  # CSRF
    402: 'A01', 425: 'A01', 441: 'A01',
    497: 'A01', 538: 'A01', 540: 'A01', 548: 'A01',
    552: 'A01',
    639: 'A01',  # IDOR
    651: 'A01', 668: 'A01',
    706: 'A01',
    862: 'A01', 863: 'A01',
    913: 'A01',
    918: 'A01',  # SSRF (merged into A01 in 2025)
    1275: 'A01',

    # A02 - Security Misconfiguration
    2: 'A02', 11: 'A02', 13: 'A02', 15: 'A02', 16: 'A02',
    209: 'A02', 215: 'A02', 256: 'A02', 260: 'A02',
    315: 'A02', 520: 'A02', 525: 'A02', 532: 'A02',
    537: 'A02', 541: 'A02',
    547: 'A02', 611: 'A02',
    614: 'A02', 756: 'A02',
    776: 'A02',
    942: 'A02', 1004: 'A02', 1032: 'A02',

    # A03 - Supply Chain Failures
    # (mostly CVE-based, handled by tool source = trivy)

    # A04 - Cryptographic Failures
    261: 'A04', 296: 'A04', 310: 'A04', 311: 'A04',
    312: 'A04', 319: 'A04', 320: 'A04',
    321: 'A04', 323: 'A04', 324: 'A04', 325: 'A04',
    326: 'A04', 327: 'A04', 328: 'A04', 329: 'A04',
    330: 'A04', 331: 'A04',
    335: 'A04', 336: 'A04',
    338: 'A04',
    340: 'A04', 347: 'A04',
    523: 'A04',
    720: 'A04', 757: 'A04', 759: 'A04', 760: 'A04', 780: 'A04',
    295: 'A04', 297: 'A04', 298: 'A04',

    # A05 - Injection
    20: 'A05', 74: 'A05', 75: 'A05', 77: 'A05', 78: 'A05',
    79: 'A05', 80: 'A05', 83: 'A05',
    87: 'A05', 88: 'A05', 89: 'A05', 90: 'A05', 91: 'A05',
    93: 'A05', 94: 'A05', 95: 'A05', 96: 'A05', 97: 'A05',
    98: 'A05', 99: 'A05',
    113: 'A05',
    116: 'A05',
    138: 'A05',
    184: 'A05',
    470: 'A05',
    471: 'A05',
    564: 'A05',
    610: 'A05',
    643: 'A05',
    644: 'A05',
    652: 'A05',
    917: 'A05',  # Expression Language Injection

    # A06 - Insecure Design
    73: 'A06', 183: 'A06', 209: 'A06',
    256: 'A06', 501: 'A06', 522: 'A06',
    602: 'A06', 642: 'A06', 646: 'A06',
    650: 'A06',
    653: 'A06', 656: 'A06', 657: 'A06',
    799: 'A06',
    841: 'A06',

    # A07 - Authentication Failures
    255: 'A07', 259: 'A07', 287: 'A07',
    288: 'A07', 290: 'A07', 294: 'A07',
    295: 'A07',
    306: 'A07', 307: 'A07', 346: 'A07',
    384: 'A07',
    521: 'A07',
    613: 'A07', 620: 'A07', 640: 'A07',
    798: 'A07',

    # A08 - Software/Data Integrity Failures
    345: 'A08', 353: 'A08',
    426: 'A08',
    494: 'A08',
    502: 'A08',  # Deserialization
    565: 'A08',
    784: 'A08', 829: 'A08', 830: 'A08',
    915: 'A08',

    # A09 - Logging/Alerting Failures
    117: 'A09', 223: 'A09', 532: 'A09', 778: 'A09',

    # A10 - Exceptional Conditions
    230: 'A10', 248: 'A10', 252: 'A10', 253: 'A10',
    280: 'A10', 354: 'A10', 391: 'A10', 395: 'A10',
    396: 'A10', 397: 'A10', 400: 'A10',
    460: 'A10', 476: 'A10',
    544: 'A10', 703: 'A10', 754: 'A10', 755: 'A10',
}

# ── ZAP Alert Tag → OWASP 2025 Mapping ──────────────────────────────────
ZAP_TAG_TO_OWASP = {
    'OWASP_2021_A01': 'A01',
    'OWASP_2021_A02': 'A04',  # Crypto → A04 in 2025
    'OWASP_2021_A03': 'A05',  # Injection → A05 in 2025
    'OWASP_2021_A04': 'A06',  # Insecure Design
    'OWASP_2021_A05': 'A02',  # Misconfig → A02 in 2025
    'OWASP_2021_A06': 'A03',  # Vulnerable Components → A03 in 2025
    'OWASP_2021_A07': 'A07',  # Auth Failures
    'OWASP_2021_A08': 'A08',  # Integrity Failures
    'OWASP_2021_A09': 'A09',  # Logging Failures
    'OWASP_2021_A10': 'A01',  # SSRF → merged into A01 in 2025
}


def map_to_owasp(cwe_id=0, tool='', tags=None, alert_ref=''):
    """Map a finding to OWASP 2025 category.

    Priority:
    1. Explicit tool-based mapping (trivy→A03, testssl→A04, wazuh→A09)
    2. ZAP alert tags (OWASP_2021_* → OWASP 2025)
    3. CWE-based mapping
    4. Empty string if no mapping found
    """
    # 1. Tool-specific defaults
    tool_defaults = {
        'trivy': 'A03',
        'testssl': 'A04',
        'wazuh': 'A09',
    }
    if tool in tool_defaults:
        return tool_defaults[tool]

    # 2. ZAP tags
    if tags:
        for tag in (tags if isinstance(tags, list) else [tags]):
            tag_str = str(tag).upper()
            for zap_tag, owasp_cat in ZAP_TAG_TO_OWASP.items():
                if zap_tag in tag_str:
                    return owasp_cat

    # 3. CWE mapping
    if cwe_id and cwe_id in CWE_TO_OWASP:
        return CWE_TO_OWASP[cwe_id]

    return ''


def get_owasp_summary(alerts_queryset):
    """Generate OWASP 2025 summary from alerts queryset.

    Returns dict: {
        'A01': {'info': {...}, 'critical': N, 'high': N, 'medium': N, 'low': N, 'info': N, 'total': N},
        ...
    }
    """
    summary = {}
    for code, info in OWASP_2025.items():
        category_alerts = alerts_queryset.filter(owasp_category=code)
        summary[code] = {
            'info': info,
            'critical': category_alerts.filter(risk=4).count(),
            'high': category_alerts.filter(risk=3).count(),
            'medium': category_alerts.filter(risk=2).count(),
            'low': category_alerts.filter(risk=1).count(),
            'informational': category_alerts.filter(risk=0).count(),
            'total': category_alerts.count(),
        }
    return summary


def get_coverage_status(tools_status):
    """Check which OWASP 2025 categories are covered by active tools.

    Args:
        tools_status: dict of {'zap': True, 'trivy': True, ...}

    Returns:
        dict: {'A01': {'covered': True, 'tools': ['zap', 'openvas']}, ...}
    """
    coverage = {}
    for code, info in OWASP_2025.items():
        active_tools = [t for t in info['tools'] if tools_status.get(t, False)]
        coverage[code] = {
            'info': info,
            'covered': len(active_tools) > 0,
            'active_tools': active_tools,
            'missing_tools': [t for t in info['tools'] if not tools_status.get(t, False)],
        }
    return coverage
