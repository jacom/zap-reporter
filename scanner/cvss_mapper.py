"""CWE to CVSS score/vector mapping for common vulnerabilities."""

# Mapping: CWE-ID → (CVSS 3.1 score, CVSS vector string)
CWE_CVSS_MAP = {
    # Injection
    89: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),    # SQL Injection
    78: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),    # OS Command Injection
    77: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),    # Command Injection
    94: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),    # Code Injection
    917: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),   # Expression Language Injection

    # XSS
    79: (6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),    # XSS (Reflected)
    80: (6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),    # XSS (Stored candidate)

    # Authentication & Session
    287: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),   # Improper Authentication
    384: (8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'),   # Session Fixation
    613: (5.4, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N'),   # Insufficient Session Expiration
    798: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),   # Hard-coded Credentials

    # Access Control
    284: (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),   # Improper Access Control
    862: (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),   # Missing Authorization
    863: (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),   # Incorrect Authorization
    22: (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),    # Path Traversal

    # Cryptographic
    327: (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),   # Broken Crypto
    328: (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),   # Reversible Hash
    311: (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),   # Missing Encryption
    295: (5.9, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'),   # Improper Cert Validation

    # Information Disclosure
    200: (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),   # Information Exposure
    209: (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),   # Error Message Info Leak
    532: (5.5, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'),   # Info in Log Files
    548: (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),   # Directory Listing

    # CSRF / SSRF
    352: (8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'),   # CSRF
    918: (9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'),   # SSRF

    # Deserialization / XXE
    502: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),   # Deserialization
    611: (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),   # XXE

    # File Upload / Inclusion
    434: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),   # Unrestricted Upload
    98: (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),    # File Inclusion

    # Security Misconfiguration
    16: (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),    # Configuration
    693: (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'),   # Protection Mechanism Failure

    # Open Redirect
    601: (6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),   # Open Redirect
}

# Fallback based on ZAP risk level
RISK_FALLBACK = {
    3: (8.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),    # High
    2: (5.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),    # Medium
    1: (3.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'),    # Low
    0: (0.0, ''),                                                    # Informational
}


def get_cvss(cwe_id, risk_level=0):
    """Return (cvss_score, cvss_vector) for a given CWE ID.

    Falls back to risk-level-based estimate if CWE not in map.
    """
    if cwe_id and cwe_id in CWE_CVSS_MAP:
        return CWE_CVSS_MAP[cwe_id]
    return RISK_FALLBACK.get(risk_level, (0.0, ''))
