"""CVE enrichment for Alert objects.

Two strategies:
1. Text extraction  — regex scan of name/reference/description for CVE-YYYY-NNNNN
2. NVD API lookup   — query nvd.nist.gov for CVEs that share a CWE ID
                      (useful when the tool only provides CWE, not CVE)
"""
import logging
import re

import requests
from django.core.cache import cache

logger = logging.getLogger(__name__)

# Matches CVE-YYYY-NNNNN (standard) and CVEyyyy-nnnnn (nmap script name style, no dash after CVE)
_CVE_RE = re.compile(r'\bCVE-?\d{4}-\d{4,7}\b', re.IGNORECASE)

NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_CACHE_TTL = 3600  # 1 hour


# ── Extraction ────────────────────────────────────────────────────────────────

def extract_cves_from_text(*texts):
    """Return sorted list of unique CVE IDs found across all given text strings."""
    found = set()
    for text in texts:
        if text:
            for m in _CVE_RE.finditer(str(text)):
                cve = m.group(0).upper()
                # Normalise CVE20YY-NNNN → CVE-20YY-NNNN (nmap script name format)
                if not cve.startswith('CVE-'):
                    cve = 'CVE-' + cve[3:]
                found.add(cve)
    return sorted(found)


def enrich_alert(alert, save=True):
    """Extract CVE IDs from alert fields and persist to cve_ids.

    Searches: name, reference, description, evidence, alert_ref.
    Only writes to DB if the set of CVEs actually changed.
    Returns the list of CVE IDs found.
    """
    cves = extract_cves_from_text(
        alert.name,
        alert.reference,
        alert.description,
        alert.evidence,
        alert.alert_ref,
    )
    if set(cves) != set(alert.cve_ids or []):
        alert.cve_ids = cves
        if save:
            alert.save(update_fields=['cve_ids'])
    return cves


def enrich_scan_alerts(scan):
    """Enrich all alerts in a scan. Returns total CVE references found."""
    total = 0
    for alert in scan.alerts.all():
        total += len(enrich_alert(alert, save=True))
    return total


def enrich_alerts_by_cwe(scan, api_key=''):
    """For alerts with CWE but no CVE IDs, query NVD by CWE and store top CVEs.

    Groups alerts by CWE to minimise API calls (one call per unique CWE).
    Returns count of alerts that were enriched.
    """
    from collections import defaultdict

    # Collect alerts that need enrichment (have CWE, but no CVEs yet)
    needs = [
        a for a in scan.alerts.filter(cwe_id__gt=0)
        if not a.cve_ids
    ]
    if not needs:
        return 0

    # Group by CWE to batch API calls
    by_cwe = defaultdict(list)
    for a in needs:
        by_cwe[a.cwe_id].append(a)

    import time

    enriched = 0
    for cwe_id, alerts in by_cwe.items():
        cve_list = lookup_nvd_cves(cwe_id, limit=5, api_key=api_key)
        if not cve_list:
            # Throttle: 5 req/30 s without key, 50 req/30 s with key
            time.sleep(0.7 if api_key else 6.5)
            continue
        cve_ids = [c['id'] for c in cve_list]
        for a in alerts:
            a.cve_ids = cve_ids
            a.save(update_fields=['cve_ids'])
            enriched += 1
        time.sleep(0.7 if api_key else 6.5)

    return enriched


# ── NVD API ───────────────────────────────────────────────────────────────────

def lookup_nvd_cves(cwe_id, limit=10, api_key=''):
    """Query NVD v2 API for CVEs associated with a CWE ID.

    Results are cached for NVD_CACHE_TTL seconds.
    Returns list of dicts:
        [{'id', 'cvss', 'cvss_vector', 'severity', 'description', 'published', 'nvd_url'}]
    sorted by CVSS score descending.
    """
    if not cwe_id:
        return []

    cache_key = f'nvd_cwe_{cwe_id}_{limit}'
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    headers = {'User-Agent': 'zap-reporter/1.0'}
    if api_key:
        headers['apiKey'] = api_key

    try:
        resp = requests.get(
            NVD_API_URL,
            params={'cweId': f'CWE-{cwe_id}', 'resultsPerPage': limit},
            headers=headers,
            timeout=15,
        )
        if resp.status_code != 200:
            logger.warning(f'NVD API returned {resp.status_code} for CWE-{cwe_id}')
            return []
        data = resp.json()
    except requests.RequestException as e:
        logger.warning(f'NVD lookup failed for CWE-{cwe_id}: {e}')
        return []

    results = []
    for item in data.get('vulnerabilities', []):
        cve_obj = item.get('cve', {})
        cve_id = cve_obj.get('id', '')
        if not cve_id:
            continue

        # English description
        desc = ''
        for d in cve_obj.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')[:500]
                break

        # CVSS score — prefer v3.1 > v3.0 > v2
        cvss = 0.0
        cvss_vector = ''
        severity = ''
        metrics = cve_obj.get('metrics', {})
        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            if metrics.get(key):
                block = metrics[key][0]
                cvss_data = block.get('cvssData', {})
                cvss = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                severity = block.get('baseSeverity', '') or cvss_data.get('baseSeverity', '')
                break

        results.append({
            'id':          cve_id,
            'cvss':        cvss,
            'cvss_vector': cvss_vector,
            'severity':    severity.upper() if severity else _cvss_to_severity(cvss),
            'description': desc,
            'published':   cve_obj.get('published', '')[:10],
            'nvd_url':     f'https://nvd.nist.gov/vuln/detail/{cve_id}',
        })

    results.sort(key=lambda x: -x['cvss'])
    cache.set(cache_key, results, NVD_CACHE_TTL)
    return results


def _cvss_to_severity(score):
    if score >= 9.0: return 'CRITICAL'
    if score >= 7.0: return 'HIGH'
    if score >= 4.0: return 'MEDIUM'
    if score > 0:    return 'LOW'
    return 'INFO'
