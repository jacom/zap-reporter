"""
AI-powered vulnerability analysis using OpenAI API.

Flow:
  grouped_alerts (from scan_detail view)
      → _build_prompt()
      → OpenAI chat completion (one batch call per scan)
      → parse JSON response
      → save AlertAIAnalysis records to DB
"""
import json
import logging

from django.conf import settings

logger = logging.getLogger(__name__)

_RISK_LABEL = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}


def _build_prompt(items, target_name, target_url):
    """Build the prompt sent to the AI model.

    items: list of dicts with keys id, title, risk, cvss, reference,
           reference_type, url_count, sample_url, evidence, description
    reference_type is 'CVE' when specific CVE IDs are known, 'CWE' otherwise.
    """
    vulns_json = json.dumps(items, ensure_ascii=False, indent=2)

    return f"""You are a senior cybersecurity consultant preparing a professional \
vulnerability assessment report for {target_name} ({target_url}).

Analyze each vulnerability below and respond with a JSON object containing \
an "analyses" array. Each element must have these fields:
  - id: integer (same as input id)
  - technical_explanation: อธิบายเชิงเทคนิคว่าช่องโหว่นี้คืออะไรและอันตรายอย่างไร (2-3 ประโยค ภาษาไทย)
  - business_impact: ผลกระทบต่อองค์กรหากถูกโจมตี (2-3 ประโยค ภาษาไทย)
  - remediation: ขั้นตอนการแก้ไขเป็น bullet point เริ่มต้นแต่ละข้อด้วย "• " (3-5 ข้อ ภาษาไทย)

Rules:
- Respond ONLY with valid JSON, no markdown, no code fences.
- Keep each field concise (under 150 words).
- remediation must be plain text bullet points separated by newline, starting with "• ".
- When reference_type is "CVE": use the specific CVE details (known exploits, patch versions, \
affected components) to make the analysis concrete and actionable for manual penetration testing.
- When reference_type is "CWE": analyze based on the weakness class and provide \
general but technically accurate guidance.

Input vulnerabilities:
{vulns_json}

Expected output format:
{{"analyses": [{{"id": 0, "technical_explanation": "...", "business_impact": "...", "remediation": "• ...\n• ..."}}]}}"""


def analyze_scan(scan, grouped_alerts, max_vulns=30):
    """Send grouped alerts to OpenAI and persist results.

    Parameters
    ----------
    scan : Scan model instance
    grouped_alerts : list of dicts (output from scan_detail view grouping)
    max_vulns : max number of unique vulns to analyze (highest risk first)

    Returns
    -------
    int : number of AI analysis records saved
    """
    from scanner.models import AlertAIAnalysis

    api_key = getattr(settings, 'OPENAI_API_KEY', '')
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured in settings / .env")

    # High (3) and Medium (2) only — exclude Critical, Low, Info
    candidates = sorted(
        [g for g in grouped_alerts if g['risk'] in (2, 3)],
        key=lambda g: (-g['risk'], -g['cvss_score'])
    )[:max_vulns]

    items = []
    for i, g in enumerate(candidates):
        cve_ids = g.get('cve_ids') or []
        if cve_ids:
            reference = ', '.join(cve_ids[:5])
            reference_type = 'CVE'
        elif g.get('cwe_id'):
            reference = f"CWE-{g['cwe_id']}"
            reference_type = 'CWE'
        else:
            reference = ''
            reference_type = ''

        items.append({
            "id": i,
            "title": g['name'],
            "risk": _RISK_LABEL.get(g['risk'], 'Unknown'),
            "cvss": str(g['cvss_score']),
            "reference": reference,
            "reference_type": reference_type,
            "url_count": len(g.get('urls', [])),
            "sample_url": (g.get('urls') or [''])[0][:120],
            "evidence": (g.get('evidence') or '')[:150],
            "description": (g.get('description') or '')[:250],
        })

    prompt = _build_prompt(items, scan.target.name, scan.target.url)

    from openai import OpenAI
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=getattr(settings, 'OPENAI_MODEL', 'gpt-5.2'),
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        response_format={"type": "json_object"},
        timeout=120,
    )

    content = response.choices[0].message.content
    try:
        data = json.loads(content)
        analyses = data.get('analyses', [])
    except json.JSONDecodeError as exc:
        logger.error("OpenAI returned invalid JSON: %s", exc)
        raise ValueError(f"AI returned invalid JSON: {exc}") from exc

    saved = 0
    for item in analyses:
        idx = item.get('id')
        if idx is None or idx >= len(candidates):
            continue
        g = candidates[idx]
        AlertAIAnalysis.objects.update_or_create(
            scan=scan,
            name=g['name'],
            cwe_id=g.get('cwe_id') or 0,
            defaults={
                'cvss_score': g.get('cvss_score', 0),
                'risk': g.get('risk', 0),
                'technical_explanation': item.get('technical_explanation', ''),
                'business_impact': item.get('business_impact', ''),
                'remediation': item.get('remediation', ''),
                'ai_model': getattr(settings, 'OPENAI_MODEL', 'gpt-5.2'),
            },
        )
        saved += 1

    logger.info("AI analysis saved %d/%d records for scan %s", saved, len(candidates), scan.id)
    return saved
