"""Wazuh SIEM client — Security Logging & Alerting (A09)."""
import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

SCA_RESULT_RISK = {
    'failed': 3,    # High
    'not applicable': 1,  # Low
    'passed': 0,    # Info
}


class WazuhClient:
    """Client for Wazuh REST API (4.x compatible)."""

    def __init__(self, base_url=None, user=None, password=None):
        self.base_url = (base_url or settings.WAZUH_URL).rstrip('/')
        self.user = user or settings.WAZUH_USER
        self.password = password or settings.WAZUH_PASSWORD
        self._token = None
        self.session = requests.Session()
        self.session.verify = False  # Wazuh uses self-signed certs by default

    def _authenticate(self):
        """Get JWT token from Wazuh API."""
        resp = self.session.post(
            f'{self.base_url}/security/user/authenticate',
            auth=(self.user, self.password),
            timeout=10,
        )
        resp.raise_for_status()
        self._token = resp.json().get('data', {}).get('token', '')
        self.session.headers['Authorization'] = f'Bearer {self._token}'

    def _get(self, endpoint, params=None):
        if not self._token:
            self._authenticate()
        resp = self.session.get(
            f'{self.base_url}{endpoint}',
            params=params or {},
            timeout=30,
        )
        if resp.status_code == 401:
            self._authenticate()
            resp = self.session.get(
                f'{self.base_url}{endpoint}',
                params=params or {},
                timeout=30,
            )
        resp.raise_for_status()
        return resp.json()

    def check_health(self):
        """Check Wazuh API status (with authentication)."""
        try:
            data = self._get('/')
            return data.get('data', {}).get('api_version') is not None
        except Exception:
            return False

    def get_version(self):
        """Get Wazuh version."""
        try:
            data = self._get('/')
            return data.get('data', {}).get('api_version', 'unknown')
        except Exception as e:
            return f'error: {e}'

    def get_agents(self):
        """List all agents."""
        data = self._get('/agents', {'limit': 500})
        return data.get('data', {}).get('affected_items', [])

    def get_agent_summary(self):
        """Get agent summary (active/disconnected/etc)."""
        data = self._get('/agents/summary/status')
        return data.get('data', {})

    def get_alerts(self, limit=500, offset=0, level_min=None, agent_id=None):
        """Get security findings from SCA checks across all agents.

        Wazuh 4.x does not expose /alerts via the Manager API.
        We use SCA (Security Configuration Assessment) checks instead,
        which provide actionable security findings.

        If agent_id is provided, only fetch SCA checks for that agent.
        """
        try:
            agents = self.get_agents()
        except Exception as e:
            logger.exception(f'Wazuh agents fetch failed: {e}')
            return [], 0

        all_findings = []
        for agent in agents:
            aid = agent.get('id')
            agent_name = agent.get('name', '')

            # If specific agent requested, skip others
            if agent_id:
                if aid != agent_id:
                    continue
            elif agent.get('status') != 'active':
                continue

            # Get SCA policies for this agent
            try:
                sca_data = self._get(f'/sca/{aid}', {'limit': 100})
                policies = sca_data.get('data', {}).get('affected_items', [])
            except Exception as e:
                logger.warning(f'Wazuh SCA fetch failed for agent {aid}: {e}')
                continue

            for policy in policies:
                policy_id = policy.get('policy_id', '')
                # Get failed checks for this policy
                try:
                    checks_data = self._get(
                        f'/sca/{aid}/checks/{policy_id}',
                        {'limit': limit, 'result': 'failed'},
                    )
                    checks = checks_data.get('data', {}).get('affected_items', [])
                except Exception as e:
                    logger.warning(f'Wazuh SCA checks fetch failed for {policy_id}: {e}')
                    continue

                for check in checks:
                    all_findings.append(self._parse_sca_check(check, agent_name, aid, policy_id))

        return all_findings, len(all_findings)

    def get_sca_results(self, agent_id):
        """Get Security Configuration Assessment results."""
        try:
            data = self._get(f'/sca/{agent_id}', {'limit': 500})
            return data.get('data', {}).get('affected_items', [])
        except Exception as e:
            logger.exception(f'Wazuh SCA fetch failed: {e}')
            return []

    def _parse_sca_check(self, check, agent_name, agent_id, policy_id):
        """Parse a single SCA check into a normalized finding dict."""
        result = check.get('result', 'failed')
        risk = SCA_RESULT_RISK.get(result, 2)

        compliance = check.get('compliance', [])
        comp_str = ', '.join(f"{c['key']}:{c['value']}" for c in compliance)

        mitre_refs = [c['value'] for c in compliance if c.get('key', '').startswith('mitre_')]

        return {
            'name': check.get('title', 'Unknown SCA check')[:500],
            'risk': risk,
            'description': (
                f"Policy: {policy_id}\n"
                f"Result: {result}\n"
                f"Rationale: {check.get('rationale', '')}\n"
                f"Agent: {agent_name} ({agent_id})\n"
                f"Compliance: {comp_str}"
            ),
            'solution': check.get('remediation', ''),
            'reference': '\n'.join(mitre_refs[:5]),
            'url': agent_name,
            'cwe_id': 0,
            'cvss_score': risk * 3,  # approximate: 0, 3, 6, 9, 12
            'cvss_vector': '',
            'alert_ref': str(check.get('id', '')),
            'evidence': check.get('command', '') or check.get('description', ''),
            'tool': 'wazuh',
            'owasp_category': 'A09',
        }
