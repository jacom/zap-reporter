import os

from django.conf import settings


def organizations(request):
    """Expose all OrganizationProfile objects to every template."""
    from scanner.models import OrganizationProfile
    return {'organizations': OrganizationProfile.objects.all()}


def tool_urls(request):
    """Expose external (browser-facing) tool URLs to all templates.

    Uses *_WEB_URL from env if set, otherwise builds from the request host.
    """
    host = request.get_host().split(':')[0]  # IP/hostname without port

    sonar_web = os.environ.get('SONARQUBE_WEB_URL', f'http://{host}:9000')
    openvas_web = os.environ.get('OPENVAS_WEB_URL', getattr(settings, 'OPENVAS_URL', ''))
    wazuh_web = os.environ.get('WAZUH_WEB_URL', getattr(settings, 'WAZUH_URL', ''))

    return {
        'SONARQUBE_WEB_URL': sonar_web,
        'OPENVAS_WEB_URL': openvas_web,
        'WAZUH_WEB_URL': wazuh_web,
    }
