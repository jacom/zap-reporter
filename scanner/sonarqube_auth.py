import logging

import requests
from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User

logger = logging.getLogger(__name__)


class SonarQubeBackend(BaseBackend):
    """Authenticate against the SonarQube API."""

    def authenticate(self, request, username=None, password=None):
        if username is None or password is None:
            return None

        if not self._verify_sonarqube(username, password):
            return None

        user, created = User.objects.get_or_create(
            username=username,
            defaults={'is_active': True},
        )
        if created:
            user.set_unusable_password()
            user.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    @staticmethod
    def _verify_sonarqube(username, password):
        """Call SonarQube authentication/validate with basic auth."""
        base_url = getattr(settings, 'SONARQUBE_URL', '') or 'http://127.0.0.1:9000'
        url = f'{base_url.rstrip("/")}/api/authentication/validate'
        try:
            resp = requests.get(url, auth=(username, password), timeout=10)
            if resp.status_code == 200:
                return resp.json().get('valid', False)
            return False
        except Exception:
            logger.exception('SonarQube auth check failed')
            return False
