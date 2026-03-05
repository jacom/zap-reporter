import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file
_env_file = BASE_DIR / '.env'
if _env_file.is_file():
    with open(_env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, value = line.partition('=')
                os.environ.setdefault(key.strip(), value.strip())

SECRET_KEY = os.environ.get(
    'DJANGO_SECRET_KEY',
    'django-insecure-zap-reporter-change-in-production'
)

DEBUG = os.environ.get('DJANGO_DEBUG', 'True').lower() in ('true', '1', 'yes')

ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '*').split(',')

CSRF_TRUSTED_ORIGINS = []
for host in os.environ.get('DJANGO_ALLOWED_HOSTS', '*').split(','):
    h = host.strip()
    if h and h != '*':
        CSRF_TRUSTED_ORIGINS.append(f"http://{h}")
        CSRF_TRUSTED_ORIGINS.append(f"http://{h}:8443")
if not CSRF_TRUSTED_ORIGINS:
    CSRF_TRUSTED_ORIGINS = ['http://192.168.1.5', 'http://192.168.1.5:8443', 'http://127.0.0.1', 'http://127.0.0.1:8443']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.postgres',
    'rest_framework',
    'scanner',
    'dashboard',
    'reports',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'dashboard.context_processors.tool_urls',
                'dashboard.context_processors.organizations',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'zap_report'),
        'USER': os.environ.get('DB_USER', 'jong2'),
        'PASSWORD': os.environ.get('DB_PASSWORD', 'jong2'),
        'HOST': os.environ.get('DB_HOST', ''),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Bangkok'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTHENTICATION_BACKENDS = [
    'scanner.sonarqube_auth.SonarQubeBackend',
    'django.contrib.auth.backends.ModelBackend',
]

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'

REST_FRAMEWORK = {
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
}

# ZAP Configuration
ZAP_BASE_URL = os.environ.get('ZAP_BASE_URL', 'http://127.0.0.1:8090')
ZAP_API_KEY = os.environ.get('ZAP_API_KEY', '')

# Trivy Configuration
TRIVY_SERVER_URL = os.environ.get('TRIVY_SERVER_URL', 'http://127.0.0.1:4954')

# SonarQube Configuration
SONARQUBE_URL = os.environ.get('SONARQUBE_URL', 'http://127.0.0.1:9000')
SONARQUBE_TOKEN = os.environ.get('SONARQUBE_TOKEN', '')

# Wazuh Configuration
WAZUH_URL = os.environ.get('WAZUH_URL', 'https://127.0.0.1:55000')
WAZUH_USER = os.environ.get('WAZUH_USER', 'wazuh-wui')
WAZUH_PASSWORD = os.environ.get('WAZUH_PASSWORD', '')

# OpenVAS/GVM Configuration
OPENVAS_URL = os.environ.get('OPENVAS_URL', 'http://127.0.0.1:9390')
OPENVAS_USER = os.environ.get('OPENVAS_USER', 'admin')
OPENVAS_PASSWORD = os.environ.get('OPENVAS_PASSWORD', '')

# OpenAI Configuration
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
# NVD API key (optional — free at https://nvd.nist.gov/developers/request-an-api-key)
# Without key: 5 req/30s limit. With key: 50 req/30s limit.
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
OPENAI_MODEL = os.environ.get('OPENAI_MODEL', 'gpt-5.2')

# WPScan Configuration (free token at https://wpscan.com/register)
WPSCAN_API_TOKEN = os.environ.get('WPSCAN_API_TOKEN', '')
