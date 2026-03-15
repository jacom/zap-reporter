from django import template
from django.utils import timezone as tz

register = template.Library()

THAI_MONTHS = [
    'มกราคม', 'กุมภาพันธ์', 'มีนาคม', 'เมษายน',
    'พฤษภาคม', 'มิถุนายน', 'กรกฎาคม', 'สิงหาคม',
    'กันยายน', 'ตุลาคม', 'พฤศจิกายน', 'ธันวาคม',
]

THAI_MONTHS_SHORT = [
    'ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.',
    'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.',
    'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.',
]


def _format_thai(dt, fmt):
    import datetime as _dt
    if dt is None:
        return ''
    if isinstance(dt, _dt.datetime):
        dt = tz.localtime(dt)
        hour, minute = dt.hour, dt.minute
    elif isinstance(dt, _dt.date):
        hour, minute = 0, 0
    else:
        return str(dt)
    be_year = dt.year + 543
    result = fmt
    result = result.replace('d', f'{dt.day:02d}')
    result = result.replace('j', str(dt.day))
    result = result.replace('F', THAI_MONTHS[dt.month - 1])
    result = result.replace('M', THAI_MONTHS_SHORT[dt.month - 1])
    result = result.replace('Y', str(be_year))
    result = result.replace('H', f'{hour:02d}')
    result = result.replace('i', f'{minute:02d}')
    return result


@register.filter(name='thaidate')
def thaidate(value, fmt='j F Y'):
    return _format_thai(value, fmt)


@register.simple_tag(name='thainow')
def thainow(fmt='j F Y'):
    return _format_thai(tz.now(), fmt)


_TOOL_BADGE = {
    'zap':       ('bg-danger',           'bi-bug'),
    'nuclei':    ('bg-success',          'bi-stars'),
    'nmap':      ('bg-primary',          'bi-ethernet'),
    'httpx':     ('bg-info text-dark',   'bi-globe2'),
    'sqlmap':    ('bg-warning text-dark','bi-database-exclamation'),
    'trivy':     ('bg-secondary',        'bi-box-seam'),
    'sonarqube': ('bg-primary',          'bi-code-slash'),
    'testssl':   ('bg-secondary',        'bi-lock'),
    'wazuh':     ('bg-warning text-dark','bi-eye'),
    'openvas':   ('bg-dark',             'bi-hdd-network'),
}


@register.filter(name='tool_badge_class')
def tool_badge_class(tool):
    """Return Bootstrap badge CSS class for a tool key."""
    return _TOOL_BADGE.get(tool, ('bg-secondary', 'bi-tools'))[0]


@register.filter(name='tool_badge_icon')
def tool_badge_icon(tool):
    """Return Bootstrap icon class for a tool key."""
    return _TOOL_BADGE.get(tool, ('bg-secondary', 'bi-tools'))[1]
