"""ZAP API client for interacting with OWASP ZAP."""
import logging
import time

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class ZAPClient:
    """Client for OWASP ZAP REST API."""

    # Default scan limits to prevent scans from running indefinitely
    SPIDER_MAX_DEPTH = 5
    SPIDER_MAX_DURATION_MINS = 10
    SPIDER_MAX_CHILDREN = 30
    ACTIVE_SCAN_MAX_DURATION_MINS = 60
    ACTIVE_SCAN_MAX_RULE_DURATION_MINS = 5

    def __init__(self, base_url=None, api_key=None):
        self.base_url = (base_url or settings.ZAP_BASE_URL).rstrip('/')
        self.api_key = api_key or settings.ZAP_API_KEY

    def _get(self, endpoint, params=None):
        params = params or {}
        params['apikey'] = self.api_key
        url = f"{self.base_url}{endpoint}"
        resp = requests.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_version(self):
        """Get ZAP version."""
        data = self._get('/JSON/core/view/version/')
        return data.get('version', 'unknown')

    # Static file extensions to exclude from active scan (large binary files)
    EXCLUDED_EXTENSIONS = (
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'mp4', 'mp3', 'avi', 'mov', 'mkv', 'webm',
        'zip', 'rar', 'tar', 'gz', '7z',
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'ico', 'webp',
        'woff', 'woff2', 'ttf', 'eot',
    )

    def _apply_scan_limits(self):
        """Set spider/active scan limits and exclude static file extensions."""
        try:
            self._get('/JSON/spider/action/setOptionMaxDepth/',
                       {'Integer': str(self.SPIDER_MAX_DEPTH)})
            self._get('/JSON/spider/action/setOptionMaxDuration/',
                       {'Integer': str(self.SPIDER_MAX_DURATION_MINS)})
            self._get('/JSON/spider/action/setOptionMaxChildren/',
                       {'Integer': str(self.SPIDER_MAX_CHILDREN)})
            self._get('/JSON/ascan/action/setOptionMaxScanDurationInMins/',
                       {'Integer': str(self.ACTIVE_SCAN_MAX_DURATION_MINS)})
            self._get('/JSON/ascan/action/setOptionMaxRuleDurationInMins/',
                       {'Integer': str(self.ACTIVE_SCAN_MAX_RULE_DURATION_MINS)})

            # Exclude static/binary file URLs from active scan to avoid
            # large response body errors (pdf/mp4 > 16 MB ZAP DB limit)
            ext_pattern = r'.*\.(' + '|'.join(self.EXCLUDED_EXTENSIONS) + r')(\?.*)?$'
            try:
                self._get('/JSON/ascan/action/addExcludedParam/', {
                    'name': ext_pattern, 'type': 'URL_PATH',
                })
            except Exception:
                pass
            try:
                self._get('/JSON/spider/action/excludeFromScan/', {
                    'regex': ext_pattern,
                })
            except Exception:
                pass

            logger.info(
                f"ZAP limits applied: spider depth={self.SPIDER_MAX_DEPTH} "
                f"duration={self.SPIDER_MAX_DURATION_MINS}m children={self.SPIDER_MAX_CHILDREN} | "
                f"active scan max={self.ACTIVE_SCAN_MAX_DURATION_MINS}m "
                f"rule max={self.ACTIVE_SCAN_MAX_RULE_DURATION_MINS}m | "
                f"excluded extensions: {len(self.EXCLUDED_EXTENSIONS)} types"
            )
        except Exception as e:
            logger.warning(f"Failed to apply ZAP scan limits: {e}")

    def spider_scan(self, target_url):
        """Start a spider scan and return scan ID."""
        data = self._get('/JSON/spider/action/scan/', {
            'url': target_url,
            'maxChildren': str(self.SPIDER_MAX_CHILDREN),
            'recurse': 'true',
        })
        return data.get('scan', '')

    def get_spider_status(self, scan_id):
        """Get spider scan progress (0-100)."""
        data = self._get('/JSON/spider/view/status/', {'scanId': scan_id})
        return int(data.get('status', '0'))

    def active_scan(self, target_url):
        """Start an active scan and return scan ID."""
        data = self._get('/JSON/ascan/action/scan/', {
            'url': target_url,
            'recurse': 'true',
        })
        return data.get('scan', '')

    def get_active_scan_status(self, scan_id):
        """Get active scan progress (0-100)."""
        data = self._get('/JSON/ascan/view/status/', {'id': scan_id})
        return int(data.get('status', '0'))

    def ajax_spider_scan(self, target_url):
        """Start an Ajax spider scan."""
        self._get('/JSON/ajaxSpider/action/scan/', {'url': target_url})
        return 'ajax'

    def get_ajax_spider_status(self):
        """Get Ajax spider status ('running' or 'stopped')."""
        data = self._get('/JSON/ajaxSpider/view/status/')
        return data.get('status', 'stopped')

    def get_spider_results(self, scan_id):
        """Get list of URLs discovered by spider scan."""
        data = self._get('/JSON/spider/view/results/', {'scanId': str(scan_id)})
        return data.get('results', [])

    def get_alerts(self, base_url=None, start=0, count=-1):
        """Get alerts from ZAP. Returns list of alert dicts."""
        params = {'start': str(start), 'count': str(count)}
        if base_url:
            params['baseurl'] = base_url
        data = self._get('/JSON/alert/view/alerts/', params)
        return data.get('alerts', [])

    def get_alerts_summary(self, base_url=None):
        """Get alert count summary by risk level."""
        params = {}
        if base_url:
            params['baseurl'] = base_url
        data = self._get('/JSON/alert/view/alertsSummary/', params)
        return data.get('alertsSummary', {})

    def poll_spider(self, scan_id, interval=3):
        """Poll spider scan until completion."""
        while True:
            progress = self.get_spider_status(scan_id)
            logger.info(f"Spider progress: {progress}%")
            if progress >= 100:
                break
            time.sleep(interval)

    def poll_active_scan(self, scan_id, interval=5):
        """Poll active scan until completion."""
        while True:
            progress = self.get_active_scan_status(scan_id)
            logger.info(f"Active scan progress: {progress}%")
            if progress >= 100:
                break
            time.sleep(interval)

    def full_scan(self, target_url):
        """Run spider + active scan, wait for completion, return alerts."""
        # Apply duration/depth limits before scanning
        self._apply_scan_limits()

        # Spider first
        spider_id = self.spider_scan(target_url)
        logger.info(f"Spider started: {spider_id}")
        self.poll_spider(spider_id)

        # Then active scan
        ascan_id = self.active_scan(target_url)
        logger.info(f"Active scan started: {ascan_id}")
        self.poll_active_scan(ascan_id)

        # Collect alerts
        alerts = self.get_alerts(base_url=target_url)
        return ascan_id, alerts

    def stop_spider(self, scan_id):
        """Stop a running spider scan."""
        self._get('/JSON/spider/action/stop/', {'scanId': scan_id})

    def stop_active_scan(self, scan_id):
        """Stop a running active scan."""
        self._get('/JSON/ascan/action/stop/', {'scanId': scan_id})

    def stop_ajax_spider(self):
        """Stop the Ajax spider."""
        self._get('/JSON/ajaxSpider/action/stop/')

    def stop_all_scans(self):
        """Stop all running scans (spider + active + ajax)."""
        try:
            self._get('/JSON/spider/action/stopAllScans/')
        except Exception:
            pass
        try:
            self._get('/JSON/ascan/action/stopAllScans/')
        except Exception:
            pass
        try:
            self.stop_ajax_spider()
        except Exception:
            pass

    def clear_session(self):
        """Create a new ZAP session (clears alerts)."""
        self._get('/JSON/core/action/newSession/', {'overwrite': 'true'})
