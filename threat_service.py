"""Shared, read-only CISA KEV service. Upstream content is untrusted."""
import os
import re
import time
import threading
from datetime import datetime, timezone
import httpx

CISA_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.ASCII | re.IGNORECASE)
_cache = {'data': None, 'at': 0}
_lock = threading.Lock()

class ServiceError(Exception):
    pass

def validate_cve(value):
    if not isinstance(value, str) or len(value) > 32 or not CVE_RE.fullmatch(value):
        raise ValueError('Invalid CVE ID. Expected CVE-YYYY-NNNN (at least 4 digits).')
    return value.upper()

def validate_limit(value, maximum=100):
    if isinstance(value, bool):
        raise ValueError('Limit must be an integer from 1 to 100.')
    try:
        result = int(value)
    except (ValueError, TypeError, OverflowError):
        raise ValueError('Limit must be an integer from 1 to 100.') from None
    if isinstance(value, float) and not value.is_integer():
        raise ValueError('Limit must be an integer from 1 to 100.')
    if not 1 <= result <= maximum:
        raise ValueError(f'Limit must be between 1 and {maximum}.')
    return result

def validate_query(value):
    if not isinstance(value, str) or len(value) > 80:
        raise ValueError('Search query must be at most 80 characters.')
    value = value.strip()
    if not value or any(ord(c) < 32 for c in value):
        raise ValueError('Search query must contain printable characters.')
    return value

def fetch_catalog():
    ttl = max(60, int(os.getenv('CACHE_TTL_SECONDS', '900')))
    with _lock:
        if _cache['data'] is not None and time.monotonic() - _cache['at'] < ttl:
            return _cache['data']
        try:
            with httpx.Client(timeout=httpx.Timeout(12, connect=5), follow_redirects=False, trust_env=False) as client:
                response = client.get(CISA_URL, headers={'Accept': 'application/json', 'User-Agent': 'ThreatGuard-MCP/1.0'})
                response.raise_for_status()
                if len(response.content) > 15_000_000:
                    raise ServiceError('Upstream catalog exceeds maximum size.')
                data = response.json()
            if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
                raise ServiceError('Unexpected CISA catalog format.')
            _cache.update(data=data, at=time.monotonic())
            return data
        except (httpx.HTTPError, ValueError) as exc:
            if _cache['data'] is not None:
                return _cache['data']  # stale fallback on upstream outage
            raise ServiceError('Threat intelligence source temporarily unavailable.') from exc

def _clean(row):
    fields = ('cveID','vendorProject','product','vulnerabilityName','dateAdded','shortDescription',
              'requiredAction','dueDate','knownRansomwareCampaignUse','notes')
    return {key: str(row.get(key) or '')[:1500] for key in fields}

def latest(limit=20):
    n = validate_limit(limit)
    rows = fetch_catalog()['vulnerabilities']
    return [_clean(r) for r in sorted(rows, key=lambda x: str(x.get('dateAdded','')), reverse=True)[:n]]

def lookup(cve):
    cve = validate_cve(cve)
    for row in fetch_catalog()['vulnerabilities']:
        if str(row.get('cveID','')).upper() == cve:
            return _clean(row)
    return None

def search(query, limit=20):
    q = validate_query(query).casefold()
    n = validate_limit(limit)
    rows = fetch_catalog()['vulnerabilities']
    matches = [r for r in rows if q in ' '.join(str(r.get(k,'')) for k in
               ('cveID','vendorProject','product','vulnerabilityName','shortDescription')).casefold()]
    return [_clean(r) for r in sorted(matches, key=lambda x: str(x.get('dateAdded','')), reverse=True)[:n]]

def stats():
    rows = fetch_catalog()['vulnerabilities']
    vendors = len({str(r.get('vendorProject','')).casefold() for r in rows if r.get('vendorProject')})
    ransomware = sum(str(r.get('knownRansomwareCampaignUse','')).lower() == 'known' for r in rows)
    return {'total':len(rows), 'vendors':vendors, 'ransomware':ransomware,
            'updated':fetch_catalog().get('dateReleased','Unknown'), 'source':'CISA KEV'}
