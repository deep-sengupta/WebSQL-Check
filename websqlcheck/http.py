from dataclasses import dataclass
from statistics import median
import random
import time
from typing import Dict, Optional
import requests
from .data import USER_AGENTS

@dataclass
class HttpResult:
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    error: Optional[str] = None

class HttpClient:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None, headers: Optional[Dict[str, str]] = None, retries: int = 1, delay: float = 0.0, verify_tls: bool = True):
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.base_headers = dict(headers or {})
        self.retries = max(0, retries)
        self.delay = max(0.0, delay)
        self.verify_tls = verify_tls
        self.session = requests.Session()

    def request(self, method: str, url: str, params=None, data=None, json_data=None, headers=None) -> HttpResult:
        merged = dict(self.base_headers)
        merged.setdefault("User-Agent", random.choice(USER_AGENTS))
        merged.update(headers or {})
        last_error = None
        for attempt in range(self.retries + 1):
            if self.delay:
                time.sleep(self.delay)
            started = time.perf_counter()
            try:
                r = self.session.request(method=method.upper(), url=url, params=params, data=data, json=json_data, headers=merged, timeout=self.timeout, proxies=self.proxies, verify=self.verify_tls, allow_redirects=True)
                return HttpResult(r.url, r.status_code, dict(r.headers), r.text, time.perf_counter() - started)
            except requests.RequestException as exc:
                last_error = str(exc)
                if attempt < self.retries:
                    time.sleep(min(2 ** attempt, 4))
        return HttpResult(url, 0, {}, "", 0.0, last_error)

def timing_threshold(baseline_samples):
    if not baseline_samples:
        return 3.0
    m = median(baseline_samples)
    spread = max(baseline_samples) - min(baseline_samples)
    return max(2.5, m + spread * 1.5 + 1.0)
