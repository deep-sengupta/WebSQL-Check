from dataclasses import dataclass
from statistics import median
from urllib.parse import urljoin
import random
import socket
import threading
import time
from typing import Callable, Dict, Optional
import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from .data import USER_AGENTS
from .scope import same_origin, split_url

DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_REDIRECTS = 10
SAFE_CROSS_ORIGIN_HEADERS = {"user-agent", "accept", "accept-language", "accept-encoding"}
BODY_HEADERS = {"content-length", "content-type", "content-encoding", "transfer-encoding"}


@dataclass
class HttpResult:
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    error: Optional[str] = None
    truncated: bool = False


def _redirect_method(status: int, method: str) -> str:
    if status == 303 and method != "HEAD":
        return "GET"
    if status == 302 and method != "HEAD":
        return "GET"
    if status == 301 and method == "POST":
        return "GET"
    return method


def _redirect_headers(headers, cross_origin: bool, drop_body_headers: bool) -> CaseInsensitiveDict:
    out = CaseInsensitiveDict()
    for key, value in headers.items():
        lowered = key.lower()
        if cross_origin and lowered not in SAFE_CROSS_ORIGIN_HEADERS:
            continue
        if drop_body_headers and lowered in BODY_HEADERS:
            continue
        out[key] = value
    return out


_active = threading.local()


class _Guard:
    def __init__(self):
        self.expired = threading.Event()
        self._lock = threading.Lock()
        self._socks, self._conns = [], []

    def add_sock(self, sock):
        with self._lock:
            self._socks.append(sock)

    def add_conn(self, conn):
        with self._lock:
            if conn not in self._conns:
                self._conns.append(conn)

    def abort(self):
        self.expired.set()
        with self._lock:
            targets = list(self._socks) + [getattr(conn, "sock", None) for conn in self._conns]
        for sock in targets:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


class _GuardedConnection:
    def _new_conn(self):
        sock = super()._new_conn()
        guard = getattr(_active, "guard", None)
        if guard is not None:
            guard.add_sock(sock)
        return sock

    def request(self, *args, **kwargs):
        guard = getattr(_active, "guard", None)
        if guard is not None:
            guard.add_conn(self)
        return super().request(*args, **kwargs)


class _GuardedHTTPConnection(_GuardedConnection, HTTPConnection):
    pass


class _GuardedHTTPSConnection(_GuardedConnection, HTTPSConnection):
    pass


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


_GUARDED_POOLS = {"http": _GuardedHTTPPool, "https": _GuardedHTTPSPool}


class _GuardedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = _GUARDED_POOLS

    def proxy_manager_for(self, proxy, **kwargs):
        manager = super().proxy_manager_for(proxy, **kwargs)
        manager.pool_classes_by_scheme = _GUARDED_POOLS
        return manager


class HttpClient:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None, headers: Optional[Dict[str, str]] = None, retries: int = 1, delay: float = 0.0, verify_tls: bool = True, scope_check: Optional[Callable[[str], bool]] = None, max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES, max_redirects: int = DEFAULT_MAX_REDIRECTS):
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.base_headers = dict(headers or {})
        self.retries = max(0, retries)
        self.delay = max(0.0, delay)
        self.verify_tls = verify_tls
        self.scope_check = scope_check
        self.max_bytes = max(1024, int(max_bytes))
        self.max_redirects = max(0, max_redirects)
        self.exchange_deadline = max(self.timeout * 3, 5)
        self.session = requests.Session()
        adapter = _GuardedAdapter()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _redirect_allowed(self, from_url: str, to_url: str) -> bool:
        if self.scope_check is not None:
            return bool(self.scope_check(to_url))
        return same_origin(from_url, to_url)

    def _read_body(self, response: requests.Response):
        chunks, size, truncated = [], 0, False
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            room = self.max_bytes - size
            if len(chunk) > room:
                chunks.append(chunk[:room])
                truncated = True
                break
            chunks.append(chunk)
            size += len(chunk)
        raw = b"".join(chunks)
        try:
            text = raw.decode(response.encoding or "utf-8", errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        return text, truncated

    def request(self, method: str, url: str, params=None, data=None, json_data=None, headers=None) -> HttpResult:
        merged = CaseInsensitiveDict(self.base_headers)
        if "User-Agent" not in merged:
            merged["User-Agent"] = random.choice(USER_AGENTS)
        merged.update(headers or {})
        if self.scope_check is not None and not self.scope_check(url):
            return HttpResult(url, 0, {}, "", 0.0, "request blocked: target outside scope")
        last_error = None
        for attempt in range(self.retries + 1):
            if self.delay:
                time.sleep(self.delay)
            started = time.perf_counter()
            try:
                return self._send(method.upper(), url, params, data, json_data, merged, started)
            except requests.RequestException as exc:
                last_error = str(exc)
                if attempt < self.retries:
                    time.sleep(min(2 ** attempt, 4))
        return HttpResult(url, 0, {}, "", 0.0, last_error)

    def _send(self, method, url, params, data, json_data, headers, started) -> HttpResult:
        guard = _Guard()
        _active.guard = guard
        timer = threading.Timer(max((started + self.exchange_deadline) - time.perf_counter(), 0.001), guard.abort)
        timer.daemon = True
        timer.start()
        try:
            result = self._send_inner(method, url, params, data, json_data, headers, started)
        except (requests.exceptions.RequestException, OSError):
            if guard.expired.is_set():
                raise requests.exceptions.ReadTimeout(f"request not complete within {self.exchange_deadline}s") from None
            raise
        finally:
            timer.cancel()
            _active.guard = None
        if guard.expired.is_set():
            raise requests.exceptions.ReadTimeout(f"request not complete within {self.exchange_deadline}s")
        return result

    def _send_inner(self, method, url, params, data, json_data, headers, started) -> HttpResult:
        current_url, current_method = url, method
        current_headers, current_params = headers, params
        current_data, current_json = data, json_data
        for _ in range(self.max_redirects + 1):
            r = self.session.request(method=current_method, url=current_url, params=current_params, data=current_data, json=current_json, headers=current_headers, timeout=self.timeout, proxies=self.proxies, verify=self.verify_tls, allow_redirects=False, stream=True)
            try:
                location = r.headers.get("Location") if r.is_redirect else None
                if not location:
                    body, truncated = self._read_body(r)
                    return HttpResult(r.url, r.status_code, dict(r.headers), body, time.perf_counter() - started, None, truncated)
                next_url = urljoin(r.url, location)
                if not self._redirect_allowed(r.url, next_url):
                    parts = split_url(next_url)
                    where = f"{parts[0]}://{parts[1]}:{parts[2]}" if parts else "an invalid URL"
                    body, truncated = self._read_body(r)
                    return HttpResult(next_url, r.status_code, dict(r.headers), body, time.perf_counter() - started, f"redirect blocked: {where} is outside scope (add it with --scope to allow it)", truncated)
                cross_origin = not same_origin(r.url, next_url)
                new_method = _redirect_method(r.status_code, current_method)
                body_dropped = new_method != current_method
                if cross_origin and not body_dropped and (current_data is not None or current_json is not None):
                    return HttpResult(next_url, r.status_code, dict(r.headers), "", time.perf_counter() - started, "redirect blocked: would replay request body to a different origin")
                current_headers = _redirect_headers(current_headers, cross_origin, body_dropped)
                if body_dropped:
                    current_data = current_json = None
                current_url, current_method, current_params = next_url, new_method, None
            finally:
                r.close()
        return HttpResult(current_url, 0, {}, "", time.perf_counter() - started, "too many redirects")


def timing_threshold(baseline_samples):
    if not baseline_samples:
        return 3.0
    m = median(baseline_samples)
    spread = max(baseline_samples) - min(baseline_samples)
    return max(2.5, m + spread * 1.5 + 1.0)
