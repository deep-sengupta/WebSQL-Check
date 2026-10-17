import gzip
import socket
import threading
import time

import pytest

from websqlcheck.cli import render_finding
from websqlcheck.detectors import ErrorDetector, Finding, MAX_ANALYSIS_CHARS, signature_hits
from websqlcheck.engine import ScanConfig, Scanner
from websqlcheck.http import HttpClient, HttpResult
from websqlcheck.request import Target
from websqlcheck.scope import Scope

SECRET = {"Authorization": "Bearer SECRET", "Cookie": "sid=SECRET", "X-Api-Key": "SECRET", "Host": "stale.example"}
SQL_ERROR = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"


def client(**kw):
    args = dict(timeout=3, proxy=None, headers={}, retries=0, delay=0.0, verify_tls=True, scope_check=None)
    args.update(kw)
    return HttpClient(args.pop("timeout"), args.pop("proxy"), args.pop("headers"), args.pop("retries"), args.pop("delay"),
                      args.pop("verify_tls"), args.pop("scope_check"), **args)


def test_default_policy_never_leaves_the_origin(make_server):
    other = make_server({"*": (200, {}, b"ok")})
    origin = make_server({"/start": (302, {"Location": other.url("/steal")}, b"")})
    result = client(headers=SECRET).request("GET", origin.url("/start"))
    assert "outside scope" in (result.error or "")
    assert other.seen == []


def test_opted_in_cross_origin_redirect_drops_all_credentials(make_server):
    other = make_server({"*": (200, {}, b"ok")})
    origin = make_server({"/start": (302, {"Location": other.url("/next")}, b"")})
    result = client(headers=SECRET, scope_check=Scope.parse(["127.0.0.1"]).allows).request("GET", origin.url("/start"))
    assert result.status == 200
    headers = other.seen[0][2]
    for leaked in ("authorization", "cookie", "x-api-key"):
        assert leaked not in headers
    assert headers["host"] == f"127.0.0.1:{other.port}"


def test_cross_origin_307_never_replays_the_body(make_server):
    other = make_server({"*": (200, {}, b"ok")})
    origin = make_server({"/login": (307, {"Location": other.url("/x")}, b"")})
    result = client(scope_check=Scope.parse(["127.0.0.1"]).allows).request("POST", origin.url("/login"), data="password=hunter2")
    assert "replay request body" in (result.error or "")
    assert other.seen == []


def test_same_origin_redirect_keeps_headers_and_drops_body_headers_on_get(make_server):
    srv = make_server({"/start": (302, {"Location": "/final"}, b""), "/final": (200, {}, b"ok")})
    client(headers={"Authorization": "Bearer A", "Content-Length": "9", "Content-Type": "application/x-www-form-urlencoded"},
           scope_check=Scope.parse(["127.0.0.1"]).allows).request("POST", srv.url("/start"), data="a=b")
    method, path, headers, body = srv.seen[-1]
    assert (method, path, body) == ("GET", "/final", b"")
    assert headers["authorization"] == "Bearer A"
    assert "content-length" not in headers and "content-type" not in headers


def test_scanner_skips_out_of_scope_targets_and_says_so(make_server):
    srv = make_server({"*": (200, {}, b"ok")})
    scanner = Scanner(ScanConfig(techniques=("error",), scope="example.com", workers=1, retries=0))
    assert scanner.scan([Target(srv.url("/p?id=1"))]) == []
    assert srv.seen == []
    assert any("outside the scope" in err[-1] for err in scanner.errors)


def _reply(handler, text, status=200):
    payload = text.encode()
    handler.send_response(status)
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def test_default_scope_scans_ip_literal_targets(make_server):
    srv = make_server({"*": lambda h: _reply(h, SQL_ERROR if "%27" in h.path or "'" in h.path else "fine")})
    scanner = Scanner(ScanConfig(techniques=("error",), workers=1, retries=0, baseline_requests=1))
    findings = scanner.scan([Target(srv.url("/p?id=1"))])
    assert findings and {f.technique for f in findings} == {"error"}


def test_huge_body_is_capped(make_server):
    srv = make_server({"/big": (200, {}, b"A" * (6 * 1024 * 1024))})
    result = client(max_bytes=1024 * 1024).request("GET", srv.url("/big"))
    assert result.truncated and len(result.body) == 1024 * 1024 and result.error is None


def test_gzip_bomb_is_capped(make_server):
    bomb = gzip.compress(b"\0" * (20 * 1024 * 1024), compresslevel=9)
    srv = make_server({"/bomb": (200, {"Content-Encoding": "gzip"}, bomb)})
    result = client(max_bytes=1024 * 1024).request("GET", srv.url("/bomb"))
    assert result.truncated and len(result.body) == 1024 * 1024


def test_slow_drip_body_hits_the_wall_clock_deadline(make_server):
    def drip(handler):
        handler.send_response(200)
        handler.send_header("Content-Length", "1000000")
        handler.end_headers()
        try:
            for _ in range(200):
                handler.wfile.write(b"x")
                handler.wfile.flush()
                time.sleep(0.1)
        except OSError:
            pass
    srv = make_server({"/drip": drip})
    c = client(timeout=2)
    c.exchange_deadline = 1.5
    started = time.time()
    result = c.request("GET", srv.url("/drip"))
    assert "not complete within" in (result.error or "")
    assert time.time() - started < 5


def test_slow_drip_headers_hit_the_wall_clock_deadline():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        try:
            conn.recv(65536)
            for byte in b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 100:
                conn.send(bytes([byte]))
                time.sleep(0.01)
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    c = client(timeout=2)
    c.exchange_deadline = 0.3
    started = time.time()
    result = c.request("GET", f"http://127.0.0.1:{port}/")
    listener.close()
    assert "not complete within" in (result.error or "")
    assert time.time() - started < 5


def test_slow_but_honest_response_is_not_cut(make_server):
    srv = make_server({"/slow": lambda h: (time.sleep(0.2), _reply(h, "done"))})
    c = client(timeout=3)
    assert c.request("GET", srv.url("/slow")).body == "done"


@pytest.mark.parametrize("token", ["Exception ", "Warning ", "SQL Server ", "Driver ", "!12345! ", "PostgreSQL ", "Sybase "])
def test_signature_matching_cost_is_bounded(token):
    body = token * (1024 * 1024 // len(token))
    started = time.perf_counter()
    signature_hits(body)
    assert time.perf_counter() - started < 5


def test_only_the_analysis_window_is_matched():
    late = "x" * (MAX_ANALYSIS_CHARS + 10) + SQL_ERROR
    assert signature_hits(late) == frozenset()
    assert signature_hits("x" * 100 + SQL_ERROR)


def test_error_already_in_baseline_is_not_a_finding():
    detector = ErrorDetector()
    baseline = HttpResult("u", 200, {}, SQL_ERROR, 0.1)
    assert detector.detect(detector.baseline_hits(baseline), HttpResult("u", 200, {}, SQL_ERROR, 0.1), "id", "'") == []
    clean = HttpResult("u", 200, {}, "fine", 0.1)
    assert detector.detect(detector.baseline_hits(clean), HttpResult("u", 200, {}, SQL_ERROR, 0.1), "id", "'")


@pytest.mark.parametrize("parameter,url", [("user[email]", "http://t/a?user[email]=1"), ("file", "http://t/v?f=[/etc/passwd]"), ("x", "http://t/[/bold]")])
def test_render_finding_never_parses_markup(parameter, url):
    text = render_finding(Finding("error", parameter, "'", url, "high", 0.7, {}))
    assert parameter in text.plain and url in text.plain
