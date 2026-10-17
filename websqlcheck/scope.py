from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List, Optional, Tuple

import requests
from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url

DEFAULT_PORTS = {"http": 80, "https": 443}
_HOSTNAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$")


class ScopeError(ValueError):
    pass


def split_url(url: str) -> Optional[Tuple[str, str, int]]:
    try:
        prepared = requests.Request("GET", url).prepare().url
        parsed = parse_url(prepared)
    except (requests.RequestException, LocationParseError, ValueError, UnicodeError):
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in DEFAULT_PORTS or not parsed.hostname:
        return None
    host = parsed.hostname.lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
        try:
            if "%" in host or ipaddress.ip_address(host).version != 6:
                return None
        except ValueError:
            return None
        return scheme, host, parsed.port or DEFAULT_PORTS[scheme]
    host = host.rstrip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            return None
    return scheme, host, parsed.port or DEFAULT_PORTS[scheme]


def same_origin(a: str, b: str, allow_https_upgrade: bool = True) -> bool:
    pa, pb = split_url(a), split_url(b)
    if pa is None or pb is None:
        return False
    if pa == pb:
        return True
    return bool(
        allow_https_upgrade
        and pa[0] == "http" and pa[2] == 80
        and pb[0] == "https" and pb[2] == 443
        and pa[1] == pb[1]
    )


def _parse_rule(text: str):
    raw = text.strip().lower()
    if not raw:
        raise ScopeError("empty scope entry")
    if any(c in raw for c in ("://", "?", "#", "@", "\\", " ")):
        raise ScopeError(
            f"invalid scope entry {text!r}: use a hostname (example.com), a wildcard (*.example.com), "
            "host:port, an IP or a CIDR range - not a URL or regex"
        )
    if "/" in raw:
        try:
            return ("net", ipaddress.ip_network(raw, strict=False), None)
        except ValueError as exc:
            raise ScopeError(f"invalid CIDR in scope entry {text!r}: {exc}") from None
    host, port_text = raw, None
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise ScopeError(f"invalid IPv6 scope entry {text!r}")
        host, rest = raw[1:end], raw[end + 1:]
        if rest:
            if not rest.startswith(":"):
                raise ScopeError(f"invalid IPv6 scope entry {text!r}")
            port_text = rest[1:]
    elif raw.count(":") == 1:
        host, port_text = raw.split(":")
    port = None
    if port_text is not None:
        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            raise ScopeError(f"invalid port in scope entry {text!r}")
        port = int(port_text)
    if host.startswith("*."):
        suffix = host[1:]
        if "*" in suffix or not _HOSTNAME_RE.match(suffix[1:] or "!"):
            raise ScopeError(f"invalid wildcard in scope entry {text!r} (only a leading '*.' is allowed)")
        return ("suffix", suffix, port)
    if "*" in host:
        raise ScopeError(f"invalid wildcard in scope entry {text!r} (only a leading '*.' is allowed)")
    try:
        ip = ipaddress.ip_address(host)
        return ("net", ipaddress.ip_network(ip), port)
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(host.rstrip(".")):
        raise ScopeError(f"invalid hostname in scope entry {text!r}")
    return ("exact", host.rstrip("."), port)


class Scope:
    def __init__(self, rules: Iterable[Tuple[str, object, Optional[int]]]):
        self._rules: List[Tuple[str, object, Optional[int]]] = list(rules)

    @classmethod
    def parse(cls, specs: Iterable[str]) -> "Scope":
        rules = []
        for spec in specs:
            for part in str(spec).split(","):
                if part.strip():
                    rules.append(_parse_rule(part))
        if not rules:
            raise ScopeError("--scope was given but contains no entries")
        return cls(rules)

    @classmethod
    def from_targets(cls, urls: Iterable[str]) -> "Scope":
        rules = []
        for url in urls:
            parts = split_url(url)
            if parts is None:
                continue
            try:
                rules.append(("net", ipaddress.ip_network(parts[1]), None))
            except ValueError:
                rules.append(("exact", parts[1], None))
        return cls(rules)

    def allows(self, url: str) -> bool:
        parts = split_url(url)
        if parts is None:
            return False
        _, host, port = parts
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        for kind, value, rule_port in self._rules:
            if rule_port is not None and rule_port != port:
                continue
            if kind == "exact" and ip is None and host == value:
                return True
            if kind == "suffix" and ip is None and host.endswith(value) and len(host) > len(value):
                return True
            if kind == "net" and ip is not None and ip.version == value.version and ip in value:
                return True
        return False

    __call__ = allows

    def describe(self) -> str:
        out = []
        for kind, value, port in self._rules:
            text = {"suffix": f"*{value}"}.get(kind, str(value))
            out.append(f"{text}:{port}" if port else text)
        return ", ".join(dict.fromkeys(out)) or "(nothing)"
