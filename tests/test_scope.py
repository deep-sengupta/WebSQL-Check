import pytest
from websqlcheck.scope import Scope, ScopeError, same_origin

EXACT = Scope.parse(["example.com"])


@pytest.mark.parametrize("url", [
    "https://example.com/a", "http://EXAMPLE.com./x", "http://example.com:8080/", "http://user:pw@example.com/p?q=1",
])
def test_exact_allows(url):
    assert EXACT.allows(url)


@pytest.mark.parametrize("url", [
    "https://evil.test/?ref=example.com",
    "https://evil.test/example.com",
    "https://example.com.evil.test/",
    "https://notexample.com/",
    "https://exampleXcom.test/",
    "http://example.com@evil.test/",
    "http://evil.test#@example.com/",
    "http://evil.test?@example.com/",
    "http://evil.test\\@example.com/",
    "http://example.com%2eevil.test/",
    "//example.com/x", "example.com/x", "ftp://example.com/", "file:///etc/passwd", "http:///example.com", "",
    "http://sub.example.com/",
])
def test_exact_denies(url):
    assert not EXACT.allows(url)


def test_wildcard_matches_subdomains_only():
    scope = Scope.parse(["*.example.com"])
    assert scope.allows("https://a.example.com/") and scope.allows("https://a.b.example.com/")
    assert not scope.allows("https://example.com/")
    assert not scope.allows("https://badexample.com/")
    assert not scope.allows("https://example.com.evil.test/")


def test_port_rule():
    scope = Scope.parse(["example.com:8443"])
    assert scope.allows("https://example.com:8443/")
    assert not scope.allows("https://example.com/")


def test_cidr_and_ip_rules():
    scope = Scope.parse(["10.0.0.0/24", "192.168.1.5", "[::1]:8080"])
    assert scope.allows("http://10.0.0.7/") and scope.allows("http://192.168.1.5/") and scope.allows("http://[::1]:8080/")
    assert not scope.allows("http://10.0.1.7/") and not scope.allows("http://192.168.1.6/") and not scope.allows("http://[::1]:9/")
    assert not scope.allows("http://10.0.0.7.evil.test/")


def test_comma_separated_and_describe():
    scope = Scope.parse(["a.com, *.b.org", "c.net"])
    assert scope.allows("http://a.com/") and scope.allows("http://x.b.org/") and scope.allows("http://c.net/")
    assert "a.com" in scope.describe() and "*.b.org" in scope.describe()


@pytest.mark.parametrize("bad", ["", "https://example.com", "example.com/path", "exa*mple.com", "*.", "ex ample.com",
                                 "example.com:99999", "(", "example.com@evil", "example.com\\x", "10.0.0.0/99"])
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(ScopeError):
        Scope.parse([bad])


def test_default_scope_is_the_scanned_hosts():
    scope = Scope.from_targets(["http://a.com/x?id=1", "https://b.org:8443/", "not a url"])
    assert scope.allows("https://a.com:444/") and scope.allows("http://b.org/")
    assert not scope.allows("http://c.com/")


def test_same_origin_rules():
    assert same_origin("http://a.com/x", "http://a.com/y")
    assert same_origin("http://a.com/", "https://a.com/")
    assert not same_origin("https://a.com/", "http://a.com/")
    assert not same_origin("http://a.com/", "http://a.com:8080/")
    assert not same_origin("http://a.com/", "http://b.com/")


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080/a", "http://192.168.1.10/", "http://[::1]:8080/x", "https://[2001:db8::1]/"])
def test_default_scope_covers_ip_literal_targets(url):
    assert Scope.from_targets([url]).allows(url)
    assert not Scope.from_targets([url]).allows("http://10.99.99.99/")


@pytest.mark.parametrize("url,expected", [
    ("http://[::1]:8080/", ("http", "::1", 8080)),
    ("https://[2001:db8::1]/x", ("https", "2001:db8::1", 443)),
    ("http://[fe80::1%25eth0]/", None),
    ("http://[bad]/", None),
])
def test_ipv6_literals(url, expected):
    from websqlcheck.scope import split_url
    assert split_url(url) == expected
