"""Strict request-head parsing for multi-tenant routing (F12 / F60).

``_host_from_head`` is the back-end half of PortSwigger's desync defense: because
chute forwards the head verbatim and cannot normalize, it MUST reject any request a
downstream hop could parse differently. These tests pin each RFC-mandated reject
(obs-fold, whitespace-before-colon, duplicate/missing/invalid Host, bare LF,
non-origin-form target) and confirm a clean request still parses -- closing the
parser-differential / smuggling primitives the lenient first-Host-wins parser left
open (CVE-2019-16276 is the same class of bug in Go's net/http).
"""

from __future__ import annotations

import pytest

from chute.server import _BadRequest, _host_from_head, _parse_request_head


def _head(*lines: str) -> bytes:
    """Join field lines with CRLF and terminate with the blank line, exactly as
    ``reader.readuntil(b"\\r\\n\\r\\n")`` delivers it. ``lines[0]`` is the request line."""
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


# -- accepted: a well-formed request still routes -----------------------------
def test_plain_host_parsed() -> None:
    assert _host_from_head(_head("GET / HTTP/1.1", "Host: alpha.chute.sh")) == "alpha.chute.sh"


def test_port_is_stripped() -> None:
    assert _host_from_head(_head("GET / HTTP/1.1", "Host: alpha.chute.sh:8443")) == "alpha.chute.sh"


def test_max_valid_port_is_stripped() -> None:
    # A well-formed port (1-5 digits, <=65535) is stripped; only a malformed one is 400.
    assert _host_from_head(_head("GET / HTTP/1.1", "Host: a.chute.sh:65535")) == "a.chute.sh"


def test_ows_around_value_is_trimmed() -> None:
    assert _host_from_head(_head("GET / HTTP/1.1", "Host:  alpha.chute.sh\t")) == "alpha.chute.sh"


def test_field_name_is_case_insensitive() -> None:
    assert _host_from_head(_head("GET / HTTP/1.1", "hOsT: alpha.chute.sh")) == "alpha.chute.sh"


def test_surrounding_headers_are_ignored() -> None:
    head = _head("GET /x HTTP/1.1", "User-Agent: curl/8", "Host: a.chute.sh", "Accept: */*")
    assert _host_from_head(head) == "a.chute.sh"


def test_asterisk_form_target_is_allowed() -> None:
    assert _host_from_head(_head("OPTIONS * HTTP/1.1", "Host: a.chute.sh")) == "a.chute.sh"


def test_scheme_in_query_is_not_absolute_form() -> None:
    # A "://" inside the query must NOT be mistaken for an absolute-form target.
    head = _head("GET /r?u=http://x.test/ HTTP/1.1", "Host: a.chute.sh")
    assert _host_from_head(head) == "a.chute.sh"


def test_default_route_accepts_http10_without_host() -> None:
    assert _parse_request_head(_head("GET /legacy HTTP/1.0"), require_host=False).host is None


def test_default_route_rejects_http11_without_host() -> None:
    with pytest.raises(_BadRequest):
        _parse_request_head(_head("GET / HTTP/1.1"), require_host=False)


# -- rejected: each is a parser differential / smuggling primitive ------------
@pytest.mark.parametrize(
    ("lines", "why"),
    [
        (("GET", "Host: a.chute.sh"), "request line needs exactly 3 tokens"),
        (("GET /", "Host: a.chute.sh"), "request line missing version"),
        (("GET / HTTP/1.1 extra", "Host: a.chute.sh"), "request line has extra token"),
        (("GET / HTTP/2.0", "Host: a.chute.sh"), "unsupported HTTP version"),
        (("GET  / HTTP/1.1", "Host: a.chute.sh"), "double-space request line"),
        (("GET *garbage HTTP/1.1", "Host: a.chute.sh"), "bad asterisk-form target"),
        (("GET / HTTP/1.1",), "missing Host (RFC 9110 §7.2)"),
        (("GET / HTTP/1.1", "Host: a.chute.sh", "Host: b.chute.sh"), "duplicate Host (§7.2)"),
        (("GET / HTTP/1.1", "Host : a.chute.sh"), "whitespace before colon (RFC 9112 §5.1)"),
        (("GET / HTTP/1.1", "Host:"), "empty Host value (§7.2)"),
        (("GET / HTTP/1.1", "Host:   "), "whitespace-only Host value"),
        (("GET / HTTP/1.1", "X-Foo: bar", "\tHost: a.chute.sh"), "obs-fold continuation (§5.2)"),
        (("GET / HTTP/1.1", " Host: a.chute.sh"), "leading-space (obs-fold) line"),
        (("GET http://b.chute.sh/ HTTP/1.1", "Host: a.chute.sh"), "absolute-form target (§3.2.2)"),
        (("GET / HTTP/1.1", "Host: a .chute.sh"), "space inside Host value"),
        (("GET / HTTP/1.1", "Host: a\x00.chute.sh"), "control char in Host value"),
        (
            ("GET / HTTP/1.1", "Bare-LF: x\nHost: a.chute.sh"),
            "bare LF in head (cf. CVE-2025-22871)",
        ),
        (("GET / HTTP/1.1", "Malformed-no-colon"), "field line without a colon"),
        (("GET / HTTP/1.1", "Host: a.chute.sh:notaport"), "non-numeric port (§7.2)"),
        (("GET / HTTP/1.1", "Host: a.chute.sh:"), "empty port"),
        (("GET / HTTP/1.1", "Host: a.chute.sh:-1"), "negative port"),
        (("GET / HTTP/1.1", "Host: a.chute.sh:999999999999"), "out-of-range port"),
    ],
)
def test_rejected(lines: tuple[str, ...], why: str) -> None:
    with pytest.raises(_BadRequest):
        _host_from_head(_head(*lines))


def test_first_of_duplicate_host_is_not_silently_chosen() -> None:
    # The old lenient parser returned the FIRST Host; a smuggler put their target
    # first and the app saw the second. We must reject, not pick a side.
    head = _head("GET / HTTP/1.1", "Host: attacker.chute.sh", "Host: victim.chute.sh")
    with pytest.raises(_BadRequest):
        _host_from_head(head)
