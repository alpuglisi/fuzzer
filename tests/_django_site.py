"""Shared assertions for PicTrail's browsable site (CC-LAB-0242 / FR-LAB-160,
`docs/LAB_LANE2_DJANGO_PICTRAIL_PLAN.md` §5 step 2's per-page gate), used by
every `test_labgen_django_live_boot_picktrail*.py` module and the django
navigability test. Not a test module itself (leading underscore)."""

from __future__ import annotations

#: The one nav link every page rendered inside `layouts/site.html` carries,
#: and its footer text -- the "renders inside the shared layout" markers.
LAYOUT_NAV_MARKER = '<a href="/explore">Explore</a>'
LAYOUT_FOOTER_MARKER = "PicTrail &mdash; lab-only, authorized-testing target."

#: R3 (CC-LAB-0242): `/post`'s designed, literal found/not-found HTML byte
#: delta floor. Independently chosen (not re-derived from
#: `SqliBooleanStrategy._similar`'s formula), sized against PicTrail's own
#: measured page size (live, 2026-09-25): a found `/post` page is 2,443
#: bytes and a not-found page 1,874 bytes -- a 569-byte designed delta --
#: so the strategy's own 5%-of-max-length threshold is ~122 bytes here. 300
#: keeps ~2.5x headroom over that threshold (and the designed 569 keeps ~1.9x
#: over the 300 floor). Coincidentally the same floor CC-LAB-0240 chose for
#: `php_laravel`'s ~1.9 KB layout, re-derived here against PicTrail's own
#: ~1.8 KB layout rather than reused.
MIN_FOUND_NOT_FOUND_DELTA = 300


def assert_in_picktrail_layout(resp, title: str) -> None:
    """The response is a full page rendered inside PicTrail's shared layout
    (`{% extends "layouts/site.html" %}`): doctype, `<title>`, nav, footer --
    never a bare fragment or a JSON body."""
    assert resp.body.lstrip().startswith("<!DOCTYPE html>"), resp.body[:300]
    assert f"<title>{title}</title>" in resp.body, resp.body[:800]
    assert LAYOUT_NAV_MARKER in resp.body, resp.body[:2000]
    assert LAYOUT_FOOTER_MARKER in resp.body, resp.body[-600:]


def assert_bare_get_gate(harness, vuln_url: str, twin_url: str, *, status: int, title: str | None) -> None:
    """§5 step 2's per-page gate, (i) + (ii), plus R1's twin comparison:
    a bare `GET` (no query, no body) of the page's vulnerable URL and of its
    secure twin's own twin-suffixed URL both return the decided absent-input
    status (never a 500); when ``title`` is given the page renders inside the
    shared layout; and the two twins' bodies are byte-identical (the layout
    cannot leak which twin is which -- R1, branch (a))."""
    vuln = harness.get(vuln_url)
    twin = harness.get(twin_url)
    assert vuln.status == status, (vuln_url, vuln.status, vuln.body[:500])
    assert twin.status == status, (twin_url, twin.status, twin.body[:500])
    if title is not None:
        assert_in_picktrail_layout(vuln, title)
        assert_in_picktrail_layout(twin, title)
    assert vuln.body == twin.body, (vuln_url, twin_url, vuln.body[:800], twin.body[:800])


def found_not_found_delta(harness, url: str, param: str, *, found: str, not_found: str) -> int:
    """R3: fetch ``url`` in its found and not-found states and return the
    literal byte-length difference of the served HTML bodies."""
    found_resp = harness.get(url, params={param: found})
    missing_resp = harness.get(url, params={param: not_found})
    assert found_resp.status == 200, (url, found_resp.body[:500])
    assert missing_resp.status == 404, (url, missing_resp.status, missing_resp.body[:500])
    assert "Post not found." in missing_resp.body, (url, missing_resp.body[:2000])
    assert "Post not found." not in found_resp.body, (url, found_resp.body[:2000])
    delta = len(found_resp.body.encode("utf-8")) - len(missing_resp.body.encode("utf-8"))
    print(
        f"R3 found/not-found {url}: found={len(found_resp.body.encode('utf-8'))} "
        f"not_found={len(missing_resp.body.encode('utf-8'))} delta={delta} bytes"
    )
    return delta
