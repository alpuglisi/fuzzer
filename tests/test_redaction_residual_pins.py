"""BUG-0556's residuals after the owner's final round, each pinned by a strict xfail
(PA-0054(3), PA-0531(4)): the fix check of review round 2 (111b6fb) found the round's
repros fixed and these neighbouring paths still open. The owner's rule for the final
round: anything found after it is pinned, never fixed in another round -- except a
regression the batch itself introduced, which is fixed in the batch (PA-0549(3c); those
are in `tests/test_redaction_nested.py`, "after the owner's final round", with N1 (B),
fixed by the same mechanism as one of them).

Each pin is real code asserting the behaviour the residual lacks, so it fails today on
its stated assertion (``raises=AssertionError``: a failure of any other kind is a
failure of the pin) and passes, failing the strict xfail, once its owner fixes it. Each
reason names BUG-0556, the finding and the owner.
"""

from __future__ import annotations

import re
from urllib.parse import quote

import pytest

from fuzzlab.core import redaction as R
from fuzzlab.core.store import Store
from tests.test_redaction_nested import (_PASS, _WORD, _SilentFetcher, _audit_findings,
                                         _dump, _import_audit_or_failure, _leaks,
                                         _linearity_violations, _spider_db)


def _both_redactors_kept(url: str, secret: str) -> list[str]:
    """The URL redactors that kept ``secret`` in ``url`` (any decoding of their output)."""
    return [fn.__name__ for fn in (R.redact_url, R.redact_url_identifiers)
            if _leaks(fn(url), secret)]


def _stored(tmp_path, urls) -> str:
    """Every table of a store `import_spider` wrote from the spider's rows of ``urls``."""
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", urls)
    with Store(tmp_path / "u.db") as store:
        import_spider(tmp_path / "s.db", store, store.start_run("auto", "h"))
        return _dump(store)


# --- N1 (A): an authority decoded from a layer is walked as a bare value ----------------
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round, N1 (A) (owner CORE, core.redaction "
    "`_UrlWalk.path`/`route`): a nested authority or a top-level fragment route's "
    "authority decoded from a layer is walked as a bare value, and `userinfo` reads an "
    "authority only after a scheme or '//', so `bob:<pw>@host` decoded from "
    "`bob%253A<pw>%2540host` or `#https://bob%3A<pw>%40host` is kept (on f939778 too)"))
@pytest.mark.parametrize("url", [
    f"http://h/app/q.php?u=bob&next=https://bob%253A{_PASS}%2540host%252Fx?y=1",
    f"http://h/app/#https://bob%3A{_PASS}%40host%2Fx?y=1",
    f"http://h/app/#//bob%3A{_PASS}%40host%2Fx?y=1",
    f"http://h/app/#https://bob%3A{_PASS}%40host",
])
def test_an_encoded_authoritys_userinfo_is_redacted(url):
    assert _leaks(url, _PASS)                                # not vacuous
    assert _both_redactors_kept(url, _PASS) == []


# --- N2 item 2: userinfo after a form-encoded space, a stripped tab or newline, %2F ------
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round, N2 item 2 (owner CORE, core.redaction "
    "`_AUTHORITY_AT`): the WHATWG parser reads a userinfo in `+https:bob:<pw>@`, "
    "`+http:/bob:<pw>@` (a '+' is a space in a query; the scheme lookbehind rejects it), "
    "`https:/%0A/` and `https:/%09/` (a tab or newline is removed) and `https:%2F/`, "
    "which `_AUTHORITY_AT` does not; kept by both redactors and stored by import_spider "
    "(on f939778 too)"))
@pytest.mark.parametrize("value", [
    f"+https:bob:{_PASS}@host/x", f"+http:/bob:{_PASS}@host/x",
    f"+https%3Abob%3A{_PASS}%40host%2Fx", f"https:/%0A/bob:{_PASS}@host/x",
    f"https:/%09/bob:{_PASS}@host/x", f"https:%2F/bob:{_PASS}@host/x?y=1",
])
def test_a_userinfo_the_whatwg_parser_reads_after_a_space_or_a_stripped_tab_is_redacted(
        value):
    url = f"http://h/app/p.php?u=bob&next={value}"
    assert _leaks(url, _PASS)                                # not vacuous
    assert _both_redactors_kept(url, _PASS) == []


# --- N2 item 3 (R3): a URL's userinfo in a top-level piece the walk keeps as identity -----
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual R3 after the final round, N2 item 3 (owner CORE, core.redaction "
    "`_UrlWalk.route`): the top-level fragment's raw route is the page's identity, so a "
    "URL's userinfo in it (`#/go/https://bob:<pw>@host/x`, `#https://bob:<pw>@...`) is "
    "kept by both redactors"))
@pytest.mark.parametrize("url", [
    f"http://h/app/p.php?u=bob#/go/https://bob:{_PASS}@host/x",
    f"http://h/app/p.php?u=bob#https://bob:{_PASS}@host/x",
])
def test_a_userinfo_in_the_top_level_fragment_route_is_redacted(url):
    assert _both_redactors_kept(url, _PASS) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual R3 after the final round, N2 item 3 (owners CORE and AUD: a "
    "pair's name is judged by the name rule only, and tools.store_adapter "
    "`import_spider` stores it as `parameter.name`): `out.php?https://bob:<pw>@host/x"
    "?a=1` and the nameless `out.php?https://bob:<pw>@host/x` (which both URL "
    "redactors redact as a value) store the password in `parameter.name`"))
@pytest.mark.parametrize("url", [
    f"http://h/app/out.php?https://bob:{_PASS}@host/x?a=1",
    f"http://h/app/out.php?https://bob:{_PASS}@host/x",
])
def test_a_userinfo_in_a_top_level_pair_name_is_never_stored(tmp_path, url):
    dump = _stored(tmp_path, [url])
    assert "/app/out.php" in dump                            # not vacuous
    assert not _leaks(dump, _PASS)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual R3 after the final round, N2 item 3 (owners CORE and AUD: a "
    "top-level path segment is the page's identity, never decoded, and "
    "tools.store_adapter `import_spider` stores it in `page` and `endpoint`): "
    "`/app/redirect/https%3A%2F%2Fbob%3A<pw>%40host%2Fx` keeps the password"))
def test_a_userinfo_in_a_top_level_path_segment_is_never_stored(tmp_path):
    url = f"http://h/app/redirect/https%3A%2F%2Fbob%3A{_PASS}%40host%2Fx?u=bob"
    dump = _stored(tmp_path, [url])
    assert "/app/redirect/" in dump                          # not vacuous
    assert not _leaks(dump, _PASS)


# --- the raw single-backslash spelling's value, decoded once (found in r3's sweep) ------
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round (owner CORE, core.redaction "
    "`_authority_start`): a value decoded once to `/\\host&token=<word>?y=1` is a URL "
    "whose `/\\` the WHATWG parser reads as an authority start and the walk reads as a "
    "path, so `value_holds_secret` is False and import_spider stores the token in "
    "`parameter.example` and `form.entries` (on f939778 too; the page URL's own walk is "
    "fixed, tests/test_redaction_nested.py)"))
def test_a_backslash_led_pair_list_decoded_once_is_held_secret(tmp_path):
    assert R.value_holds_secret(f"/\\host&token={_WORD}?y=1")
    dump = _stored(tmp_path, [f"http://h/app/p.php?u=bob&next=/\\host%26token%3D{_WORD}"
                              "?y=1"])
    assert not _leaks(dump, _WORD)


# --- the same value one layer down: the page URL's own walk (found by r4's skeptic) ------
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round, found by r4's skeptic (owner CORE, "
    "core.redaction `_authority_start`): `next=%2F%5Cx%26password%3D<word>` decodes once "
    "to `/\\x&password=<word>`, whose `/\\` Node 22's URL reads as an authority start "
    "(host `x&password=<word>`) and the walk reads as a path, so `redact_url` keeps the "
    "password; r4's measurement found the other '/'-led runs that are not exactly '//' "
    "(`///`, `/\\\\`, `/\\/`, `////`) the same (on f939778 too: not a regression)"))
@pytest.mark.parametrize("lead", ["/\\", "///", "/\\\\", "/\\/", "////"])
def test_a_slash_led_authoritys_pair_list_encoded_once_is_redacted_by_redact_url(lead):
    url = "http://h/app/p.php?u=bob&next=" + quote(f"{lead}x&password={_WORD}", safe="")
    assert _leaks(url, _WORD)                                # not vacuous
    assert not _leaks(R.redact_url(url), _WORD)


# --- r5: what the pushed tree (7393c90) kept too (the owner's shipping criterion) --------
# r5's differential (scratchpad/lanes/REDACTURL/r5b/: 214 352 secret-bearing URLs through
# every URL consumer, 7393c90 against the revision) found 78 135 URLs both keep a secret
# of; `r5b/assign.py` assigns every one to a family. Each family not already pinned above
# is pinned here (the owner's rule: a leak the pushed code also had is pinned, never
# fixed in another round); the rest are stated in BUG-0556 "r5" with their reason.
_BS = "\\"
_ON_7393 = "on 7393c90 too: not a regression against the pushed tree"


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual, class (a) of r4's skeptic (owner CORE, core.redaction "
    "`_UrlWalk.path`): a nested URL's path segments are decoded and split on ';' only, "
    "so a value led by `\\\\`, `\\/`, `\\\\\\`, `\\\\/`, `\\//`, `\\/\\` or `\\\\\\\\` (or "
    "`/`, `//`, a scheme, a URL nested in a segment) whose pair list sits in a later path "
    "segment (`\\\\x/p&password=<word>`) is never split into pairs; f939778 split such a "
    f"value into pairs (r5: 40 503 URLs of the differential; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    f"http://h/app/p.php?u=bob&next=%5C%5Cx%2Fp%26password%3D{_WORD}",
    f"http://h/app/p.php?u=bob&next=%5C%2Fx%2Fp%26token%3D{_WORD}",
    "http://h/app/p.php?u=bob&next=" + quote(f"{_BS * 2}x/a/b&password={_WORD}", safe="/"),
    f"http://h/app/p.php?u=bob&next={_BS * 2}x/p%26password%3D{_WORD}",
    f"http://h/app/#/r?next=%5C%5Cx%2Fp%26password%3D{_WORD}",
    "http://h/app/p.php?u=bob&next=" + quote(f"{_BS}//x/p&password={_WORD}", safe=""),
    "http://h/app/p.php?u=bob&next=" + quote(f"/x/p&password={_WORD}", safe=""),
    "http://h/app/p.php?u=bob&next=" + quote(f"/go/https://x&password={_WORD}", safe=""),
])
def test_a_pair_list_in_a_nested_urls_later_path_segment_is_redacted(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _both_redactors_kept(url, _WORD) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual, class (b) of r4's skeptic (owner CORE, core.redaction "
    "`_authority_start` / `_UrlWalk.route`): r4 starts a nested head's authority after its "
    "backslash run, so the top-level fragment route's `\\\\user%3A<pw>%40x` reaches "
    "`layer` without its lead; decoded, `user:<pw>@x` has no scheme or `//`, and "
    "`userinfo` never matches (20cd466 redacted the encoded spellings; the raw ones are "
    f"R3's identity; r5: 6 580 URLs; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    f"http://h/app/p.php#{_BS * 2}user%3A{_WORD}%40x%2Fp",
    f"http://h/app/p.php#{_BS * 2}user:{_WORD}%40x/p",
    f"http://h/app/p.php#{_BS * 2}user%3A{_WORD}%40x?a=1",
    f"http://h/app/p.php#{_BS * 2}user%3Acorrect%20{_WORD}%40x%2Fp",
    f"http://h/app/p.php#{_BS * 3}user%3A{_WORD}%40x%2Fp",
    f"http://h/app/p.php#{_BS * 4}user%3A{_WORD}%40x%2Fp",
    f"http://h/app/p.php?u=bob#{_BS * 2}user:{_WORD}@x",
])
def test_a_backslash_led_userinfo_in_the_top_level_fragment_is_redacted(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _both_redactors_kept(url, _WORD) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual (owner CORE, core.redaction `_UrlWalk.path`): a top-level path is "
    "split into segments on '/' before its ';' parameters are read, so a path "
    "parameter's value holding a raw '/' (`;next=//x&password=<word>/x`, "
    "`;next=/go/https://bob:<pw>@host`) is judged only up to its first '/' and the rest "
    f"is a segment of the page's identity (r5: 13 298 URLs; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    f"http://h/app/p.php;next=//x&password={_WORD}/x?u=bob",
    f"http://h/app/p.php;next=/go/https://bob:{_WORD}@host?u=bob",
    f"http://h/app/p.php;next=%20https://bob:{_WORD}@host?u=bob",
    f"http://h/app/p.php;next={_BS * 2}x/p&password={_WORD}?u=bob",
])
def test_a_path_parameter_value_holding_a_raw_slash_is_redacted(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _both_redactors_kept(url, _WORD) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual (owner CORE, core.redaction `_AUTHORITY_AT` / `_UrlWalk.userinfo`): "
    "a userinfo with no scheme, '//' or backslash before it (`next=bob:<pw>@host`, after "
    "a space `x bob:<pw>@host`) is not a URL to the walk, though the record redactor's "
    "`_BARE_USERINFO` calls it a credential at a piece's start "
    f"(r5: 2 365 URLs; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    f"http://h/app/p.php?u=bob&next=bob:{_WORD}@host",
    f"http://h/app/p.php?u=bob&next=bob%3Apw%20{_WORD}%40host%3Fy%3D1",
    f"http://h/app/#/r?next=bob:{_WORD}@host/x",
    f"http://h/app/p.php?u=bob&next=x%20bob%3A{_WORD}%40host",
])
def test_a_scheme_less_userinfo_in_a_value_is_redacted(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _both_redactors_kept(url, _WORD) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual (owner CORE, core.redaction `_UrlWalk.pairs`): a userinfo holding a "
    "raw '&' in a top-level query value (`next=//bob:p&w<pw>@host`) is cut by the query "
    "split, and the piece after the '&' is a nameless pair (`w<pw>@host`) with no "
    f"authority start, so its password is kept (r5: 910 URLs; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    f"http://h/app/p.php?u=bob&next=//bob:p&w{_WORD}@host",
    f"http://h/app/p.php?u=bob&next=https://bob:p&w{_WORD}@host/x",
    f"http://h/app/p.php?u=bob&next=bob:p&w{_WORD}@host",
])
def test_a_top_level_userinfo_holding_a_raw_amp_is_redacted(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _both_redactors_kept(url, _WORD) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual (owner CORE, core.redaction `_UrlWalk.fragment`): a top-level "
    "fragment is split at its first '?' into a route (the page's identity, never split "
    "into pairs) and a query, so a pair list before the '?' (`#token=<word>?y=1`, "
    "`#next=x&password=<word>?y=1`) is kept; 7393c90's record redactor split the "
    f"fragment the same way (r5: 864 URLs; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    f"http://h/app/#token={_WORD}?y=1",
    f"http://h/app/#next=x&password={_WORD}?y=1",
    f"http://h/app/#u=1&sid={_WORD}/x?y=1",
])
def test_a_top_level_fragments_pairs_before_a_question_mark_are_redacted(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _both_redactors_kept(url, _WORD) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual (owner CORE, core.redaction `_authority_start`): after a scheme, "
    "Node 22's URL starts the authority after the whole run of '/' and '\\\\' "
    "(`https:///x&password=<word>`: host `x&password=<word>`), the walk after exactly "
    "'//', so the pair list is read as a path; the sibling of "
    "`test_a_slash_led_authoritys_pair_list_encoded_once_is_redacted_by_redact_url` "
    f"behind a scheme (r5: 688 URLs; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    "http://h/app/p.php?u=bob&next=" + quote(f"https:///x&password={_WORD}", safe=""),
    "http://h/app/p.php?u=bob&next=" + quote(f"https:////host&token={_WORD}", safe=""),
    "http://h/app/#/r?next=" + quote(f"http:///x&sid={_WORD}", safe=""),
])
def test_a_slash_run_after_a_scheme_before_a_pair_list_is_redacted(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _both_redactors_kept(url, _WORD) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual (owner CORE, core.redaction `_UrlWalk.pairs`): r5 reads an '&' part "
    "holding a ';' as one pair too (7393c90's reading), but only its name: its value "
    "across the ';' is walked as ';' pieces, never whole, so `next=/v?password;x=<word>` "
    "(the '&' reading's value of `next` is `/v?password;x=<word>`, whose query's '&' "
    f"reading names `password;x`) is kept (r5: 384 URLs; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    f"http://h/app/p.php?u=bob&next=/v?password;x={_WORD}",
    f"http://h/app/p.php?u=bob&next=/v?a;token;b={_WORD}",
    f"http://h/app/p.php?u=bob&next=/v?sid=pw;{_WORD}",
])
def test_the_amp_reading_of_a_nested_value_is_redacted(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _both_redactors_kept(url, _WORD) == []


_TOKEN16 = "0123abcd4567ef01"


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual (owners CORE and AUD: core.redaction `_UrlWalk.url` keeps a "
    "top-level path segment and fragment route as the page's identity, R3, and "
    "tools.store_adapter `import_spider` stores the path as the page): an identifier "
    "there (`/app/<16 hex>/p.php`, `#<16 hex>`) is kept by `redact_url_identifiers`; "
    "`core.trace.safe_ref` blanks it in a path segment, not as a bare fragment "
    f"(r5: 36 URLs; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    f"http://h/app/{_TOKEN16}/p.php?token=a",
    f"http://h/app/p.php?token=a#{_TOKEN16}",
])
def test_an_identifier_as_a_top_level_path_segment_or_route_is_redacted(url):
    assert _leaks(url, _TOKEN16)                             # not vacuous
    assert not _leaks(R.redact_url_identifiers(url), _TOKEN16)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual (owner CORE, core.redaction `_UrlWalk.url`): a top-level URL's own "
    "authority is its identity and never walked, so its userinfo "
    "(`http://user:<pw>@h/app/…`) is kept by both URL redactors, `page_url_is_clean` and "
    "the proxy's `Location` / `Referer` (the record redactor and `safe_ref` strip it; "
    f"r5: 4 URLs; {_ON_7393})"))
@pytest.mark.parametrize("url", [
    f"http://user:{_WORD}@h/app/p.php?u=1",
    f"http://user:pw%20{_WORD}@h/app/p.php?u=1",
    f"http://user:{_WORD}@h/app/#/r?u=1",
])
def test_a_top_level_urls_own_userinfo_is_redacted_by_the_url_redactors(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _both_redactors_kept(url, _WORD) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual (owner PROXY, proxy.redact `redact`): a raw LF inside a request "
    "target or a URL header ends that line, so the rest of the URL "
    "(`?p<LF>assword=<word>`'s `assword=<word> HTTP/1.1`) is a malformed line no URL "
    "rule reads; it reaches history only through operator-supplied bytes, as N6's "
    f"malformed messages (r5: 948 URLs; {_ON_7393})"))
@pytest.mark.parametrize("raw", [
    "GET /app/p.php?p\nassword={W} HTTP/1.1\r\nHost: h\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: h\r\nReferer: http://h/app/p.php?u=bob&passw\nord={W}\r\n\r\n",
    "HTTP/1.1 302 Found\r\nLocation: http://h/app/#/r?t\noken={W}\r\n\r\n",
])
def test_proxy_history_redacts_a_url_holding_a_raw_lf(raw):
    from fuzzlab.proxy.redact import redact
    message = raw.format(W=_WORD).encode()
    assert _WORD.encode() in message                         # not vacuous
    assert _WORD.encode() not in redact(message)


# --- r6: layered on the pushed redactor (the floor runs first, the walk on its output) ----
# r6 runs 7393c90's own redactor first (`core.redaction_floor`) and the walk on its output
# only, so nothing the pushed tree redacted can be kept (`tests/test_redaction_floor.py`).
# Four families were redacted by 144d234 (which ran the walk on the raw input) and are
# kept by r6 and by 7393c90 alike: three the walk cannot see in the floor's output, (a)-(c),
# and (d), what a caller stores where the floor raises (the r6 review's R3). Under the
# owner's criterion (nothing the pushed tree redacted may leak; anything it also leaks is
# pinned) each is pinned here, never another design round. Each case fails on its stated
# assertion on r6 and on 7393c90's export, every consumer the pin names existing there but
# `redact_url_identifiers`' ``placeholder`` mode (the batch's own; checked where the code
# has it). PA-0549(3c) ("a defect a sweep finds in an unpushed change of the same batch is
# fixed in that batch") concerns regressions against the pushed tree (the owner's rule, and
# F-226's correction): 144d234 is unpushed, and these leaks are 7393c90's too.
_ON_7393_R6 = ("on 7393c90 too: not a regression against the pushed tree, so pinned, not "
               "fixed in the batch -- PA-0549(3c) concerns regressions against the pushed "
               "tree (the owner's rule; F-226); 144d234, unpushed, redacted it, reading the "
               "raw input")


def _layered_consumers_keeping(url: str, secret: str) -> list[str]:
    """The URL consumers that keep ``secret`` of ``url`` after their floor: both URL
    redactors (``placeholder`` mode too, where the code has it), the evidence reference,
    and, for a URL holding no raw CR or LF (one ends an HTTP line: the PROXY pin above),
    the proxy's request line, ``Location`` and ``Content-Location``."""
    import inspect

    from fuzzlab.core.trace import safe_ref
    from fuzzlab.proxy.redact import redact
    outs = [("redact_url", R.redact_url(url)),
            ("redact_url_identifiers", R.redact_url_identifiers(url)),
            ("safe_ref", safe_ref(url))]
    if "placeholder" in inspect.signature(R.redact_url_identifiers).parameters:
        outs.append(("redact_url_identifiers(placeholder=True)",
                     R.redact_url_identifiers(url, placeholder=True)))
    if "\r" not in url and "\n" not in url:
        target = "/" + url.split("://", 1)[1].partition("/")[2]
        for name, raw in (("proxy request line", f"GET {target} HTTP/1.1\r\nHost: h\r\n\r\n"),
                          ("proxy Location", f"HTTP/1.1 302 Found\r\nLocation: {url}\r\n\r\n"),
                          ("proxy Content-Location",
                           f"HTTP/1.1 200 OK\r\nContent-Location: {url}\r\n\r\n")):
            outs.append((name, redact(raw.encode("latin-1")).decode("latin-1")))
    return [name for name, out in outs if _leaks(out, secret)]


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual r6, family (a) (owner CORE, core.redaction: the floor "
    "`core.redaction_floor.redact_url` / `redact_url_identifiers` read a query through "
    "`urlsplit`, which removes every tab, CR and LF, and return the URL so cleaned "
    "whenever they redact another pair; the walk then sees one token): "
    "`?token=a&x<TAB>password=<word>` becomes `?token=__REDACTED__&xpassword=<word>`, "
    "`xpassword` is not a sensitive name, and the word is kept by `redact_url`, "
    "`redact_url_identifiers` (both modes), `core.trace.safe_ref` and the proxy's "
    "request line, `Location` and `Content-Location` (`proxy.redact.redact`); in a "
    "top-level pair, a raw or encoded nested query, a fragment pair and a route's query "
    "(r6: 100 of 480 generated URLs, 500 consumer pairs, all with a second pair the floor "
    f"redacts; {_ON_7393_R6} as two tokens). Candidate rule, not built: the walk judges a "
    "name holding a tab, CR or LF from the raw input"))
@pytest.mark.parametrize("url", [
    f"http://h/app/p.php?token=a&x\tpassword={_WORD}",
    f"http://h/app/p.php?token=a&u=b&next=/cb?my\ttoken={_WORD}",
    f"http://h/app/p.php?token=a&u=b&next=%2Fcb%3Fq\tsecret%3D{_WORD}",
    f"http://h/app/p.php?token=a&u=b#a\tsid={_WORD}",
    f"http://h/app/p.php?token=a&u=b#/r?user\tapi_key={_WORD}",
    f"http://h/app/p.php?token=a&x\rsid={_WORD}",
    f"http://h/app/p.php?token=a&u=b&next=/cb?q\r\nsecret={_WORD}",
])
def test_a_name_joined_by_a_tab_cr_or_lf_in_the_floors_output_is_redacted(url):
    assert _leaks(url, _WORD)                                # not vacuous
    assert _layered_consumers_keeping(url, _WORD) == []


_ID22 = "a70000000123f3e9c1b5d2"


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual r6, family (b) (owner CORE: the floor `core.redaction_floor."
    "safe_ref` runs 7393c90's record rule, `_URL_USERINFO` / `_BARE_USERINFO` to `***@`, "
    "before the walk sees the URL): the `***@` deletes a pair's name "
    "(`;next=is:open label:bug&password=H@<word>` becomes `;next=is:open ***@<word>`) or "
    "the userinfo that made the walk redact a nested URL whole (`#https://%26bob@<id>` "
    "becomes `#https://***@<id>`), so `core.trace.safe_ref` keeps the word or the "
    "identifier, in a diagram, an export and, through `tools.observe` under `fuzzlab "
    "auto`'s trace recorder, `trace_event` and `dg_flow` rows (r6: 146 URLs of r5b's "
    "corpus, 3 of the check's, 1 imported; the record redactor's own reading of the "
    f"same rule is N7's pin above; {_ON_7393_R6}). Candidate rule, not built: the walk "
    "redacts whole any value that holds the floor's `***@`"))
@pytest.mark.parametrize("url,secret", [
    (f"http://h/app/p.php;next=is:open label:bug&password=H@{_WORD}?u=bob", _WORD),
    (f"http://h/app/#next=is:open label:bug&password=H@{_WORD}", _WORD),
    (f"http://h/app/#next=https://is:open label:bug&password=H@{_WORD}/x", _WORD),
    (f"http://h/app/p.php#https://%26bob@{_ID22}", _ID22),
    (f"http://h/app/p.php?u=1#//%26bob@{_ID22}/x", _ID22),
])
def test_the_floors_userinfo_rule_never_lets_the_evidence_reference_keep_a_secret(url,
                                                                                    secret):
    from fuzzlab.core.trace import safe_ref
    assert _leaks(url, secret)                               # not vacuous
    out = safe_ref(url)
    assert not _leaks(out, secret), out


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual r6, family (b) through the store (owners CORE and AUD: "
    "`core.trace.safe_ref`'s floor, and `tools.store_adapter.import_spider`, whose "
    "pages `tools.observe` cites by `safe_ref` under a trace recorder): a page whose "
    "fragment holds `https://%26bob@<id>` stores the identifier in `trace_event` and "
    f"`dg_flow` (r6: the 1 imported URL of the check's corpus; {_ON_7393_R6})"))
def test_import_spider_under_a_trace_recorder_stores_no_identifier_behind_the_floors_userinfo(
        tmp_path):
    from fuzzlab.core import trace
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", [f"http://h/a1/x&bobtoken#https://%26bob@{_ID22}",
                                   f"http://h/a2/p.php#https://%26bob@{_ID22}"])
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        recorder = trace.TraceRecorder(store, run)
        with trace.recording(recorder):
            import_spider(tmp_path / "s.db", store, run)
        recorder.close()
        events = store.conn.execute("SELECT COUNT(*) FROM trace_event").fetchone()[0]
        dump = _dump(store)
    assert events > 0 and "/a2/p.php" in dump                # not vacuous: traced pages
    assert not _leaks(dump, _ID22)


_CUT_PASS = "SecretPassWord99"


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual r6, family (c) (owner CORE: the floor `core.redaction_floor."
    "redact_for_record` cuts a value at `MAX_RECORD_CHARS` (4096) after its userinfo "
    "rule and before the walk sees it): a nested, percent-encoded userinfo "
    "(`next=https%3A%2F%2Fbob%3A<pw>%40host`) that straddles the cut loses its `%40`, so "
    "neither the floor's rule nor the walk reads a userinfo and the start of the password "
    "is kept by `redact_for_record` (`launch.argv`, `launch.target`, `project.targets`) "
    "and `core.trace.safe_ref` (r6: 20 of 120 probes, 10 cut positions per consumer; "
    f"{_ON_7393_R6}, before its cut). Candidate rule, not built: when the floor "
    "truncated, the walk redacts the cut piece whole"))
@pytest.mark.parametrize("pad", [0, 4, 9])
def test_a_nested_userinfo_cut_by_the_records_size_bound_keeps_no_password(pad):
    from urllib.parse import unquote

    from fuzzlab.core.trace import safe_ref
    url = ("http://h/p?a=" + "x" * 4040 + "&next=" + "y" * pad + "https%3A%2F%2Fbob%3A"
           + _CUT_PASS + "%40host%2Fx")
    assert _CUT_PASS in url and len(url) > R.MAX_RECORD_CHARS   # not vacuous

    def keeps(out):
        seen = [out]
        for _ in range(4):
            seen.append(unquote(seen[-1]))
        return any(_CUT_PASS[:8] in t for t in seen)
    kept = [name for name, out in (("redact_for_record", R.redact_for_record("target", url)),
                                   ("safe_ref", safe_ref(url))) if keeps(out)]
    assert kept == []


_JSESSION = "a70000000123f3e9c1b5d2e4f6a8b0c1"


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual r6, family (d) (owner PROXY, proxy.history "
    "`HistoryWriter._prepare_contained`; the r6 review's R3): where the floor raises (a URL "
    "`urlsplit` rejects: `http://[h/…`, `http://[::1]x/…`), `redact` raises and the writer "
    "stores the flow with every body `OMIT_FAILED` and its URL cut at the first '?' "
    "(`rec.url.split('?', 1)[0]`), in `flow.url` and its `errors` line, so a `;name=value` "
    "path parameter, or a query-shaped fragment, before the '?' is stored whole "
    "(`http://[h/app;jsessionid=<hex>/p.php?u=1` keeps the session id; 144d234's walk "
    "stored `;jsessionid=__REDACTED__`; r6 review: 651 of the r6b check's 70 000 URLs "
    "store a secret so, 183 of them redacted by 144d234 -- 171 in a path parameter, 12 "
    f"in a fragment; {_ON_7393_R6}). Candidate rule, not built: the fallback stores the "
    "URL cut at its first ';', '?' or '#'"))
@pytest.mark.parametrize("url,secret", [
    (f"http://[h/app;jsessionid={_JSESSION}/p.php?u=1", _JSESSION),
    (f"http://[::1]x/app;token={_JSESSION}/p.php?u=1", _JSESSION),
    (f"http://[h/app/p.php;sid={_WORD}?u=1", _WORD),
    (f"http://[h/app/p.php#a=1;password={_WORD}?u=bob", _WORD),
])
def test_proxy_history_stores_no_path_parameter_of_a_flow_its_floor_rejects(tmp_path, url,
                                                                           secret):
    from urllib.parse import urlsplit

    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    with pytest.raises(ValueError):                          # not vacuous: the floor raises
        urlsplit(url)
    rq = f"GET {url} HTTP/1.1\r\nHost: h\r\n\r\n".encode()
    rs = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=5)
        h.record(FlowRecord("GET", url, "h", 200, raw_request=rq, raw_response=rs))
        assert h.flush() == 1                                # not vacuous: one flow stored
        dump = _dump(store)
    assert not _leaks(dump + "\n".join(h.errors), secret)


_BAD_URL_VALUE = "http://[h/x?y=1"                  # urlsplit rejects it, and it has a '?'


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual r6, family (d), header-triggered (owner PROXY, proxy.history "
    "`HistoryWriter._prepare_contained`; the r6 fix check's R3(b), pinned at the merge): "
    "a flow whose own URL `urlsplit` accepts, with a `Location`, `Refresh` (`url=`) or "
    "`Content-Location` value it rejects that holds a '?' (`http://[h/x?y=1`), makes "
    "the floor's `redact` raise, and the writer falls back as for a rejected request "
    "line: every body `OMIT_FAILED` and the flow's own URL cut at its first '?', so the "
    "flow's own `;name=value` path parameter (or a fragment before the '?') is stored "
    "whole in `flow.url` and the `errors` line (`http://h/app;jsessionid=<hex>/p.php?u=1` "
    "with `Location: http://[h/x?y=1` keeps the session id; the same flow without that "
    "header is redacted). The fix check, each r6b corpus URL paired with such a "
    "`Location`: 67 371 fallbacks, 14 082 store a secret (on 7393c90 too), 3 517 of them "
    "redacted by 144d234; the fallback flow's `observe.exchange` trace event, built from "
    "the cut URL, kept a secret in 1 055 (45 redacted by 144d234). "
    f"{_ON_7393_R6}. Candidate rule, not built: the fallback stores the URL cut at its "
    "first ';', '?' or '#'"))
@pytest.mark.parametrize("url,secret,header", [
    (f"http://h/app;jsessionid={_JSESSION}/p.php?u=1", _JSESSION,
     f"Location: {_BAD_URL_VALUE}"),
    (f"http://h/app;jsessionid={_JSESSION}/p.php?u=1", _JSESSION,
     f"Refresh: 0;url={_BAD_URL_VALUE}"),
    (f"http://h/app/p.php;sid={_WORD}?u=1", _WORD, f"Content-Location: {_BAD_URL_VALUE}"),
    (f"http://h/app/p.php#a=1;password={_WORD}?u=bob", _WORD,
     f"Location: {_BAD_URL_VALUE}"),
])
def test_proxy_history_stores_no_path_parameter_of_a_flow_a_header_value_makes_it_fall_back(
        tmp_path, url, secret, header):
    from urllib.parse import urlsplit

    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    urlsplit(url)                                            # the flow's own URL parses
    with pytest.raises(ValueError):                          # not vacuous: the header's
        urlsplit(_BAD_URL_VALUE)                             # value is what raises
    target = "/" + url.split("://", 1)[1].partition("/")[2]
    rq = f"GET {target} HTTP/1.1\r\nHost: h\r\n\r\n".encode()
    rs = f"HTTP/1.1 302 Found\r\n{header}\r\nContent-Length: 0\r\n\r\n".encode()
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=5)
        h.record(FlowRecord("GET", url, "h", 302, raw_request=rq, raw_response=rs))
        assert h.flush() == 1                                # not vacuous: one flow stored
        dump = _dump(store)
    assert h.errors                                          # not vacuous: it fell back
    assert not _leaks(dump + "\n".join(h.errors), secret)


# --- at the merge (the coordinator's records round, owner-approved): `import_audit` ------
# The fix check of 08eb900 found `import_audit` still fails on pages 7393c90's import
# failed on too, where the records said it never fails (R4), and reads a BLOB page as
# 7393c90 read it (D1(b): the batch's regression on a BLOB page with an empty path is
# fixed, `tests/test_redaction_nested.py::test_merge_d1b_*`). Each pin fails at its first
# assertion ("the import failed") or its leak assertion on the merge and on 7393c90.
_ON_7393_IMPORT = ("on 7393c90 too: not a regression against the pushed tree, so pinned, "
                   "not fixed in the batch")


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual at the merge, R4 (owner AUD, tools.store_adapter `_audit_text`): a "
    "finding page `urlsplit` rejects as written WITHOUT a '?' (`http://[h/app/p.php`, "
    "`//[h/app/p.php`, `http://x＃y/app/p.php`, `//user:pw@x[y/app/p.php`) passes the "
    "floor unread (the pushed tree's URL redactors call `urlsplit` only on a URL holding "
    "a '?'), so `_audit_text`'s withhold branch is never reached and its "
    "`urlparse(page_url)` raises ValueError, uncaught: the whole import fails, every "
    "other finding with it (the fix check of 08eb900: all 3 000 '?'-less pages of the "
    "12 000 rejected ones among 43 680 generated neighbours, and 27 of the 888-URL "
    "supplement; the 70 000-URL corpus holds no URL without a '?'); 7393c90's `to_path` "
    f"raised on the same pages ({_ON_7393_IMPORT}). Candidate rule, not built: catch "
    "that ValueError and withhold the finding's texts (`AUDIT_TEXT_WITHHELD`), as for "
    "such a page with a '?'"))
@pytest.mark.parametrize("page,secret", [
    ("http://[h/app/p.php", None),
    ("//[h/app/p.php", None),
    ("http://x＃y/app/p.php", None),
    ("//user:pw@x[y/app/p.php", None),
    (f"http://[h/app;jsessionid={_JSESSION}/p.php", _JSESSION),
])
def test_import_audit_imports_a_finding_page_urlsplit_rejects_without_a_query(tmp_path,
                                                                              page, secret):
    from urllib.parse import urlsplit
    assert "?" not in page
    with pytest.raises(ValueError):                          # not vacuous: urlsplit
        urlsplit(page)                                       # rejects the page as written
    audit_db = _audit_findings(tmp_path, [
        (page, "rule_a", "u", f"called from {page}"),
        ("http://h/app/q.php?u=1", "rule_b", "u", "value reflected")])
    counts, failed, endpoints, _candidates, dump = _import_audit_or_failure(tmp_path,
                                                                            audit_db)
    assert failed is None, f"the import failed: {failed!r}"
    assert counts == {"candidate": 2} and "/app/q.php" in endpoints
    assert secret is None or not _leaks(dump, secret)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual at the merge, D1(b) (owner AUD, tools.store_adapter "
    "`import_audit` / `_audit_endpoint` / `_audit_text`): a finding page stored as a BLOB "
    "is read by `to_path` as 7393c90 read it, so one with a path "
    "(`b\"http://h/app/p.php\"`, `b\"/app/p.php\"`) fails the whole import with "
    "TypeError (`bytes.startswith` given a str), and one with an empty path is imported "
    "but its texts are never judged against it (`_audit_text` judges a str page only), "
    "so a context quoting its query value stores it (`b\"http://h?token=<word>\"`); "
    "unreachable from the auditor "
    f"(`fetcher.log_finding` writes the crawler's str URL); {_ON_7393_IMPORT}. Candidate "
    "rule, not built: decode a BLOB page (UTF-8, the crawler's str) before reading it, "
    "or withhold its finding's texts"))
@pytest.mark.parametrize("page,secret", [
    (b"http://h/app/p.php", None),
    (b"/app/p.php", None),
    (b"http://h?token=" + _WORD.encode(), _WORD),
])
def test_import_audit_imports_a_blob_finding_page_and_judges_its_texts(tmp_path, page,
                                                                      secret):
    context = f"value '{secret}' reflected" if secret else "value reflected"
    audit_db = _audit_findings(tmp_path, [
        (page, "rule_a", "token" if secret else "u", context),
        ("http://h/app/q.php?u=1", "rule_b", "u", "value reflected")])
    counts, failed, _endpoints, _candidates, dump = _import_audit_or_failure(tmp_path,
                                                                             audit_db)
    assert failed is None, f"the import failed: {failed!r}"
    assert counts == {"candidate": 2}
    assert secret is None or not _leaks(dump, secret)


# --- N3: `fuzzlab audit --append --store` ------------------------------------------------
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round, N3 neighbour 2 (owner AUD, "
    "tools.store_adapter `import_audit` / `_audit_endpoint`): with `--append` the "
    "findings kept from an earlier audit have no row in this run's spider rows, so the "
    "fallback `store_url(page, main)` takes the main origin from the first finding's "
    "page, not the spider's seed: the API page is stored `/v1/q.php` (the wrong host) "
    "and a main-origin page absolute (`http://h:80/app/old.php`), RU-8's split"))
def test_import_audit_after_an_appended_audit_stores_each_page_as_the_spider_does(
        tmp_path):
    from fuzzlab.tools import fetcher as F
    from fuzzlab.tools.spider import StorageManager
    from fuzzlab.tools.store_adapter import import_audit, import_spider
    rules = [(k, "cat", None) for k in F.RULES]

    def crawl_and_audit(rows, append):
        sm = StorageManager(str(tmp_path / "s.db"))
        sm.reset()
        for url, depth, source in rows:
            sm.mark_visited(url, 200, depth, source=source,
                            found_from=None if depth == 0 else rows[0][0])
        sm.close()
        db = F.setup_results_db(str(tmp_path / "a.db"), append=append)
        for target, source in F.load_urls(str(tmp_path / "s.db")):
            F.audit_page(target, source, _SilentFetcher(), rules, db, set(), verbose=False)
        db.close()

    # run 1: an XHR on an API origin audited before a main-origin page
    crawl_and_audit([("http://h/", 0, "link"), ("http://api.h:8081/v1/q.php?u=bob", 1,
                                                 "xhr"),
                     ("http://h/app/old.php?id=1", 1, "link")], append=False)
    # run 2 re-crawls the main origin and audits with --append (fuzzlab audit's order)
    crawl_and_audit([("http://h/", 0, "link"), ("http://h/app/z.php?id=7", 1, "link")],
                    append=True)
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auditor", "h")
        import_spider(tmp_path / "s.db", store, run)
        spider = {r[0] for r in store.conn.execute("SELECT url FROM endpoint").fetchall()}
        import_audit(tmp_path / "a.db", store, run)
        added = {r[0] for r in store.conn.execute(
            "SELECT url FROM endpoint WHERE source = 'audit'").fetchall()}
    assert "/app/z.php" in spider and added                  # not vacuous
    assert added == {"/app/old.php", "http://api.h:8081/v1/q.php"}, sorted(added)


# --- N6: proxy history -------------------------------------------------------------------
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round, N6 (owner PROXY, proxy.redact `redact`): "
    "a request line after an empty line or a leading space (`_target_span` gives "
    "(0, 0); RFC 9112 2.2 lets a server skip the empty line), a folded (obs-fold) URL "
    "header, `Link`'s `anchor` parameter and a custom header holding a relative or "
    "quoted URL keep the secret in the stored raw messages; they reach history only "
    "through operator-supplied bytes (the Repeater, an intercept edit, a match-replace "
    "rule)"))
@pytest.mark.parametrize("raw", [
    "\r\nGET /app;jsessionid={W} HTTP/1.1\r\nHost: h\r\n\r\n",
    "\r\nGET /app?token={W} HTTP/1.1\r\nHost: h\r\n\r\n",
    " GET /app/?token={W} HTTP/1.1\r\nHost: h\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: h\r\nReferer:\r\n /app/;jsessionid={W}\r\n\r\n",
    "HTTP/1.1 302 Found\r\nLocation:\r\n\t/app/;jsessionid={W}\r\n\r\n",
    'HTTP/1.1 200 OK\r\nLink: </x>; rel=next; anchor="/app;jsessionid={W}"\r\n\r\n',
    "HTTP/1.1 302 Found\r\nX-Redirect: ?token={W}\r\n\r\n",
    "HTTP/1.1 302 Found\r\nX-Redirect: app/;jsessionid={W}\r\n\r\n",
    'HTTP/1.1 302 Found\r\nX-Redirect: "/app;jsessionid={W}"\r\n\r\n',
])
def test_proxy_history_redacts_a_url_in_a_malformed_or_folded_message(raw):
    from fuzzlab.proxy.redact import redact
    message = raw.format(W=_WORD).encode()
    assert _WORD.encode() in message                         # not vacuous
    assert _WORD.encode() not in redact(message)


# --- N7 neighbour 1 and `_URL_USERINFO` across a pair separator: the record redactor ---
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round, N7 neighbour 1 (owner CORE, "
    "core.redaction `redact_for_record`): its userinfo pre-pass runs on the whole value "
    "before the URL walk, so `_BARE_USERINFO` after a raw space (`q=is:open "
    "label:bug&password=…@…`) and `_URL_USERINFO` across a '&' or a '%26' "
    "(`?next=//x&password=…@…`) replace a span holding a pair's name, and the walk "
    "never sees `password=` (on f939778 too)"))
@pytest.mark.parametrize("value", [
    f"http://127.0.0.1:3000/app/?q=is:open label:bug&password=Hunter@{_WORD}",
    f"http://127.0.0.1:3000/app/#/r?next=/v?q=a b:c&token=Abc@{_WORD}",
    f"http://127.0.0.1:3000/app/?q=a b:c&token=@{_WORD}",
    f"http://127.0.0.1:3000/app/?next=//x&password=Hunter@{_WORD}",
    f"http://127.0.0.1:3000/app/?next=/v?a=//x%26password%3DHunter@{_WORD}",
])
def test_a_record_never_deletes_a_pair_name_with_a_userinfo_pattern(value):
    assert _WORD in value                                    # not vacuous
    assert not _leaks(R.redact_for_record("target", value), _WORD)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round (owner CORE, core.redaction "
    "`_URL_USERINFO_SPACED`): a top-level userinfo holding both whitespace and a pair "
    "separator (`http://bob:pw x&<word>@h/`; Node 22: password `pw%20x&<word>`) is "
    "kept by the record redactor, whose spaced pattern stops at '&' so that a space "
    "never lets it delete a later pair's name (the top-level URL's own userinfo is "
    "R3 for the URL walk; on f939778 too)"))
def test_a_record_strips_a_top_level_userinfo_holding_a_space_and_a_pair_separator():
    value = f"http://bob:pw x&{_WORD}@127.0.0.1:3000/app/"
    assert not _leaks(R.redact_for_record("target", value), _WORD)


# --- N8: the linearity oracle's blind spots -----------------------------------------------
def _flagged(monkeypatch, attr: str, variant) -> list:
    """The oracle's violations with ``_UrlWalk.<attr>`` replaced by ``variant`` (the real
    walk's output and its one ``tick`` per step kept), the real step restored after."""
    real = getattr(R._UrlWalk, attr)
    monkeypatch.setattr(R._UrlWalk, attr, variant)
    try:
        return _linearity_violations(100, monkeypatch)
    finally:
        monkeypatch.setattr(R._UrlWalk, attr, real)


def _per_pair(work):
    """A ``pairs`` step doing ``work(text)`` on the whole list once per pair."""
    def pairs(self, text, depth, top):
        self.tick(text)
        parts = R._PAIR_SEP.split(text)
        for i in range(0, len(parts), 2):
            work(text)
            parts[i] = self.pair(parts[i], depth, top)
        return "".join(parts)
    return pairs


def _resplit(text):
    return re.split(r"([&;])", text)


def _unquote_directly(text):
    from urllib import parse
    return parse.unquote(text)


def _str_split(text):
    return text.split("&")


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round, N8 A (owner CORE, the oracle in "
    "tests/test_redaction_nested.py `_counted_walk`): C-level work outside the counted "
    "names is not seen: a pair step that splits the whole list with `re.split` (an "
    "uncompiled pattern), unquotes it through `urllib.parse` directly or splits it with "
    "`str.split` once per pair passes the oracle at n=100, though quadratic"))
@pytest.mark.parametrize("work", [_resplit, _unquote_directly, _str_split],
                         ids=["re.split", "urllib.parse.unquote", "str.split"])
def test_the_linearity_oracle_flags_c_level_work_outside_the_counted_names(monkeypatch,
                                                                            work):
    assert _flagged(monkeypatch, "pairs", _per_pair(work))


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round, N8 B (owner CORE, the oracle's "
    "`_oracle_urls`): no oracle URL holds an '@' or '%40', so `userinfo`'s per-match "
    "loop never runs: one that rescans the whole text per authority (counted "
    "`_AUTHORITY_AT.findall`) passes the oracle"))
def test_the_linearity_oracle_runs_the_userinfo_loop(monkeypatch):
    real = R._UrlWalk.userinfo

    def userinfo(self, text):
        if "@" in text or "%40" in text:
            for _match in R._AUTHORITY_AT.finditer(text):
                R._AUTHORITY_AT.findall(text)
        return real(self, text)
    assert _flagged(monkeypatch, "userinfo", userinfo)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0556 residual after the final round, N8 C (owner CORE, the oracle's "
    "`_oracle_urls`): every oracle URL is clean, so no branch that runs only after a "
    "value changes (the sensitive name, `_Whole`, a layer's re-encode, the userinfo "
    "replacement) is exercised: a pair step that re-splits the whole list once per "
    "redacted pair passes the oracle"))
def test_the_linearity_oracle_runs_the_redaction_path(monkeypatch):
    def pairs(self, text, depth, top):
        self.tick(text)
        parts = R._PAIR_SEP.split(text)
        for i in range(0, len(parts), 2):
            new = self.pair(parts[i], depth, top)
            if new != parts[i]:
                R._PAIR_SEP.split(text)
            parts[i] = new
        return "".join(parts)
    assert _flagged(monkeypatch, "pairs", pairs)
