"""A secret nested in a URL value or behind a ``;`` is redacted wherever it sits
(BUG-0556, FR-CORE-537, PA-0556; SP-17).

Before BUG-0556 the URL and sibling redactors judged a query value as one flat token:
`looks_like_identifier` splits on ``. : @ /`` and whitespace only, so a token behind
``?``, ``=``, ``&`` or ``;`` -- ``?next=%2Fview%3Fticket%3D<hex>``, ``?next=/view?ticket=
<hex>``, ``?return=https%3A%2F%2Fhost%2Fcb%3Faccess_token%3D<jwt>`` (a short one),
``?a=1;token=<hex>`` and a ``;jsessionid=<id>`` path parameter in a middle segment --
reached ``page.url``, ``parameter.example``, a link set's ``form.entries`` and its
``source_page`` through `import_spider`, and the name-only redactor (`redact_url`: proxy
history, the HTTP recorder, the disco capture) never looked inside a value at all.

The sweep below is generated over nesting depth, encodings (raw, single and double
percent-encoding, ``+``, and ``quote(safe="/")`` / ``quote(safe="/:")``, which leave ``/``
and ``:`` raw and encode ``?``, ``=``, ``&``, ``;``, ``#`` and ``@``: Python's default and
Django's ``redirect_to_login``), separators (``&``, ``;`` and a mix), nested shapes (a
path, an absolute URL, a query string, a URL's userinfo) and credential names and
identifier shapes; each case is proven to store no secret byte, and the benign list
proves ordinary nested values are left byte-identical. Review round 1 (BUG-0556) added
the ``quote(safe="/")`` spellings, the userinfo shape, `import_audit`, the proxy's
query-less messages, the project-record redactor and the endpoint query's replay.
Review round 2 added each neighbouring path its check found: a layer left encoded in
any piece, userinfo wherever a URL starts, a quoted substring in `import_audit`'s
texts and its endpoint by the spider's main origin, greybox's refused points, every
URL-bearing proxy header and request line, a record URL holding a raw space, the
pre-fix fallbacks of every test, and an oracle counting the walk's C-level work.
"""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path
from urllib.parse import quote, quote_plus, unquote, unquote_plus, urlencode, urlsplit

import pytest

from fuzzlab.core import redaction as R
from fuzzlab.core.store import Store

# --- the secrets: identifier shapes under a benign name, credential names with a word --
_HEX = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
_UUID = "550e8400-e29b-41d4-a716-446655440001"
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZTcifQ.c2lnbmF0dXJlLXZhbHVlLTk4NzY1NA"
_B64 = "Qm9i+ZW5jb2RlZC/dG9rZW4+dmFsdWU9"          # standard base64: '+' and '/'
#: (name, value): an identifier-shaped value behind an ordinary name ...
SHAPED = [("ticket", _HEX), ("ref", _UUID), ("k", _JWT), ("state", _B64)]
#: ... and a credential name holding a value no shape rule sees (a word).
_WORD = "CanaryWordZq"
NAMED = [("token", _WORD), ("access_token", _WORD), ("jsessionid", _WORD),
         ("password", _WORD), ("api_key", _WORD), ("sid", _WORD)]
SECRETS = SHAPED + NAMED


def _runs(secret: str) -> list[str]:
    """The secret's alphanumeric runs of 8 or more characters: what must appear nowhere
    (any of them, in any encoding, is a secret byte; '+', '/', '.', '-' and '=' are
    re-encoded or split differently by each layer)."""
    return [r for r in re.findall(r"[A-Za-z0-9]+", secret) if len(r) >= 8]


def _leaks(text: str, secret: str, layers: int = 4) -> bool:
    """Whether ``text`` -- or any percent-decoding of it, up to ``layers`` layers --
    holds a run of ``secret``."""
    seen = [text]
    for _ in range(layers):
        seen.append(unquote(seen[-1]))
    return any(r in t for t in seen for r in _runs(secret))


def _api(name: str):
    """A function of the owner this file names, asserted present (FR-CORE-537). A test
    calls it only after its leak assertions, so the pre-fix code fails on the secret it
    keeps, never on a function it lacked (PA-0545(6); review round 1, RU-5, and round 2,
    N5: every test of the file swept)."""
    fn = getattr(R, name, None)
    assert fn is not None, f"core.redaction has no {name} (FR-CORE-537)"
    return fn


# --- the generated spellings ------------------------------------------------------------
_SEPS = {"amp": ("&", "&"), "semi": (";", ";"), "mix": ("&", ";")}
_ENCODINGS = {
    "raw": lambda s: s.replace(" ", "+"),            # a raw URL holds no space
    "pct": lambda s: quote(s, safe=""),
    "pct2": lambda s: quote(quote(s, safe=""), safe=""),
    "plus": lambda s: quote_plus(s),                 # form encoding: ' ' -> '+'
    # '/' (and ':') left raw, '?', '=', '&', ';', '#', '@' encoded: Python's quote()
    # default and Django's redirect_to_login (QueryDict.urlencode(safe="/")); review
    # round 1, RU-1/RU-6
    "slash": lambda s: quote(s, safe="/"),
    "slash2": lambda s: quote(quote(s, safe="/"), safe="/"),
    "colon": lambda s: quote(s, safe="/:"),
}


def _inner(name: str, secret: str, sep: tuple[str, str], shape: str) -> str:
    """A nested value holding ``name=secret``: a path with a query, an absolute URL
    with one, or a bare query string; a benign pair and a word with a space first. The
    ``userinfo`` shape holds the secret as a nested URL's password, percent-encoded as
    a URL carries one (review round 1, RU-2)."""
    first, second = sep
    query = f"x=1{first}q=hello world{second}{name}={secret}"
    if shape == "userinfo":
        return (f"https://{name}:{quote(secret, safe='')}@host.example/cb"
                f"?x=1{first}q=hello world")
    return {"path": "/view?" + query, "absolute": "https://host.example/cb?" + query,
            "query": query}[shape]


def _spelling(depth: int, name: str, secret: str, sep_key: str, enc: str,
              shape: str) -> str:
    """One page URL: the secret pair at the top level (depth 1), in a value (2), or in a
    value of a URL in a value (3)."""
    first, second = _SEPS[sep_key]
    if depth == 1:
        return f"http://h/app/p.php?u=bob{first}a=1{second}{name}={secret}"
    encode = _ENCODINGS[enc]
    value = encode(_inner(name, secret, _SEPS[sep_key], shape))
    if depth == 3:                                     # a URL in a value of a URL
        value = encode("/go?ret=" + value)
    return f"http://h/app/p.php?u=bob&next={value}"


_SHAPES = ("path", "absolute", "query", "userinfo")
CASES = sorted({(d, n, s, sep, enc, shape)
                for d in (1, 2, 3) for (n, s) in SECRETS for sep in _SEPS
                for enc in (_ENCODINGS if d > 1 else ["raw"])
                for shape in (_SHAPES if d > 1 else ["query"])})
#: A path parameter in a middle segment (its value percent-encoded: a raw ``/`` would
#: end the segment), alone or after a clean one.
_MATRIX = [f"http://h/app/a;{n}={quote(s, safe='')}/b.php?u=bob" for n, s in SECRETS] + \
    [f"http://h/app/a;x=1;{n}={quote(s, safe='')}/b/c.php?u=bob" for n, s in SECRETS]


def _case_url(case) -> str:
    return _spelling(*case)


def test_the_sweep_is_not_vacuous():
    """Every axis is present; every generated URL holds its secret before redaction."""
    assert len(CASES) == 3 * 10 + 2 * 10 * 3 * 7 * 4
    assert {c[0] for c in CASES} == {1, 2, 3}
    for case in CASES:
        assert _leaks(_case_url(case), case[2]), case


# --- the owner: every spelling is redacted, the URL stays a URL --------------------------
def test_every_nested_spelling_of_a_secret_is_redacted_and_the_url_stays_a_url():
    """BUG-0556: identifier shapes and credential names at any depth, in any encoding and
    behind any separator leave no secret byte in the strongest redactor's output; the
    output parses as the same page (scheme, host, path, the top-level names in order);
    the page is never clean; and the value is one `value_holds_secret` holds for.

    The leak, clean-page and shape failures are asserted first, so the pre-fix code
    fails on the secret found, never on a function it lacked (review round 1, RU-5;
    PA-0545(6)). The top-level names kept are the URL's, or the pushed tree's own
    redactor's (BUG-0556 r6: it runs first, reads a query's ``&`` parts only and blanks a
    part whose value, read across its ``;``, is identifier-like: ``u=bob;a=1;k=<jwt>``
    becomes ``u=``, as on 7393c90)."""
    try:
        from fuzzlab.core.redaction_floor import redact_url_identifiers as pushed
    except ImportError:                               # a tree before r6: no floor
        pushed = None
    failures, values = [], []
    for case in CASES:
        url = _case_url(case)
        out = R.redact_url_identifiers(url)
        before, after = urlsplit(url), urlsplit(out)
        names = [p.partition("=")[0] for p in re.split(r"[&;]", before.query)]
        kept = [p.partition("=")[0] for p in re.split(r"[&;]", after.query)]
        floor = ([p.partition("=")[0] for p in re.split(r"[&;]", urlsplit(pushed(url)).query)]
                 if pushed is not None else names)
        if "next=" in before.query:
            values.append((case, before.query.split("next=", 1)[1]))
        if (_leaks(out, case[2]) or R.page_url_is_clean(url)
                or (after.scheme, after.netloc, after.path)
                != (before.scheme, before.netloc, before.path)
                or kept[:2] not in (names[:2], floor[:2])):
            failures.append((case, out))
    assert failures == []
    holds = _api("value_holds_secret")
    assert [case for case, value in values if not holds(unquote(value))] == []


def test_a_credential_name_is_redacted_by_the_name_only_redactor_at_any_depth():
    """`redact_url` (proxy history, the HTTP recorder, the disco capture, the spider's
    form and landing URLs) applies the name rule wherever a pair sits."""
    failures = [(c, R.redact_url(_case_url(c))) for c in CASES
                if c[1] in dict(NAMED) and _leaks(R.redact_url(_case_url(c)), c[2])]
    assert failures == []


@pytest.mark.parametrize("url", _MATRIX)
def test_a_path_parameter_holding_a_secret_is_redacted_and_never_stored(url):
    name, _eq, rest = url.split(";")[-1].partition("=")
    secret = unquote(rest.split("/", 1)[0])
    assert not _leaks(R.redact_url_identifiers(url), secret)
    assert not R.page_url_is_clean(url)
    if name in dict(NAMED):
        assert not _leaks(R.redact_url(url), secret)
    from fuzzlab.core.urls import canonical_origin, store_url
    stored = store_url(url, canonical_origin("http://h/"))
    assert not _leaks(stored, secret)
    assert stored in ("/app/a/b.php", "/app/a;x=1/b/c.php")   # a clean parameter kept


#: Review round 1, RU-1/RU-6: a nested URL whose leading ``/`` or ``://`` is raw and
#: whose ``?``, ``=``, ``&``, ``;`` or ``#`` is percent-encoded: ``(url, secret, the
#: secret's name is sensitive)``.
_LAYER_LEFT_ENCODED = [
    # Django's redirect_to_login: QueryDict.urlencode(safe="/") -> quote(v, safe="/")
    ("http://h/accounts/login/?" + urlencode({"next": f"/orders/view?ticket={_HEX}"},
                                             safe="/"), _HEX, False),
    (f"http://h/app/p.php?u=bob&next=/view%3Fticket%3D{_HEX}", _HEX, False),
    (f"http://h/app/r.php?u=bob&return=https://host/cb%3Faccess_token%3D{_WORD}", _WORD,
     True),
    (f"http://h/p?u=bob&next=/a%3Fr%3D/cb%253Ftoken%253D{_WORD}", _WORD, True),
    (f"http://h/p?u=bob&next=/a%3Bjsessionid%3D{_HEX}", _HEX, True),
    (f"http://h/p?u=bob&next=/view%253Fticket%253D{_HEX}", _HEX, False),
    (f"http://h/p?u=bob&next=/r%23/x%3Ftoken%3D{_WORD}", _WORD, True),
    # a raw query, and a path segment of the nested URL still encoded
    (f"http://h/p?u=bob&next=/view%3Bjsessionid%3D{_HEX}/x?a=1", _HEX, True),
]


@pytest.mark.parametrize("url,secret,named", _LAYER_LEFT_ENCODED)
def test_a_layer_left_encoded_behind_a_raw_slash_is_decoded_wherever_it_is_read(
        url, secret, named):
    """Review round 1, RU-1/RU-6: the walk decodes a percent-encoding layer wherever one
    remains after the raw walk -- here a nested URL's path segment -- so the strongest
    redactor, `page_url_is_clean`, the evidence reference and (for a sensitive name)
    the name-only redactor all see the token."""
    from fuzzlab.core.trace import safe_ref
    assert _leaks(url, secret)                               # not vacuous
    assert not _leaks(R.redact_url_identifiers(url), secret)
    assert not R.page_url_is_clean(url)
    assert not _leaks(safe_ref(url), secret)
    if named:
        assert not _leaks(R.redact_url(url), secret)
    value = urlsplit(url).query.rsplit("&", 1)[-1].partition("=")[2]
    assert _api("stored_value")("next", unquote(value), unquote_plus(value)) == ""


_USERINFO = "https://bob:CanaryPassWord@host.example/x"


@pytest.mark.parametrize("value", [
    _USERINFO, quote(_USERINFO, safe=""), quote(_USERINFO, safe="/"),
    quote(_USERINFO, safe="/:"), quote(quote(_USERINFO, safe=""), safe=""),
    "//bob:CanaryPassWord@host.example/x", "http://admin:CanaryPassWord@10.0.0.1/",
])
def test_a_nested_urls_userinfo_is_a_credential_in_both_redactors(value):
    """Review round 1, RU-2: a credential in a nested URL's userinfo is redacted by
    both URL redactors and is never stored as a value, whatever the password's shape
    (the record boundary and `safe_ref` already treated userinfo as a credential)."""
    url = f"http://h/app/p.php?u=bob&next={value}"
    for fn in (R.redact_url, R.redact_url_identifiers):
        assert "CanaryPassWord" not in unquote(unquote(fn(url))), fn.__name__
    assert not R.page_url_is_clean(url)
    assert _api("stored_value")("next", unquote(value), unquote_plus(value)) == ""


_PASS = "CanaryPassWord"
#: Review round 2's neighbouring spellings, each kept by a redactor on f939778 (``(url,
#: secret)``; every secret is a sensitive name's value or a URL's password, so the
#: name-only redactor must remove it too):
_ROUND2 = [
    # N1: an encoded layer in a nested URL's authority with a raw '?' elsewhere
    f"http://h/app/q.php?u=bob&next=https://host%2Fcb%3Faccess_token%3D{_WORD}?y=1",
    # N1: Werkzeug's url_for applied twice (measured by the review on werkzeug 3.1.9), a
    # pair list holding a URL (raw, and decoded from a layer)
    f"http://h/login?next=/login?next%3Dhttps://bob:{_PASS}@host/x",
    f"http://h/app/p.php?u=bob&state=next=https://bob:{_PASS}@host/x",
    "http://h/app/p.php?u=bob&next=" + quote(f"a=1&token={_WORD}&next=https://h/x", safe=""),
    # N2: a URL's userinfo inside a nested URL's path segment, encoded and raw
    f"http://h/app/p.php?u=bob&next=/go/https%3A%2F%2Fbob%3A{_PASS}%40host%2Fx",
    f"http://h/app/p.php?u=bob&next=/go/https://bob:{_PASS}@host/x",
    f"http://h/app/p.php?u=bob&next=https://proxy.example/go/https://bob:{_PASS}@host/x",
    # N2: after a space; in a nested fragment route; the WHATWG parser's userinfo
    # spellings (measured on Node 22's URL: 'https:///', 'https:\\\\', '/\\', 'http:/')
    f"http://h/app/p.php?u=bob&next=+https://bob:{_PASS}@host/x",
    f"http://h/app/p.php?u=bob&next=%20https://bob:{_PASS}@host/x",
    f"http://h/app/p.php?u=bob&next=/a%23https://bob:{_PASS}@host/x?y=1",
    f"http://h/app/p.php?u=bob&next=https:///bob:{_PASS}@host/x",
    f"http://h/app/p.php?u=bob&next=https:\\\\bob:{_PASS}@host/x",
    f"http://h/app/p.php?u=bob&next=/\\bob:{_PASS}@host/x",
    f"http://h/app/p.php?u=bob&next=http:/bob:{_PASS}@host/x",
    # N1 (N7's second neighbour): a layer left encoded in the top-level fragment's
    # route (Python's quote() of a route, '#!', encodeURIComponent, a bare pair), and a
    # route's path parameter before its query
    f"http://h/app/#/r%3Ftoken%3D{_WORD}",
    f"http://h/app/#!/r%3Ftoken%3D{_WORD}",
    f"http://h/app/#%2Fr%3Ftoken%3D{_WORD}",
    f"http://h/app/#token%3D{_WORD}",
    f"http://h/app/#/r;jsessionid={_WORD}?x=1",
]


def _round2_secret(url: str) -> str:
    return _PASS if _PASS in url else _WORD


@pytest.mark.parametrize("url", _ROUND2)
def test_a_review_round_2_spelling_is_redacted_by_every_url_redactor(url):
    """Review round 2, N1 and N2: a layer left encoded in any piece (a nested URL's
    authority, the top-level fragment's route) is decoded and walked; a pair list
    holding a URL is split into pairs first; a URL's userinfo is a credential wherever
    a URL starts in a value, as `redact_for_record` and `safe_ref` already judged it.
    Each redactor, `page_url_is_clean`, the evidence reference and the record
    redactor see the secret."""
    from fuzzlab.core.trace import safe_ref
    secret = _round2_secret(url)
    assert _leaks(url, secret)                               # not vacuous
    for fn in (R.redact_url, R.redact_url_identifiers):
        assert not _leaks(fn(url), secret), fn.__name__
    assert not R.page_url_is_clean(url)
    assert not _leaks(safe_ref(url), secret)
    assert not _leaks(R.redact_for_record("target", url), secret)


def test_the_review_round_2_spellings_store_no_secret_through_import_spider(tmp_path):
    """The same spellings through the spider's rows and `import_spider`: no secret in
    ``page``, ``endpoint``, ``parameter.example``, ``form.entries`` or
    ``form.source_page`` (on f939778 the nested userinfo and the encoded authority
    reached ``form.source_page``, the page the binder fetches)."""
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", _ROUND2)
    with Store(tmp_path / "u.db") as store:
        import_spider(tmp_path / "s.db", store, store.start_run("auto", "h"))
        pages = {r[0] for r in store.conn.execute("SELECT url FROM page").fetchall()}
        dump = _dump(store)
    assert {"/app/q.php", "/login", "/app/p.php"} <= pages      # not vacuous
    assert not _leaks(dump, _PASS) and not _leaks(dump, _WORD)


# --- after the owner's final round: the batch's own regressions (BUG-0556) ---------------
#: A passphrase: Node 22's ``URL`` reads ``https://bob:correct horse@host/x`` as password
#: ``correct%20horse`` (`scratchpad/lanes/REDACTURL/r3/whatwg_ws.js`; a VT, FF, NBSP or
#: U+3000 is kept and encoded too, a tab or newline removed).
_PHRASE = "correct " + _PASS
#: Spellings 111b6fb kept in at least one consumer (``(url, secret)``): the fix check's
#: regression after the final round (N2 item 1 = N7 neighbour 2: `_AUTHORITY_AT`'s
#: authority stopped at whitespace) and the three the r3 differential sweep found beside
#: it (a userinfo that is also a pair list, replaced before the walk split it; a nested
#: authority holding raw pair structure, never walked once round 2's `_url_shaped` sent
#: ``a=https://…`` to it; a value led by one backslash taken for a URL). Most are
#: regressions: f939778's URL redactors redacted them. Not all (corrected in r4, by the
#: skeptic's measurement and `scratchpad/lanes/REDACTURL/r4/probe_after_final.py`):
#: cases 5 and 6 of `_AFTER_FINAL` (0-based; group 1's two ``/go/`` spellings, a spaced
#: userinfo in a nested path segment) and case 12 (group 2's ``#/r?next=a%3Dhttps…``, a
#: pair-list userinfo in a route's query) were kept by f939778 too, by both URL
#: redactors, the proxy's ``Location``, `page_url_is_clean` and `value_holds_secret`
#: (cases 5 and 12 by `safe_ref` and `redact_for_record` as well). They are not
#: regressions against f939778: they are fixed by the same change as their group's
#: regression (r3's class 1 or 2), and disclosed as such in BUG-0556 and CC-CORE-0076.
#: So are N1 (B) (group 3's last four, kept on f939778 too, the same mechanism as the
#: third class, fixed with it) and case 14's `value_holds_secret` (False on f939778;
#: its URL redactors redacted it).
#:
#: 1. a userinfo holding whitespace: encodeURIComponent's spelling, raw, a tab, an NBSP,
#: in a nested path segment, a raw space at the top and in a route's query
_SPACED_USERINFO = [
    ("http://h/app/p.php?u=bob&next=" + quote(f"https://bob:{_PHRASE}@host/x", safe=""),
     _PASS),
    (f"http://h/app/p.php?u=bob&next=https://bob:{quote(_PHRASE)}@host/x", _PASS),
    ("http://h/app/p.php?u=bob&next=" + quote(f"https://bob:correct\t{_PASS}@host/x",
                                              safe=""), _PASS),
    (f"http://h/app/p.php?u=bob&next=https://bob:correct%09{_PASS}@host/x", _PASS),
    ("http://h/app/p.php?u=bob&next=" + quote(f"https://bob:pw {_PASS}@host/x",
                                              safe=""), _PASS),
    ("http://h/app/p.php?u=bob&next=/go/" + quote(f"https://bob:{_PHRASE}@host/x", safe=""),
     _PASS),
    (f"http://h/app/p.php?u=bob&next=/go/https://bob:{quote(_PHRASE)}@host/x", _PASS),
    (f"http://h/app/q.php?u=bob&next=https://bob:pw {_WORD}@host/x", _WORD),
    (f"http://h/app/r.php?u=bob#/r?next=https://bob:pw {_WORD}@host/x", _WORD),
]
#: 2. a userinfo holding a pair separator, raw or encoded: the pair reading's name was
#: deleted with it (``a=//__REDACTED__@<word>``)
_PAIR_LIST_USERINFO = [
    ("http://h/app/p.php?u=bob&next=" + quote(f"a=//x&password=Hunter@{_WORD}", safe=""),
     _WORD),
    ("http://h/app/p.php?u=bob&next=" + quote(f"a=//x;token=Hunter@{_WORD}", safe=""),
     _WORD),
    ("http://h/app/p.php?u=bob&next=" + quote(f"/v?a=//x&password=Hunter@{_WORD}"), _WORD),
    ("http://h/app/#/r?next=" + quote(f"a=https://x&password=Hunter@{_WORD}", safe=""),
     _WORD),
    ("http://h/app/p.php?u=bob&next="
     + quote(f"a=https://x%26password%3DHunter@{_WORD}/x"), _WORD),
]
#: 3. a nested authority holding raw pair structure once its layer is decoded, and N1 (B)
_NESTED_AUTHORITY_PAIRS = [
    (f"http://h/app/p.php?u=bob&next=a=https://x%26password%3D{_WORD}", _WORD),
    ("http://h/app/p.php?u=bob&next=" + quote(f"a=https://x%26password%3D{_WORD}", safe=""),
     _WORD),
    # ... and N1 (B), the same mechanism (Tomcat's encodeURL of a bare origin, encoded)
    ("http://h/app/c1.php?u=bob&next=" + quote(f"https://host;jsessionid={_HEX}", safe=""),
     _HEX),
    ("http://h/app/c1.php?u=bob&next=" + quote(f"https://host;token={_WORD}", safe=""),
     _WORD),
    ("http://h/app/c1.php?u=bob&next=" + quote(f"https://host;token={_WORD}/app", safe=""),
     _WORD),
    ("http://h/app/c1.php?u=bob&next=" + quote(f"//host;token={_WORD}", safe=""), _WORD),
]
#: 4. a value led by one backslash (not an authority) holding a pair list, one layer
#: below the page's (the raw spelling, whose value decoded once leaves the pair list in
#: a raw ``/\`` segment, has its own test,
#: `test_a_raw_single_backslash_pair_list_is_redacted_by_every_url_redactor`: its
#: `value_holds_secret` and `import_spider` kept it on f939778 too, pinned in
#: `tests/test_redaction_residual_pins.py`)
_BACKSLASH_PAIRS = [
    ("http://h/app/p.php?u=bob&next=" + quote(f"/\\host%26token%3D{_WORD}?y=1", safe=""),
     _WORD),
]
_AFTER_FINAL = (_SPACED_USERINFO + _PAIR_LIST_USERINFO + _NESTED_AUTHORITY_PAIRS
                + _BACKSLASH_PAIRS)


def _next_value(url: str) -> str:
    """The ``next`` value of a page URL (its query's, or its route fragment's)."""
    return re.split(r"[?&]next=", url, maxsplit=1)[1]


def _url_consumers_keeping(url: str, secret: str) -> list[str]:
    """Every URL consumer that keeps ``secret`` of ``url``: both URL redactors, the
    evidence reference, the record redactor, the proxy's request line and ``Referer``
    and its ``Location``, `page_url_is_clean` (True) and `value_holds_secret` of the
    ``next`` value decoded once (False; judged where the code has it)."""
    from fuzzlab.core.trace import safe_ref
    from fuzzlab.proxy.redact import redact
    target = url.split("://", 1)[1].partition("/")[2]
    request = f"GET /{target} HTTP/1.1\r\nHost: h\r\nReferer: {url}\r\n\r\n".encode()
    response = f"HTTP/1.1 302 Found\r\nLocation: {url}\r\n\r\n".encode()
    kept = [name for name, out in (
        ("redact_url", R.redact_url(url)),
        ("redact_url_identifiers", R.redact_url_identifiers(url)),
        ("safe_ref", safe_ref(url)),
        ("redact_for_record", R.redact_for_record("target", url)),
        ("proxy request line and Referer", redact(request).decode("latin-1")),
        ("proxy Location", redact(response).decode("latin-1"))) if _leaks(out, secret)]
    if R.page_url_is_clean(url):
        kept.append("page_url_is_clean")
    holds = getattr(R, "value_holds_secret", None)
    if holds is not None and not holds(unquote(_next_value(url))):
        kept.append("value_holds_secret")
    return kept


@pytest.mark.parametrize("url,secret", _AFTER_FINAL)
def test_an_in_batch_regression_spelling_is_redacted_by_every_url_consumer(url, secret):
    """BUG-0556 after the final round (PA-0549(3c): a regression the batch introduced is
    fixed in the batch): each spelling is redacted by both URL redactors, the evidence
    reference, the record redactor, the proxy's request line, ``Referer`` and
    ``Location``, is never a clean page, and its value is one `value_holds_secret` holds
    for. Every consumer is checked before the one assertion, so 111b6fb fails there,
    naming what kept the secret."""
    assert _leaks(url, secret)                               # not vacuous
    assert _url_consumers_keeping(url, secret) == []
    _api("value_holds_secret")


def test_a_raw_single_backslash_pair_list_is_redacted_by_every_url_redactor():
    """Group 4's raw spelling: round 2 took ``/\\host%26token%3D…`` for a URL and its
    segment's layer ``\\host&token=…`` for another, whose path is never split, so every
    URL redactor, the evidence reference, the record redactor and the proxy kept the
    token f939778 redacted. (Its value decoded once is pinned, see `_BACKSLASH_PAIRS`.)"""
    from fuzzlab.core.trace import safe_ref
    from fuzzlab.proxy.redact import redact
    url = f"http://h/app/p.php?u=bob&next=/\\host%26token%3D{_WORD}?y=1"
    response = f"HTTP/1.1 302 Found\r\nLocation: {url}\r\n\r\n".encode()
    kept = [name for name, out in (
        ("redact_url", R.redact_url(url)),
        ("redact_url_identifiers", R.redact_url_identifiers(url)),
        ("safe_ref", safe_ref(url)),
        ("redact_for_record", R.redact_for_record("target", url)),
        ("proxy Location", redact(response).decode("latin-1"))) if _leaks(out, _WORD)]
    if R.page_url_is_clean(url):
        kept.append("page_url_is_clean")
    assert kept == []


#: The spellings `import_spider` stored a secret of on 111b6fb (``parameter.example``,
#: ``form.entries``, ``form.source_page``; measured, `scratchpad/lanes/REDACTURL/r3/
#: probe_after_final.py`). It stored group 2 clean there: the replaced userinfo changed
#: the value, so `stored_value` blanked it and the page was not clean.
_AFTER_FINAL_STORED = _SPACED_USERINFO + _NESTED_AUTHORITY_PAIRS + _BACKSLASH_PAIRS


@pytest.mark.parametrize("url,secret", _AFTER_FINAL_STORED)
def test_an_in_batch_regression_spelling_stores_no_secret_through_import_spider(
        tmp_path, url, secret):
    """The same spellings through the spider's rows and `import_spider`: no secret in
    ``page``, ``endpoint``, ``parameter.example``, ``form.entries`` or
    ``form.source_page`` (the page the binder fetches, BUG-0544)."""
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", [url])
    with Store(tmp_path / "u.db") as store:
        import_spider(tmp_path / "s.db", store, store.start_run("auto", "h"))
        pages = [r[0] for r in store.conn.execute("SELECT url FROM page").fetchall()]
        dump = _dump(store)
    assert any(p.startswith(urlsplit(url).path) for p in pages)    # not vacuous
    assert not _leaks(dump, secret)


# --- r4: the skeptic's regression after r3 (BUG-0556; PA-0549(3c)) ------------------------
_BS = "\\"
#: A value led by ``\\`` or ``\/`` holding a pair list, below the page's own layer (the
#: skeptic's ``next=%5C%5Cx%26password%3D<word>``, which decodes once to
#: ``\\x&password=<word>``): another sensitive name, the ``\/`` lead, a triple
#: backslash, the leads ``\\/`` and ``\//`` (Node 22 starts the authority after the whole
#: run, `scratchpad/lanes/REDACTURL/r4/whatwg_bs.js`), double encoding, a raw and an
#: encoded ``/x`` after it, the lead left raw, and the same in a route's query. r3 kept
#: such a value URL-shaped (`_url_shaped`) while `_authority_start` read no authority
#: after a backslash, so the pair list was one path segment, never split: 2955f16,
#: 111b6fb and 20cd466 kept the secret in every URL consumer; f939778 split the pairs
#: and redacted it (`r4/probe.py`; `r4/sweep3.py`).
_BACKSLASH_AUTHORITY_PAIRS = [
    ("http://h/app/p.php?u=bob&next=" + quote(f"{_BS * 2}x&password={_WORD}", safe=""),
     _WORD),
    ("http://h/app/p.php?u=bob&next=" + quote(f"{_BS * 2}host&token={_WORD}", safe=""),
     _WORD),
    ("http://h/app/p.php?u=bob&next=" + quote(f"{_BS}/x&password={_WORD}", safe=""),
     _WORD),
    ("http://h/app/p.php?u=bob&next=" + quote(f"{_BS * 3}x&password={_WORD}", safe=""),
     _WORD),
    ("http://h/app/p.php?u=bob&next=" + quote(f"{_BS * 2}/x&password={_WORD}", safe=""),
     _WORD),
    ("http://h/app/p.php?u=bob&next=" + quote(f"{_BS}//x&password={_WORD}", safe=""),
     _WORD),
    ("http://h/app/p.php?u=bob&next="
     + quote(quote(f"{_BS * 2}x&password={_WORD}", safe=""), safe=""), _WORD),
    ("http://h/app/p.php?u=bob&next="
     + quote(f"{_BS * 2}x&password={_WORD}", safe="") + "/x", _WORD),
    ("http://h/app/p.php?u=bob&next=" + quote(f"{_BS * 2}x&password={_WORD}/x", safe=""),
     _WORD),
    (f"http://h/app/p.php?u=bob&next={_BS * 2}x" + quote(f"&password={_WORD}", safe=""),
     _WORD),
    ("http://h/app/#/r?next=" + quote(f"{_BS * 2}x&password={_WORD}", safe=""), _WORD),
]


@pytest.mark.parametrize("url,secret", _BACKSLASH_AUTHORITY_PAIRS)
def test_a_backslash_led_authoritys_pair_list_is_redacted_by_every_url_consumer(url,
                                                                                  secret):
    """r4 (PA-0549(3c)): a value led by ``\\\\`` or ``\\/`` has its authority read after
    the run (`_authority_start`), and one holding a pair list is walked as a value, so
    every URL consumer -- both URL redactors, `safe_ref`, `redact_for_record`, the
    proxy's request line, ``Referer`` and ``Location``, `page_url_is_clean` and
    `value_holds_secret` -- redacts what f939778 redacted. Checked before the one
    assertion, so 20cd466 fails there naming every consumer that kept it."""
    assert _leaks(url, secret)                               # not vacuous
    assert _url_consumers_keeping(url, secret) == []


@pytest.mark.parametrize("url,secret", _BACKSLASH_AUTHORITY_PAIRS)
def test_a_backslash_led_authoritys_pair_list_stores_no_secret_through_import_spider(
        tmp_path, url, secret):
    """The same spellings through the spider's rows and `import_spider` (20cd466 stored
    the secret: the page was clean and the value held none)."""
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", [url])
    with Store(tmp_path / "u.db") as store:
        import_spider(tmp_path / "s.db", store, store.start_run("auto", "h"))
        pages = [r[0] for r in store.conn.execute("SELECT url FROM page").fetchall()]
        dump = _dump(store)
    assert any(p.startswith(urlsplit(url).path) for p in pages)    # not vacuous
    assert not _leaks(dump, secret)


@pytest.mark.parametrize("url", [
    "http://h/app/p.php?u=bob&next=" + quote(f"{_BS * 2}host/x?y=1", safe=""),
    "http://h/app/p.php?u=bob&next=" + quote(f"{_BS}/host&lang=en", safe=""),
    f"http://h/app/p.php?u=bob&next={_BS * 2}host%26lang%3Den",
    f"http://h/app/p.php;v={_BS * 2}host?u=bob",
])
def test_a_clean_backslash_led_value_is_left_byte_identical(url):
    """The guard beside r4's fix: a clean backslash-led value (a host and a path, a
    clean pair list, the lead left raw, a top-level path parameter, whose head is never
    read for an authority) is left byte-identical and the page stays clean."""
    for fn in (R.redact_url, R.redact_url_identifiers):
        assert fn(url) == url, fn.__name__
    assert R.page_url_is_clean(url)


# --- r5: what the pushed tree (7393c90) redacted, by its own readings (BUG-0556) ---------
#: The owner's shipping criterion for the batch: it leaks nothing the pushed tree
#: redacted (PA-0549(3c)). r5's differential against 7393c90 (`scratchpad/lanes/
#: REDACTURL/r5b/`: 214 352 secret-bearing URLs through every URL consumer) found two
#: readings of the pushed tree that the walk dropped, so 290fcfb kept what 7393c90
#: redacted in 4 366 URLs:
#: (1) 7393c90's `redact_query` split a query on '&' only: a pair's name ran to its first
#:     '=' across a ';' (``password;x=…``, ``a;token;b=…``) and a sensitive pair's value
#:     ran to the next '&' across one (``password=pw;<word>``); its record redactor read a
#:     fragment's pairs the same way. The walk split on ';' first and judged ``x`` alone.
#: (2) 7393c90 read the query through ``urlsplit``, which removes every tab, CR and LF
#:     (bpo-43882; the WHATWG parser does the same), so ``p<TAB>assword=…`` and
#:     ``%7<TAB>0assword=…`` were ``password=…``, a 16-hex token split by a tab was one
#:     token, and the URL it returned (``urlunsplit``) was so cleaned whenever it
#:     redacted: `safe_ref`'s record pass and identifier blanking then read a fragment's
#:     pairs, a path parameter and a matrix value with them removed too.
_HALVES = "5b8add2a\t5d98b1a6"                   # 16 hex: two 8-character pieces as written
_PUSHED_TREE_READINGS = [
    # (1) the '&'-only reading
    (f"http://h/app/p.php?password;x={_WORD}", _WORD),
    (f"http://h/app/p.php?u=bob&a;token;b={_WORD}", _WORD),
    (f"http://h/app/p.php?u=bob&api_key;={_WORD}#f", _WORD),
    (f"http://h/app/p.php?jsessionid;x;y={_WORD}&u=bob", _WORD),
    (f"http://h/app/p.php?u=bob&apikey=pw;{_WORD}#f", _WORD),
    (f"http://h/app/p.php?pwd=a;b;{_WORD}&u=bob", _WORD),
    (f"http://h/app/p.php?u=bob&api_key%3Bx=pw;x={_WORD}", _WORD),
    (f"http://h/app/p.php?u=bob&x;password=a b;{_WORD}#f", _WORD),
    (f"http://h/app/#password;x={_WORD}", _WORD),
    (f"http://h/app/#u=1&x;access_token=pw;x={_WORD}", _WORD),
    (f"http://h/app/#/r?secret;x;y=pw;x={_WORD}", _WORD),
    (f"http://h/app/#!/r?u=1&a;access_token;b=pw;{_WORD}", _WORD),
    # (2) a tab, CR or LF urlsplit removed: in a name, inside a name's escape, ...
    (f"http://h/app/p.php?p\tassword={_WORD}", _WORD),
    (f"http://h/app/p.php?u=bob&pa\rssword={_WORD}", _WORD),
    (f"http://h/app/p.php?passw\nord={_WORD}&u=bob", _WORD),
    (f"http://h/app/p.php?u=bob&%7\t0assword={_WORD}", _WORD),
    (f"http://h/app/p.php?u=bob&%\r74oken=pw;{_WORD}", _WORD),
    (f"http://h/app/p.php?access_toke\rn={_WORD}#/r?u=1", _WORD),
    # ... after a query 7393c90 redacted, read again by `safe_ref` with them removed ...
    (f"http://h/app/p.php?token=a&u=1#p\tassword={_WORD}", _WORD),
    (f"http://h/app/p.php?token=a&u=1#%\r70assword={_WORD}", _WORD),
    (f"http://h/app/p.php?token=a#!/r?u=1&toke\rn={_WORD}", _WORD),
    (f"http://h/app/p.php;passwor\td={_WORD}?token=a", _WORD),
    (f"http://h/app/a;s\rid={_WORD}/p.php?token=a", _WORD),
]
#: ... and an identifier split by one (judged by the identifier consumers only: the
#: name-only ones never judged a value's shape, on either tree)
_PUSHED_TREE_IDENTIFIERS = [
    f"http://h/app/p.php?ref={_HALVES}",
    f"http://h/app/p.php?u=bob&k={_HALVES.replace(chr(9), chr(13))}#f",
    f"http://h/app/p.php?token=a#/r?k={_HALVES.replace(chr(9), chr(10))}",
    f"http://h/app/p.php?p\tassword=a&k={_HALVES.replace(chr(9), chr(10))}",
    f"http://h/app/a;k={_HALVES}/p.php?token=a",
]


def _pushed_consumers_keeping(url: str, secret: str) -> list[str]:
    """Every consumer 7393c90 had of a page URL that keeps ``secret``: both URL
    redactors, the evidence reference (`core.trace.safe_ref`), the record redactor,
    `page_url_is_clean` (True) and, for a URL an HTTP message can carry on one line (no
    LF), the proxy's request line and ``Location``."""
    from fuzzlab.core.trace import safe_ref
    from fuzzlab.proxy.redact import redact
    outs = [("redact_url", R.redact_url(url)),
            ("redact_url_identifiers", R.redact_url_identifiers(url)),
            ("safe_ref", safe_ref(url)),
            ("redact_for_record", R.redact_for_record("target", url))]
    if "\n" not in url:
        target = url.split("://", 1)[1].partition("/")[2]
        for name, raw in (
                ("proxy request line", f"GET /{target} HTTP/1.1\r\nHost: h\r\n\r\n"),
                ("proxy Location", f"HTTP/1.1 302 Found\r\nLocation: {url}\r\n\r\n")):
            outs.append((name, redact(raw.encode()).decode("latin-1")))
    kept = [name for name, out in outs if _leaks(out, secret)]
    if R.page_url_is_clean(url):
        kept.append("page_url_is_clean")
    return kept


@pytest.mark.parametrize("url,secret", _PUSHED_TREE_READINGS)
def test_a_secret_the_pushed_tree_redacted_is_redacted_by_every_url_consumer(url, secret):
    """r5 (PA-0549(3c), the owner's shipping criterion): a secret 7393c90 redacted by
    its '&'-only reading of a pair list or its ``urlsplit`` reading (tabs, CRs and LFs
    removed) is redacted by every URL consumer: the walk reads each pair both ways and
    each name and identifier both ways, and returns a URL holding a tab, CR or LF so
    cleaned whenever either reading redacts (`_walk_url`). Every consumer is checked
    before the one assertion, so 290fcfb fails there naming what kept it."""
    assert _leaks(url, secret)                               # not vacuous
    assert _pushed_consumers_keeping(url, secret) == []


@pytest.mark.parametrize("url", _PUSHED_TREE_IDENTIFIERS)
def test_an_identifier_the_pushed_tree_read_whole_is_redacted_by_every_identifier_consumer(
        url):
    """r5: a 16-hex token split by a tab, CR or LF is one token to ``urlsplit`` (7393c90
    blanked it in a query and, after a query it redacted, `safe_ref` blanked it in a
    route's query or a matrix value) and two 8-character pieces as written; the walk
    judges a value both ways (`_identifier_like`). Checked in `redact_url_identifiers`,
    `safe_ref` and `page_url_is_clean` before the one assertion."""
    from fuzzlab.core.trace import safe_ref
    assert _leaks(url, _HALVES)                              # not vacuous
    kept = [name for name, out in (
        ("redact_url_identifiers", R.redact_url_identifiers(url)),
        ("safe_ref", safe_ref(url))) if _leaks(out, _HALVES)]
    if R.page_url_is_clean(url):
        kept.append("page_url_is_clean")
    assert kept == []


@pytest.mark.parametrize("url", [
    f"http://h/app/p.php?u=bob&next=host%253Btoken%253D{_WORD}%2Fx%3Ba%3D1",
    f"http://h/app/p.php?u=bob&host%3Btoken%3D{_WORD};a=1",
    f"http://h/app/#/r?u=1&host%3Btoken%3D{_WORD};a=1",
])
def test_the_amp_reading_never_replaces_the_semicolon_reading(url):
    """The guard beside r5's '&'-only reading: an '&' part whose name, read to its first
    '=', holds a sensitive token only because a secret sits inside it
    (``host%3Btoken%3D<word>;a=1``) still has each ``;`` pair walked first, so the
    secret inside the name is redacted too (r5's first draft replaced the ``;`` reading
    by the '&' one and kept 450 URLs of its differential that 290fcfb redacted)."""
    assert _leaks(url, _WORD)                                # not vacuous
    for fn in (R.redact_url, R.redact_url_identifiers):
        assert not _leaks(fn(url), _WORD), fn.__name__


@pytest.mark.parametrize("url", [
    "http://h/app/p.php?u=bob&lang;x=en",
    "http://h/app/p.php?u=bob&sort=asc;dir=up&next=/x",
    "http://h/app/p.php?q=a\tb&u=1",
    "http://h/app/p.php?u=bob#/r?lang;x=en",
    "http://h/app/a;v=1\t2/p.php?u=1",
])
def test_a_clean_semicolon_part_or_tab_is_left_byte_identical(url):
    """The guard beside r5's fix: a clean ``&`` part holding a ``;`` and a clean URL
    holding a tab are left byte-identical (the cleaned reading is returned only when a
    reading redacts) and the page stays clean."""
    for fn in (R.redact_url, R.redact_url_identifiers):
        assert fn(url) == url, fn.__name__
    assert R.page_url_is_clean(url)


@pytest.mark.parametrize("value", [
    f"http://bob:pw {_PASS}@127.0.0.1:3000/app/",
    f"http://bob:pw {_PASS}@127.0.0.1:3000/app/?q=1",
    f"//bob:pw {_PASS}@127.0.0.1:3000/app/",
])
def test_a_project_record_strips_a_top_level_userinfo_holding_a_space(tmp_path, value):
    """BUG-0556 after the final round: `_URL_USERINFO` stopped at whitespace, so a
    top-level userinfo holding a space (Node 22: password ``pw%20<word>``) was kept in
    ``launch.argv``, ``launch.target`` and ``project.targets`` (on f939778 too); a span
    crossing whitespace is now matched when it holds no pair separator. Through the real
    writers too."""
    from fuzzlab.core import project
    assert _PASS not in R.redact_for_record("target", value)
    with Store(tmp_path / "s.db") as store:
        project.ensure_metadata(store, "s")
        project.insert_launch(store, "auto", [("", "fuzzlab"), ("url", value)], value)
        project.add_target(store, value)
        dump = _dump(store)
    assert "127.0.0.1:3000/app/" in dump                    # not vacuous
    assert _PASS not in dump


def test_a_records_spaced_userinfo_never_reaches_a_later_pair():
    """The guard on the spaced userinfo: a span crossing whitespace stops at a pair
    separator, so ``?next=//x q&password=…@…`` stays a pair the walk redacts (a span
    crossing it would delete the name ``password``: residual pinned for the no-space
    form, `tests/test_redaction_residual_pins.py`)."""
    url = f"http://127.0.0.1:3000/app/?next=//x q&password=Hunter@{_WORD}"
    out = R.redact_for_record("target", url)
    assert _WORD not in out and "password=" in out, out


# --- r6: layered on the pushed redactor (BUG-0556, the owner's design) -------------------
#: The independent check of 144d234 found five classes 144d234 kept that 7393c90 redacted
#: (journal wf_9a1e5879-609; regenerated in `scratchpad/lanes/REDACTURL/r6/checkwork/`):
#: R1 `safe_ref` ran the walk before the record rule's userinfo regexes, so a userinfo
#: password holding a ';' or '&' before a piece the walk redacted lost its '@' and kept
#: its start; R2 the record redactor (and `safe_ref`) returned a URL holding a tab, CR or
#: LF cleaned, merging the pieces 7393c90 split on that whitespace; R3 the proxy read a
#: quoted ``Refresh`` URL only inside its quotes, and only the first ``url=``; A1 a URL
#: ``urlsplit`` rejects made 7393c90 raise, and its callers fell back (not always
#: withholding it: proxy history keeps what precedes the ``?``, family (d)); A2 7393c90
#: collapsed a duplicate ``Location`` / ``Content-Location`` into the one it rewrote. r6
#: runs the pushed tree's own redactor first, frozen (`core.redaction_floor`), and the
#: walk on its output: each case below fails on 144d234 at its own assertion.
_R1_USERINFO = [
    f"http://h/app/p.php?u=1&next=https://bob:{_PASS};a70000000123f3e9c1b5d2@host/x",
    f"http://h/app/p.php?u=1&next=https://bob:{_PASS}&a70000000123f3e9c1b5d2@host/x",
    f"http://h/go/https://bob:{_PASS};sid=x@host/x",
    f"http://h/p#https://bob:{_PASS}%26x%3Da70000000123f3e9c1b5d2@host/x",
    f"http://h/app/p.php?u=1&next=%2Fcb%3Ftoken%3DX%26a%3D1 bob:{_PASS}@host",
    f"http://h/app/p.php?u=bob#next=https://bob:{_PASS};Zx81mQ2vT9kLw3nB@host/x",
]


@pytest.mark.parametrize("url", _R1_USERINFO)
def test_r6_r1_the_evidence_reference_keeps_no_userinfo_the_pushed_tree_removed(url):
    """R1: 7393c90's `safe_ref` removed the whole userinfo (its record rule's regex ran
    on its URL redactor's output); 144d234's walk ran first, cut the ``@`` and kept
    ``bob:<password>;``. The floor runs first now."""
    from fuzzlab.core.trace import safe_ref
    assert _leaks(url, _PASS)                                # not vacuous
    out = safe_ref(url)
    assert not _leaks(out, _PASS), out


def test_r6_r1_import_spider_under_a_trace_recorder_stores_no_such_userinfo(tmp_path):
    """R1 through the store: `fuzzlab auto` imports a crawl with its run's trace recorder
    active, and `tools.observe` cites each page by `safe_ref` in ``trace_event`` and
    ``dg_flow`` rows; 144d234 stored the password's start there (146 URLs of the
    check's corpus), 7393c90 none. Two spellings are left out, each kept by both trees
    elsewhere, not this class: a userinfo in the page's own path (``/go/https://bob:<pw>
    @…``: ``page.url``, `store_url`) and one cut by a raw ``&`` of the page's query
    (``next=https://bob:<pw>&…``: the pair's value holds no ``@``; pinned)."""
    from fuzzlab.core import trace
    from fuzzlab.tools.store_adapter import import_spider
    urls = [u.replace("/app/", f"/a{i}/", 1).replace("http://h/p#", f"http://h/a{i}/p#", 1)
            for i, u in enumerate(_R1_USERINFO)
            if "/go/" not in u and f"{_PASS}&" not in u]
    _spider_db(tmp_path / "s.db", urls)
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        recorder = trace.TraceRecorder(store, run)
        with trace.recording(recorder):
            import_spider(tmp_path / "s.db", store, run)
        recorder.close()
        events = store.conn.execute("SELECT COUNT(*) FROM trace_event").fetchone()[0]
        dump = _dump(store)
    assert events > 0 and "/a5/p.php" in dump                # not vacuous: traced pages
    assert not _leaks(dump, _PASS)


_R2_MERGED = [tpl.format(ws=ws, W=_WORD) for ws, tpl in [
    ("\t", "http://h/app/p.php?u=bob&n{ws}ext=/cb?password=v;{W}"),
    ("\r", "http://h/app/p.php?u=bob{ws}next=/cb?sid=pw;{W}"),
    ("\n", "http://h/app/p.php?u=bob&n{ws}ext=https://host/cb?pwd=a;b;{W}"),
    ("\r\n", "http://h/app/p.php?u=b{ws}ob&next=cb.php?password=v;{W}"),
    ("\t\t", "http://h/app/p.php?u=bob{ws}next=/cb?sid=pw;{W}"),
    ("\r", "http://h/app/p.php?u=bob&n{ws}ext=/cb?password=v;{W}"),
    ("\n", "http://h/app/p.php?u=b{ws}ob&next=cb.php?password=v;{W}"),
    ("\t", "http://h/app/p.php?u=bob&n{ws}ext=https://host/cb?pwd=a;b;{W}"),
]]


@pytest.mark.parametrize("url", _R2_MERGED)
def test_r6_r2_a_tab_cr_or_lf_never_merges_what_the_pushed_tree_split(url):
    """R2: 7393c90's record redactor split a value on whitespace and read
    ``ext=/cb?password=v;<word>`` as a URL of its own, its value running past the ``;``;
    144d234's walk returned the whole value with the tab removed, the nested query cut at
    the ``;``, and kept the word (450 of the check's 2 268 variants), in the record
    redactor and in `safe_ref`."""
    from fuzzlab.core.trace import safe_ref
    assert _leaks(url, _WORD)                                # not vacuous
    kept = [name for name, out in (("redact_for_record", R.redact_for_record("target", url)),
                                   ("safe_ref", safe_ref(url))) if _leaks(out, _WORD)]
    assert kept == []


@pytest.mark.parametrize("value", [
    f'0;url="http://h/?a=1"&password={_WORD}',
    f'0;url="http://a/" ; url=http://b/?password={_WORD}',
    f"0; url='http://h/x?a=1'&token={_WORD}",
    f'0;URL="/x?a=1"&x=1&token={_WORD}',
])
def test_r6_r3_a_quoted_refresh_url_keeps_nothing_the_pushed_tree_redacted(value):
    """R3: 7393c90 passed every ``url=`` run of ``Refresh`` -- quotes and the tail after
    them included -- to its URL redactor; 144d234 walked only the quoted URL and only the
    first ``url=``, and kept the rest (384 of the check's 1 410 secret-bearing values)."""
    from fuzzlab.proxy.redact import redact
    raw = f"HTTP/1.1 200 OK\r\nRefresh: {value}\r\nContent-Length: 0\r\n\r\n".encode()
    assert _WORD.encode() in raw                             # not vacuous
    out = redact(raw).decode("latin-1")
    assert not _leaks(out, _WORD), out


#: A URL ``urlsplit`` rejects (an unclosed or invalid bracketed host, a netloc that
#: NFKC-normalises to a delimiter), holding a secret 144d234's walk keeps (the pinned
#: ``/``-led value, `tests/test_redaction_residual_pins.py`).
_A1_REJECTED = [
    f"http://[h/app/p.php?u=bob&next=%2F%5Cx%26password%3D{_WORD}",
    f"http://[::1]x/app/p.php?u=bob&next=%2F%5Cx%26password%3D{_WORD}",
    f"http://h＠x/app/p.php?u=bob&next=%2F%5Cx%26password%3D{_WORD}",
]


def _withheld_or(fn, *args):
    """``fn(*args)``, or None when it raises ``ValueError`` (its caller withholds)."""
    try:
        return fn(*args)
    except ValueError:
        return None


@pytest.mark.parametrize("url", _A1_REJECTED)
def test_r6_a1_a_url_urlsplit_rejects_is_withheld_by_every_consumer(url):
    """A1: 7393c90's URL redactors raised on such a URL and each caller handled the raise
    as it does now: `safe_ref` withholds it (``(unparseable URL withheld)``), the history
    writer's ``_prepare_contained`` stores the flow with every body `OMIT_FAILED` and its
    URL cut at the first ``?`` -- what precedes the ``?`` as received, which is not
    withholding it (family (d), pinned in `tests/test_redaction_residual_pins.py`; the
    query's secret, the one this test plants, is cut); 144d234's walk never raised and
    kept the secret it keeps
    (1 329 URLs of the check's corpus). The floor raises again: each redactor raises
    ``ValueError`` or keeps nothing, `page_url_is_clean` never answers True, and the
    proxy's request line, ``Location``, ``Content-Location`` and ``Refresh`` too."""
    from urllib.parse import urlsplit as _urlsplit

    from fuzzlab.core.trace import safe_ref
    from fuzzlab.proxy.redact import redact
    assert _leaks(url, _WORD)                                # not vacuous
    with pytest.raises(ValueError):
        _urlsplit(url)
    outs = [("redact_url", _withheld_or(R.redact_url, url)),
            ("redact_url_identifiers", _withheld_or(R.redact_url_identifiers, url)),
            ("safe_ref", safe_ref(url))]
    if "＠" not in url:                  # the proxy reads latin-1: a byte-level URL
        for name, raw in (("request line", f"GET {url} HTTP/1.1\r\nHost: h\r\n\r\n"),
                          ("Location", f"HTTP/1.1 302 Found\r\nLocation: {url}\r\n\r\n"),
                          ("Content-Location",
                           f"HTTP/1.1 200 OK\r\nContent-Location: {url}\r\n\r\n"),
                          ("Refresh", f"HTTP/1.1 200 OK\r\nRefresh: 0;url={url}\r\n\r\n")):
            out = _withheld_or(redact, raw.encode("latin-1"))
            outs.append((name, None if out is None else out.decode("latin-1")))
    kept = [name for name, out in outs if out is not None and _leaks(out, _WORD)]
    if _withheld_or(R.page_url_is_clean, url) is True:
        kept.append("page_url_is_clean")
    assert kept == []


def test_r6_a1_proxy_history_stores_a_flow_its_floor_rejects_bodies_omitted_query_cut(
        tmp_path):
    """A1 through the store: the history writer contains a redaction failure per flow
    (``_prepare_contained``: every body `OMIT_FAILED`, the URL cut at its first ``?``), as
    on 7393c90, so the secret planted in the query is not stored; 144d234 stored the raw
    request line's secret. The flow is stored, not withheld: what precedes the ``?`` is
    kept as received (a path parameter there: family (d), pinned in
    `tests/test_redaction_residual_pins.py`). Renamed at the merge from
    ``test_r6_a1_proxy_history_withholds_a_flow_whose_url_its_floor_rejects``, a name
    that claimed more than it asserts (BUG-0556, "At the merge", R3(a))."""
    from fuzzlab.core.redaction import OMIT_FAILED
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    url = _A1_REJECTED[0]
    rq = f"GET {url} HTTP/1.1\r\nHost: h\r\n\r\n".encode()
    rs = f"HTTP/1.1 302 Found\r\nLocation: {url}\r\n\r\n".encode()
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=5)
        h.record(FlowRecord("GET", url, "h", 302, raw_request=rq, raw_response=rs))
        assert h.flush() == 1                                # not vacuous: one flow stored
        dump = _dump(store)
    assert not _leaks(dump, _WORD)
    assert OMIT_FAILED.decode() in dump


@pytest.mark.parametrize("target", _A1_REJECTED[:2])
def test_r6_a1_import_audit_withholds_a_target_its_floor_rejects_and_imports_the_rest(
        tmp_path, target):
    """A1 on the one caller the batch added that 7393c90 did not have (`import_audit`'s
    target identifier, which 7393c90 and 144d234 stored raw, the secret with it): where
    the floor raises, the import never fails -- the target is withheld, as `safe_ref`
    withholds a URL it cannot parse (`store_adapter`'s own marker), and every other
    finding is imported. r6's first draft let the floor's ``ValueError`` propagate and
    failed the whole import (the first assertion below)."""
    from fuzzlab.tools import fetcher as F
    from fuzzlab.tools.store_adapter import import_audit
    page = "http://h/app/p.php?u=bob"
    db = F.setup_results_db(str(tmp_path / "a.db"))
    for rule, ident in (("rule_a", target), ("rule_b", "u")):
        db.execute("INSERT INTO findings (page_url, category, transaction_type, "
                   "target_identifier, html_context) VALUES (?,?,?,?,?)",
                   (page, "cat", rule, ident, f"value 'bob' reflected ({rule})"))
    db.commit()
    db.close()
    assert _leaks(target, _WORD)                             # not vacuous
    with Store(tmp_path / "u.db") as store:
        failed = None
        try:
            counts = import_audit(tmp_path / "a.db", store, store.start_run("auditor", "h"))
        except ValueError as exc:                            # the floor's raise, unhandled
            failed, counts = exc, {}
        targets = sorted(json.loads(e)["target_identifier"] for (e,) in store.conn.execute(
            "SELECT evidence FROM candidate").fetchall())
        dump = _dump(store)
    assert failed is None, f"the import failed: {failed!r}"
    assert not _leaks(dump, _WORD)
    from fuzzlab.tools.store_adapter import AUDIT_TEXT_WITHHELD
    assert counts == {"candidate": 2} and targets == sorted([AUDIT_TEXT_WITHHELD, "u"])


# --- r6 review: what the independent checks of 3615cfb found ------------------------------
def _audit_findings(tmp_path, rows) -> Path:
    """A legacy auditor's results DB holding ``rows`` (page URL, rule, target, context)."""
    from fuzzlab.tools import fetcher as F
    db = F.setup_results_db(str(tmp_path / "a.db"))
    for page, rule, ident, context in rows:
        db.execute("INSERT INTO findings (page_url, category, transaction_type, "
                   "target_identifier, html_context) VALUES (?,?,?,?,?)",
                   (page, "cat", rule, ident, context))
    db.commit()
    db.close()
    return tmp_path / "a.db"


def _import_audit_or_failure(tmp_path, audit_db):
    """`import_audit` into a fresh store: ``(counts, the failure or None, endpoint urls,
    candidate rows, the store's dump)``. A ``TypeError`` is a failure too (a BLOB page:
    at the merge, D1(b))."""
    from fuzzlab.tools.store_adapter import import_audit
    with Store(tmp_path / "u.db") as store:
        failed, counts = None, {}
        try:
            counts = import_audit(audit_db, store, store.start_run("auditor", "h"))
        except (ValueError, TypeError) as exc:
            failed = exc
        endpoints = [u for (u,) in store.conn.execute("SELECT url FROM endpoint")]
        candidates = [tuple(r) for r in store.conn.execute(
            "SELECT parameter_id, evidence, sink_context FROM candidate ORDER BY id")]
        return counts, failed, endpoints, candidates, _dump(store)


#: A finding page that is not an absolute URL and holds ``[`` or ``]`` in its first
#: segment (or holds them after a leading Unicode space): `core.urls.canonical_origin`
#: strips whitespace and prefixes ``http://``, and ``urlsplit`` then rejects the netloc.
#: 7393c90's `import_audit` stored ``to_path`` of each and imported it.
_D1_PAGES = [
    f"x[y/app/p.php?u=1&token={_WORD}",
    "h]/app/p.php?u=1",
    "[h/app/p.php",
    f"x[1]/app/p.php?u=1&password={_WORD}",
    f"\u3000http://[h/app/p.php?token={_WORD}",
    "\xa0http://h]/app/p.php",
]


@pytest.mark.parametrize("page", _D1_PAGES)
def test_r6_review_d1_import_audit_imports_a_page_no_origin_reads_as_the_pushed_tree_did(
        tmp_path, page):
    """D1 (the differential check of 3615cfb): the batch's `import_audit` read each
    finding page's origin (`_main_origin`, `_audit_endpoint` -> `canonical_origin`,
    `store_url`), which raises ``ValueError("Invalid IPv6 URL")`` on such a page, and
    failed the whole import where 7393c90's (``to_path`` only) imported it. The page
    names no origin now: it is stored by its path, as 7393c90 stored it, and nothing
    7393c90 redacted is stored (its ``to_path`` dropped the query)."""
    from fuzzlab.core.urls import to_path
    good = "http://h/app/q.php?u=1"
    audit_db = _audit_findings(tmp_path, [
        (page, "rule_a", "u", f"called from {page}"),
        (good, "rule_b", "u", "value reflected")])
    counts, failed, endpoints, _candidates, dump = _import_audit_or_failure(tmp_path,
                                                                            audit_db)
    assert failed is None, f"the import failed: {failed!r}"
    assert counts == {"candidate": 2}
    assert sorted(endpoints) == sorted([to_path(page), "/app/q.php"])
    assert not _leaks(dump, _WORD)


#: A finding page ``urlsplit`` rejects as written, so ``to_path`` rejects it too: 7393c90's
#: `import_audit` raised there, and r6's raised at `_main_origin` before `_audit_text`'s
#: page-URL branch could withhold anything.
_R4_PAGES = [
    f"http://[h/app/p.php?u=bob&password={_PASS}",
    f"//[h/app/p.php?u=bob&token={_PASS}",
]


@pytest.mark.parametrize("page", _R4_PAGES)
def test_r6_review_r4_import_audit_withholds_the_texts_of_a_page_its_floor_rejects(
        tmp_path, page):
    """R4 (the records review of 3615cfb): FR-AUD-31, CC-AUD-0059 and the r6 commit said
    a text whose page URL the floor rejects is stored as `AUDIT_TEXT_WITHHELD` and the
    import goes on, but `_main_origin` raised first, so `_audit_text`'s page-URL branch
    was unreachable. Through `import_audit`: such a finding is imported with no endpoint
    (its ``parameter_id`` NULL), its target and context withheld whole (they may quote
    the page URL the owner cannot read), and every other finding is imported."""
    good = "http://h/app/q.php?u=1"
    audit_db = _audit_findings(tmp_path, [
        (page, "rule_a", "u", f"called from {page}"),
        (good, "rule_b", "u", "value reflected")])
    counts, failed, endpoints, candidates, dump = _import_audit_or_failure(tmp_path,
                                                                           audit_db)
    assert failed is None, f"the import failed: {failed!r}"
    assert counts == {"candidate": 2} and endpoints == ["/app/q.php"]
    from fuzzlab.tools.store_adapter import AUDIT_TEXT_WITHHELD
    withheld = candidates[0]
    assert withheld[0] is None
    assert json.loads(withheld[1])["target_identifier"] == AUDIT_TEXT_WITHHELD
    assert withheld[2] == AUDIT_TEXT_WITHHELD
    assert json.loads(candidates[1][1])["target_identifier"] == "u"
    assert not _leaks(dump, _PASS)


# --- at the merge (coordinator's records round, owner-approved): D1(b) --------------------
#: A finding page stored as a BLOB whose path is empty: 7393c90's `import_audit` read it
#: with ``to_path`` (``urlparse(b"http://h").path`` is ``b""``, so ``"/"``) and imported
#: it; the batch's raised ``TypeError`` in `canonical_origin` (`_readable_origin` and
#: `_audit_endpoint` caught ``ValueError`` only) and stored nothing. Unreachable from the
#: auditor itself (`fetcher.log_finding` writes the crawler's str URL), reachable from any
#: other writer of a findings DB.
_D1B_PAGES = [b"http://h", b"x://", b"http://h?u=bob"]


@pytest.mark.parametrize("page", _D1B_PAGES)
def test_merge_d1b_import_audit_imports_a_blob_page_with_no_path_as_the_pushed_tree_did(
        tmp_path, page):
    """D1(b) (the fix check of 08eb900): a regression of the batch against 7393c90, fixed
    at the merge. The page names no origin, so it is stored by its path, ``/``, as 7393c90
    stored it, with no parameter, and every finding is imported. A BLOB page with a path
    (``b"http://h/app/p.php"``) fails the import on 7393c90 too (``to_path``'s
    ``TypeError``): pinned in `tests/test_redaction_residual_pins.py`, not here."""
    good = "http://h/app/q.php?u=1"
    audit_db = _audit_findings(tmp_path, [
        (page, "rule_a", "u", f"called from {page!r}"),
        (good, "rule_b", "u", "value reflected")])
    counts, failed, endpoints, candidates, _dump_text = _import_audit_or_failure(
        tmp_path, audit_db)
    assert failed is None, f"the import failed: {failed!r}"
    assert counts == {"candidate": 2}
    assert sorted(endpoints) == ["/", "/app/q.php"]                 # 7393c90's endpoints
    assert candidates[0][0] is None and json.loads(candidates[0][1])["target_identifier"] \
        == "u"


@pytest.mark.parametrize("headers", [
    f"Location: http://h/?token=a\r\nLocation: http://user:{_WORD}@h/app",
    f"Location: http://h/?token=a\r\nLocation: http://h/app/p.php?u=bob&next=%2F%5Cx%26"
    f"password%3D{_WORD}",
    f"Content-Location: /x?sid=a\r\nContent-Location: http://user:{_WORD}@h/app",
    f"Content-Location: /x?sid=a\r\nContent-Location: /y?u=1&next=%2F%5Cx%26password%3D"
    f"{_WORD}",
])
def test_r6_a2_a_duplicate_url_header_keeps_nothing_the_pushed_tree_dropped(headers):
    """A2: when 7393c90 rewrote a ``Location`` or ``Content-Location`` it replaced every
    occurrence by the one rewritten value (``RawMessage.with_header``), dropping a
    duplicate holding a secret its walk keeps (a userinfo, the pinned ``/``-led value);
    144d234 kept every duplicate and walked each. The floor collapses it again."""
    from fuzzlab.proxy.redact import redact
    raw = f"HTTP/1.1 302 Found\r\n{headers}\r\nContent-Length: 0\r\n\r\n".encode()
    assert _WORD.encode() in raw                             # not vacuous
    out = redact(raw).decode("latin-1")
    assert not _leaks(out, _WORD), out


# --- what reaches the store -------------------------------------------------------------
def _dump(store: Store) -> str:
    out = []
    for (table,) in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        for row in store.conn.execute(f'SELECT * FROM "{table}"').fetchall():
            out.extend(str(v) for v in tuple(row))
    return "\n".join(out)


def _spider_db(path: Path, urls) -> None:
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(path))
    sm.reset()
    sm.mark_visited("http://h/app/start.php", 200, 0)
    for url in urls:
        sm.mark_visited(url, 200, 1, found_from=url)
    sm.close()


def _leaked(dump: str) -> list:
    return sorted({n for n, s in SECRETS if _leaks(dump, s)})


def test_no_generated_spelling_reaches_the_store_through_import_spider(tmp_path):
    """Every generated page URL, also as the page its links were found on: no secret
    byte in ``page``, ``endpoint``, ``parameter.example``, ``form.entries`` or
    ``form.source_page`` (BUG-0556; BUG-0120's parameter examples included)."""
    from fuzzlab.tools.store_adapter import import_spider
    urls = [_case_url(c) for c in CASES] + _MATRIX
    _spider_db(tmp_path / "s.db", urls)
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        counts = import_spider(tmp_path / "s.db", store, run)
        pages = {r[0] for r in store.conn.execute("SELECT url FROM page").fetchall()}
        # not vacuous: a page row per stored path (a secret path parameter dropped, a
        # clean one kept), and the generated queries became link sets and examples
        assert pages == {"/app/start.php", "/app/p.php", "/app/a/b.php",
                         "/app/a;x=1/b/c.php"}
        assert counts["link_set"] > 50 and counts["parameter"] > 200   # (74 and 274)
        assert _leaked(_dump(store)) == []


@pytest.mark.parametrize("url", [
    f"http://h/app/p.php?u=bob&next=%2Fview%3Fticket%3D{_HEX}",
    f"http://h/app/p.php?u=bob&next=/view?ticket={_HEX}",
    f"http://h/app/p.php?u=bob&return=https%3A%2F%2Fhost%2Fcb%3Faccess_token%3D{_WORD}",
    f"http://h/app/p.php?u=bob&a=1;token={_HEX}",
    f"http://h/app/a;jsessionid={_HEX}/b.php?u=bob&v=2",
    f"http://h/app/q.php?next=%2Fview%3Fticket%3D{_HEX}",
])
def test_the_reported_spellings_store_no_secret_through_import_spider(tmp_path, url):
    """The AU-REQID78 round-1 fix check's five spellings (and a one-name link): before
    BUG-0556 each reached ``page.url``, ``parameter.example``, ``form.entries`` or
    ``form.source_page``."""
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", [url])
    with Store(tmp_path / "u.db") as store:
        import_spider(tmp_path / "s.db", store, store.start_run("auto", "h"))
        dump = _dump(store)
    assert _HEX not in dump and _WORD not in dump
    assert "/app/" in dump                                   # the page itself is kept


def test_no_generated_spelling_reaches_the_store_through_import_disco(tmp_path):
    """A disco capture redacts names only (`redact_url`); the importer stores every URL,
    query value and example through the owner: page loads, a captured POST's URL and
    the explorer's page URLs."""
    from fuzzlab.disco.capture import append_record, make_record
    from fuzzlab.tools import store_adapter
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    urls = [_case_url(c).replace("http://h", "http://127.0.0.1:3000") for c in CASES]
    for i, url in enumerate(urls):
        append_record(run_dir / "capture.jsonl", make_record(
            kind="http", t=float(i), action_id=f"act-{i}", method="GET" if i % 2 else "POST",
            url=url, req_headers={"Content-Type": store_adapter.FORM_URLENCODED},
            req_body=b"" if i % 2 else b"q=hello", status=200,
            res_headers={"Content-Type": "text/html"}, res_body=b"ok"))
    (run_dir / "actions.jsonl").write_text("".join(
        json.dumps({"seq": i, "url": u}) + "\n" for i, u in enumerate(urls[:200])))
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        counts = store_adapter.import_disco(run_dir, store, run)
        assert counts["page"] > 0 and counts["request_form"] > 0   # not vacuous
        assert _leaked(_dump(store)) == []


@pytest.mark.parametrize("url,secret", [(u, s) for u, s, _n in _LAYER_LEFT_ENCODED] + [
    (f"http://h/app/p.php?u=bob&next={quote(_USERINFO, safe=sp)}", "CanaryPassWord")
    for sp in ("", "/", ":/")])
def test_the_review_round_1_spellings_store_no_secret_through_import_spider(tmp_path, url,
                                                                           secret):
    """Review round 1 (RU-1/RU-6, RU-2): each reached ``form.source_page`` (and, double
    encoded, ``parameter.example`` and ``form.entries``) on c3a13f7."""
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", [url])
    with Store(tmp_path / "u.db") as store:
        import_spider(tmp_path / "s.db", store, store.start_run("auto", "h"))
        pages = [r[0] for r in store.conn.execute("SELECT url FROM page").fetchall()]
        dump = _dump(store)
    assert urlsplit(url).path in pages                       # the page itself is kept
    assert not _leaks(dump, secret)


def test_a_crawled_forms_nested_or_identifier_value_is_blanked_and_bound_fresh(tmp_path):
    """A crawled form's default value and its action's query are stored values too: a
    hidden ``next`` holding a nested token and a hidden token are blanked and named in
    the replay recipe (FR-FUZZ-67); an ordinary value is kept."""
    from bs4 import BeautifulSoup

    from fuzzlab.core.forms import form_record
    from fuzzlab.tools.spider import StorageManager
    from fuzzlab.tools.store_adapter import import_spider
    html = (f"<form method=post action='/app/do.php?next=%2Fview%3Fticket%3D{_HEX}'>"
            f"<input type=hidden name=next value='/view?ticket={_HEX}'>"
            f"<input type=hidden name=state value='{_HEX}'>"
            "<input type=hidden name=back value='/account'><input name=q></form>")
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    sm.record_form(form_record(BeautifulSoup(html, "html.parser").find("form"),
                               "http://h/app/f.php"))
    sm.close()
    with Store(tmp_path / "u.db") as store:
        import_spider(tmp_path / "s.db", store, store.start_run("auto", "h"))
        row = store.conn.execute("SELECT entries, fresh FROM form").fetchone()
        assert _HEX not in _dump(store)
    assert json.loads(row["entries"]) == [["next", ""], ["state", ""], ["back", "/account"],
                                          ["q", "fuzzlab"]]
    assert json.loads(row["fresh"]) == ["next", "state"]


# --- every other writer of a URL ---------------------------------------------------------
def test_proxy_history_and_the_http_recorder_store_no_nested_credential(tmp_path):
    """The name rule at any depth reaches the proxy's flow history (request target and
    raw request) and the core HTTP client's recorder: both call `redact_url`."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient, Request
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    named = [c for c in CASES if c[1] in dict(NAMED)][::4]
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=500)
        for case in named:
            url = _case_url(case)
            target = url.split("http://h", 1)[1]
            h.record(FlowRecord("GET", url, "h", 200,
                                raw_request=f"GET {target} HTTP/1.1\r\nHost: h\r\n\r\n".encode(),
                                raw_response=b"HTTP/1.1 200 OK\r\n\r\n"))
        assert h.flush() == len(named)

        def transport(method, url, headers, body, timeout):
            return 200, {}, b"ok"
        run = store.start_run("t", "x")
        client = HttpClient(RequestBudget(len(named) + 1), ["h"], store=store, run_id=run,
                            transport=transport)
        for case in named:
            client.send(Request("GET", _case_url(case)))
        assert _WORD not in _dump(store)
        assert store.conn.execute("SELECT COUNT(*) FROM flow").fetchone()[0] >= len(named)


@pytest.mark.parametrize("name", [n for n, _s in NAMED])
def test_proxy_history_redacts_a_path_parameter_in_a_message_with_no_query(tmp_path, name):
    """Review round 1, RU-7: `proxy.redact` passed the request target and the URL
    headers to `redact_url` only when they held a ``?``, so a ``;jsessionid=`` path
    parameter with no query (Tomcat's URL rewriting) stayed in the stored raw request
    and response and their full-text index, though the flow's URL was redacted."""
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    targets = [f"/app/a;{name}={_WORD}/b.php", f"/app/b.php;{name}={_WORD}",
               f"/app/a;x=1;{name}={_WORD}/b/c.php"]
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=50)
        for target in targets:
            h.record(FlowRecord(
                "GET", "http://h" + target, "h", 302,
                raw_request=f"GET {target} HTTP/1.1\r\nHost: h\r\n\r\n".encode(),
                raw_response=(f"HTTP/1.1 302 Found\r\nLocation: http://h/app/;{name}={_WORD}"
                              f"\r\nContent-Location: /x;{name}={_WORD}\r\n"
                              f"Refresh: 0; url=/y;{name}={_WORD}\r\n\r\n").encode()))
        assert h.flush() == len(targets)
        assert store.conn.execute("SELECT COUNT(*) FROM flow").fetchone()[0] == len(targets)
        assert _WORD not in _dump(store)


#: Review round 2, N6: ``(raw request, raw response)`` pairs whose secret sat in a URL
#: the proxy's redactor never read: a duplicate URL header, ``Referer``, ``Origin``,
#: ``Link``, a custom header holding a URL, ``Refresh`` spelled ``url = `` or bare or
#: quoted, a request line with a doubled space, a tab or a raw space, and N2's nested
#: userinfo in the target and ``Location``.
_PROXY_ROUND2 = [
    ("GET /app/b.php HTTP/1.1\r\nHost: h\r\nReferer: http://h/app/;jsessionid={W}\r\n"
     "Origin: http://h/;jsessionid={W}\r\nX-Return-To: /a;jsessionid={W}\r\n\r\n",
     "HTTP/1.1 302 Found\r\nLocation: /clean\r\nLocation: /app/;jsessionid={W}\r\n"
     "Content-Location: /x\r\nContent-Location: /x;jsessionid={W}\r\n"
     "Link: </app;jsessionid={W}>; rel=next\r\n\r\n"),
    ("GET /app/b.php HTTP/1.1\r\nHost: h\r\nReferer: http://h/app/?token={W}\r\n\r\n",
     "HTTP/1.1 302 Found\r\nLocation: /clean\r\nLocation: /app/?token={W}\r\n\r\n"),
    ("GET  /app;jsessionid={W} HTTP/1.1\r\nHost: h\r\n\r\n",
     "HTTP/1.1 200 OK\r\nRefresh: 0; url = /y;jsessionid={W}\r\n\r\n"),
    ("GET\t/app;jsessionid={W}\tHTTP/1.1\r\nHost: h\r\n\r\n",
     "HTTP/1.1 200 OK\r\nRefresh: 0; /y;jsessionid={W}\r\n\r\n"),
    ("GET /a b;jsessionid={W} HTTP/1.1\r\nHost: h\r\n\r\n",
     "HTTP/1.1 200 OK\r\nRefresh: 0;URL='/y;jsessionid={W}'\r\n\r\n"),
    ("GET /app/p.php?u=bob&next=/go/https://bob:{P}@host/x HTTP/1.1\r\nHost: h\r\n\r\n",
     "HTTP/1.1 302 Found\r\nLocation: http://h/app/p.php?u=bob&next=/go/https://bob:{P}@"
     "host/x\r\n\r\n"),
]


def test_proxy_history_redacts_every_url_bearing_header_and_any_request_line(tmp_path):
    """Review round 2, N6: `proxy.redact.redact` read only the first value of each URL
    header (and a changed one replaced every duplicate), never ``Referer``, ``Origin``,
    ``Link`` or another header holding a URL, ``Refresh`` only as ``url=``, and the
    request target as ``split(b" ")[1]`` -- each kept the secret in the stored raw
    messages and their full-text index. Every value is now read, in place."""
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    from fuzzlab.proxy.redact import redact
    pairs = [(rq.format(W=_WORD, P=_PASS).encode(), rs.format(W=_WORD, P=_PASS).encode())
             for rq, rs in _PROXY_ROUND2]
    for rq, rs in pairs:
        for raw in (rq, rs):
            out = redact(raw)
            assert _WORD.encode() not in out and _PASS.encode() not in out, raw
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=50)
        for rq, rs in pairs:
            h.record(FlowRecord("GET", "http://h/app/b.php", "h", 302, raw_request=rq,
                                raw_response=rs))
        assert h.flush() == len(pairs)
        dump = _dump(store)
    assert _WORD not in dump and _PASS not in dump
    # nothing else moves: the duplicate's clean value, the order and the clean headers
    out = redact(pairs[0][1])
    assert out.index(b"Location: /clean\r\n") < out.index(b"Location: /app/;jsessionid=")
    clean = (b"GET /app/x?q=1 HTTP/1.1\r\nHost: h\r\nUser-Agent: Mozilla/5.0 (X11; Linux)"
             b" +http://x/bot\r\nReferer: http://h/app/?q=hello\r\nRefresh: 5\r\n\r\n")
    assert redact(clean) == clean


@pytest.mark.xfail(strict=True, reason="BUG-0556 residual R4 (stated in review round 2, "
                   "owner PROXY): a URL inside another structured header's grammar (a "
                   "CSP `report-uri`, `Reporting-Endpoints`, `Report-To`'s JSON) is not "
                   "parsed, so a sensitively named value there is kept in proxy history; "
                   "the URL-bearing headers whose value is a URL are covered (N6)",
                   raises=AssertionError)
def test_proxy_history_redacts_a_url_inside_a_structured_header():
    from fuzzlab.proxy.redact import redact
    raw = (f"HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'; report-uri "
           f"/csp?token={_WORD}\r\n\r\n").encode()
    assert _WORD.encode() not in redact(raw)


@pytest.mark.parametrize("value", [
    f"http://127.0.0.1:3000/app/#/r?next=/v?q=a b&token={_WORD}",
    f"http://127.0.0.1:3000/app/#/r?next=/v?q=a b%26token%3D{_WORD}",
    f"http://127.0.0.1:3000/app/?q=a b&token={_WORD}",
    f"http://127.0.0.1:3000/app/#/r%3Ftoken%3D{_WORD}",
])
def test_a_project_record_walks_a_url_holding_a_raw_space_whole(tmp_path, value):
    """Review round 2, N7: `redact_for_record` split the value on whitespace before the
    walk, so a URL holding a raw space was walked a piece at a time and ``b&token=…``
    was never read as part of the query; the walk now runs on the whole value first.
    Through the real writers too: `add_target` and `insert_launch`."""
    from fuzzlab.core import project
    assert not _leaks(R.redact_for_record("target", value), _WORD)
    with Store(tmp_path / "s.db") as store:
        project.ensure_metadata(store, "s")
        project.insert_launch(store, "auto", [("", "fuzzlab"), ("url", value)], value)
        project.add_target(store, value)
        dump = _dump(store)
    assert "127.0.0.1:3000/app/" in dump                    # not vacuous
    assert not _leaks(dump, _WORD)


@pytest.mark.parametrize("case", [c for c in CASES if c[1] in dict(NAMED)][::3])
def test_a_project_record_redacts_a_credential_nested_in_a_route_fragment(case):
    """Review round 1, RU-9: `redact_for_record` (``launch.argv``, ``launch.target``,
    ``project.targets``) judged a route fragment's query flat, so a credential nested in
    ``#/r?next=…`` was kept: the generated spellings, moved into a route fragment."""
    url = _case_url(case).replace("/app/p.php?", "/app/p.php#/r?")
    assert "#/r?" in url and _leaks(url, case[2])          # not vacuous
    assert not _leaks(R.redact_for_record("target", url), case[2])


def test_a_launch_record_holds_no_credential_nested_in_a_route_fragment(tmp_path):
    """RU-9 through the real writer: `project.insert_launch` stores ``launch.argv`` and
    ``launch.target`` through `redact_for_record`."""
    from fuzzlab.core import project
    url = f"http://127.0.0.1:3000/app/#/r?next=/v?token={_WORD}"
    encoded = f"http://127.0.0.1:3000/app/#/r?next=%2Fv%3Ftoken%3D{_WORD}"
    with Store(tmp_path / "s.db") as store:
        project.ensure_metadata(store, "s")
        project.insert_launch(store, "auto", [("", "fuzzlab"), ("", url), ("", encoded)],
                              url)
        rows = store.conn.execute("SELECT COUNT(*) FROM launch").fetchone()[0]
        dump = _dump(store)
    assert rows == 1 and "127.0.0.1:3000/app/#/r?next=" in dump
    assert _WORD not in dump


def test_a_diagram_reference_holds_no_nested_secret():
    """Finding and trace evidence cite URLs through `core.trace.safe_ref`, which starts
    from `redact_url_identifiers`."""
    from fuzzlab.core.trace import safe_ref
    leaks = [c for c in CASES if _leaks(safe_ref(_case_url(c)), c[2])]
    assert leaks == []


# --- the legacy auditor's import (review round 1, RU-3/RU-8) -------------------------------
class _FakeFetcher:
    """A page that echoes the values the auditor's rules quote, and one XHR (no network)."""

    def fetch(self, url):
        body = "<html><body>hello " + " ".join(
            unquote_plus(p.partition("=")[2]) for p in urlsplit(url).query.split("&")) + \
            "</body></html>"
        return 200, "text/html", body, ["http://h/api/live.php"]


#: Page URLs the spider stores as crawled (a link's middle-segment parameter, a nested
#: token, a token behind a raw '/', a JWT, a sensitive name and a repeated name).
_AUDITED = [
    f"http://h/app/a;ref={_UUID}/b.php?u=bob&next=%2Fview%3Fticket%3D{_HEX}",
    f"http://h/app/a;jsessionid={_HEX}/c.php?u=bob&id=12345&sort=name",
    f"http://h/app/d.php?u=bob&next=/view%3Fticket%3D{_HEX}&k={_JWT}",
    f"http://h/app/e.php?u=bob&token={_WORD}&dup=1&dup={_HEX}",
]


def test_import_audit_stores_the_spiders_endpoint_and_no_secret(tmp_path):
    """Review round 1, RU-3/RU-8: `import_audit` (``fuzzlab audit --store``) stored
    ``to_path(page_url)`` -- a middle segment's ``;ref=<uuid>`` kept, a second endpoint
    beside the spider's -- and the rules' ``target_identifier`` and ``html_context``
    (``example value: …``, ``value '…' reflected``, ``supplied 2x: …``, ``called from
    <url>``) unredacted. The real chain: the spider's row, `load_urls`, `audit_page`
    with the real rules, `import_spider`, then `import_audit`."""
    from fuzzlab.tools import fetcher as F
    from fuzzlab.tools.spider import StorageManager
    from fuzzlab.tools.store_adapter import import_audit, import_spider
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    sm.mark_visited("http://h/app/start.php", 200, 0)
    for url in _AUDITED:
        sm.mark_visited(url, 200, 1, found_from="http://h/app/start.php")
    sm.close()
    rules = [(k, "cat", None) for k in F.RULES]
    db = F.setup_results_db(str(tmp_path / "a.db"))
    for target, source in F.load_urls(str(tmp_path / "s.db")):
        F.audit_page(target, source, _FakeFetcher(), rules, db, set(), verbose=False)
    db.close()
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auditor", "h")
        import_spider(tmp_path / "s.db", store, run)
        spider = {r[0] for r in store.conn.execute("SELECT url FROM endpoint").fetchall()}
        spider |= {r[0] for r in store.conn.execute("SELECT url FROM page").fetchall()}
        counts = import_audit(tmp_path / "a.db", store, run)
        audit = {r[0] for r in store.conn.execute(
            "SELECT url FROM endpoint WHERE source = 'audit'").fetchall()}
        contexts = [r[0] for r in store.conn.execute(
            "SELECT sink_context FROM candidate").fetchall()]
        dump = _dump(store)
    # not vacuous: the rules quoted values, the URL and the path
    assert counts["candidate"] > 20
    assert any(c and c.startswith("example value: ") for c in contexts)
    assert any(c and c.startswith("called from http://h/app/") for c in contexts)
    assert any(c and "reflected" in c for c in contexts)
    assert _leaked(dump) == [] and "446655440001" not in dump
    assert audit <= spider, (audit, spider)     # the page as the spider stores it, never a second


class _SilentFetcher:
    """A page that echoes nothing of its query (so the rules quote the value from the
    parameter itself, never from the body), and no XHR (no network)."""

    def fetch(self, url):
        return 200, "text/html", "<html><body>hello</body></html>", []


#: Review round 2, N3: query values a legacy rule quotes as a substring, not a prefix at
#: one of the cut lengths: a JWT behind ``Bearer `` and behind ``x.``, a short JWT with
#: a tail, Java-serialized base64 holding a ``+`` (form-decoded to a space, so the
#: match stops there) and a Python pickle behind ``v1:`` (`rule_serialized_tokens`'s
#: ``match.group(0)[:60]``).
_JWT2 = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IiLCJzaWQiOiJDYW5hcnlKV1QifQ."
         "Q2FuYXJ5U2lnbmF0dXJlOTg3NjU0MzIx")
_SHORT_JWT = "eyJhbGciOiJ9.eyJzdWIiOiJ9.Zq9f8e7d6c5b"
_JAVA = "rO0ABXNyABFqYXZhLnV0aWwuSGFz+aE1Q2FuYXJ5SmF2YVNlcg"
_PICKLE = "gASVKAAAAAAAAACMCGJ1aWx0aW5zlIwFcHJpbnSUk5SMC0NhbmFyeVBpY2ts"
_SUBSTRING_QUOTED = [
    (f"http://h/app/j.php?u=bob&auth=Bearer%20{_JWT2}", _JWT2),
    (f"http://h/app/k.php?u=bob&data=x.{_JWT2}", _JWT2),
    (f"http://h/app/l.php?u=bob&k={_SHORT_JWT}~tail", _SHORT_JWT),
    (f"http://h/app/m.php?u=bob&obj={_JAVA}", _JAVA),
    (f"http://h/app/n.php?u=bob&state=v1:{_PICKLE}", _PICKLE),
]


def _audit_store(tmp_path, rows, fetcher, base_url=None):
    """The real chain: the spider's rows, `load_urls`, `audit_page` with every rule,
    `import_spider`, then `import_audit` (no ``base_url`` by default, as `fuzzlab audit
    --store` calls them). ``(candidates' sink contexts, the endpoint urls after the
    spider's import, the endpoint urls after the audit's, dump)``.

    ``base_url`` is passed only when given, and to `import_audit` only where it takes
    the keyword (since review round 1): passing ``base_url=None`` stopped the pre-fix
    code (7393c90, c3a13f7) on a ``TypeError`` before any assertion, masking the leaks
    and the endpoint split the tests assert (the fix check after the final round, N5;
    PA-0545(6))."""
    import inspect
    kw = {"base_url": base_url} if base_url else {}
    from fuzzlab.tools import fetcher as F
    from fuzzlab.tools.spider import StorageManager
    from fuzzlab.tools.store_adapter import import_audit, import_spider
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    for url, depth, source in rows:
        sm.mark_visited(url, 200, depth, source=source,
                        found_from=None if depth == 0 else rows[0][0])
    sm.close()
    db = F.setup_results_db(str(tmp_path / "a.db"))
    for target, source in F.load_urls(str(tmp_path / "s.db")):
        F.audit_page(target, source, fetcher, [(k, "cat", None) for k in F.RULES], db,
                     set(), verbose=False)
    db.close()
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auditor", "h")
        import_spider(tmp_path / "s.db", store, run, **kw)
        spider = {r[0] for r in store.conn.execute("SELECT url FROM endpoint").fetchall()}
        takes_base = "base_url" in inspect.signature(import_audit).parameters
        import_audit(tmp_path / "a.db", store, run, **(kw if takes_base else {}))
        after = {r[0] for r in store.conn.execute("SELECT url FROM endpoint").fetchall()}
        contexts = [r[0] for r in store.conn.execute(
            "SELECT sink_context FROM candidate").fetchall()]
        dump = _dump(store)
    return contexts, spider, after, dump


def test_import_audit_redacts_a_quoted_substring_of_a_secret_value(tmp_path):
    """Review round 2, N3: `_audit_text` swapped a secret value's prefixes at the rules'
    cut lengths only, so `rule_serialized_tokens`' match (a substring of the value) was
    stored in ``candidate.sink_context``; the round-1 test's fetcher echoed the query,
    so the body's row won the dedupe and hid it. Every quoted run of a value the owner
    would not store is now replaced, judged on the whole value."""
    rows = [("http://h/app/start.php", 0, "link")] + [(u, 1, "link")
                                                       for u, _s in _SUBSTRING_QUOTED]
    contexts, _spider, _after, dump = _audit_store(tmp_path, rows, _SilentFetcher())
    assert any(c and " found in parameter " in c for c in contexts)    # not vacuous
    assert [s for _u, s in _SUBSTRING_QUOTED if _leaks(dump, s)] == []


def test_import_audit_stores_a_page_as_the_spider_does_when_the_first_finding_is_off_origin(
        tmp_path):
    """Review round 2, N3 (RU-8's split in a new form): `import_spider` takes the run's
    main origin from the seed and `import_audit` took it from its first finding's page,
    so with an off-origin page (an XHR on an API origin) audited first the main
    origin's page was stored absolute, a second endpoint beside the spider's path. The
    audit endpoint is now the spider's form of the same page: no endpoint is added."""
    rows = [("http://h/", 0, "link"), ("http://api.h:8081/v1/q.php?u=bob", 1, "xhr"),
            ("http://h/app/z.php?id=7", 1, "link")]
    contexts, spider, after, _dump_text = _audit_store(tmp_path, rows, _SilentFetcher())
    assert {"/app/z.php", "http://api.h:8081/v1/q.php"} <= spider     # not vacuous
    assert any(c and c.startswith("example value: ") for c in contexts)
    assert after == spider, sorted(after - spider)


def test_import_audit_under_a_subpath_base_stores_the_spiders_paths(tmp_path):
    """PA-0300 (`tests/test_base_url_subpath_registry.py`): `import_audit`'s ``base_url``
    (a keyword since review round 1) with the app under a sub-path. Its origin is the
    run's main one, so a page is stored by its whole path, as `import_spider` stores it
    with the same base -- never re-rooted at the sub-path nor doubled -- and another
    origin's page keeps its origin; the audit import adds no endpoint."""
    base = "http://h/app/"
    rows = [(base, 0, "link"), ("http://api.h:8081/v1/q.php?u=bob", 1, "xhr"),
            ("http://h/app/z.php?id=7", 1, "link")]
    contexts, spider, after, _dump_text = _audit_store(tmp_path, rows, _SilentFetcher(),
                                                       base_url=base)
    assert {"/app/z.php", "http://api.h:8081/v1/q.php"} <= spider     # not vacuous
    assert any(c and c.startswith("example value: ") for c in contexts)
    assert after == spider, sorted(after - spider)


@pytest.mark.xfail(strict=True, reason="BUG-0556 residual R5 (stated in review round 2; "
                   "owners CORE and AUD): a page URL's own userinfo is kept by both URL "
                   "redactors (R3), so `import_audit`'s `called from <url>` text keeps it "
                   "in `candidate.sink_context`; R3's reason (the store keeps no top-level "
                   "userinfo) does not hold for this writer", raises=AssertionError)
def test_import_audit_stores_no_userinfo_of_the_finding_page():
    # the writer's text redactor where the code has one; before review round 1
    # `import_audit` stored the rules' texts as they were (the fix check after the final
    # round, N5: the import of `_audit_text` failed there, so the pin "held" for an
    # ImportError, not for the userinfo it kept)
    from fuzzlab.tools import store_adapter
    audit_text = getattr(store_adapter, "_audit_text", lambda text, _page, **_k: text)
    url = f"http://bob:{_PASS}@h/app/x.php?u=bob"
    assert _PASS not in audit_text(f"called from {url}", url)


# --- the endpoint's own query is never sent redacted (review round 1, RU-4; PA-0544) -----
class _NothingSent:
    def __init__(self):
        self.sent = []

    def send(self, *a, **k):
        self.sent.append((a, k))
        raise AssertionError("nothing may be sent")


def _points_and_verdicts(store, run):
    """Every point of the run and the oracle's outcome for each (sending nothing)."""
    from fuzzlab.harness.auto import injection_points_from_store
    from fuzzlab.oracle.oracle import Oracle
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import ReflectedXssStrategy
    points = injection_points_from_store(store, run, "http://127.0.0.1:3000/")
    out = []
    for p in points:
        sender = _NothingSent()
        cand = Candidate(url=p.url, param=p.param, method=p.method, location=p.location,
                         category="xss", base_entries=p.base_entries,
                         bindings=None, replay_refusal=p.replay_refusal)
        if p.replay_refusal:
            verdict, unsure = Oracle(strategies=[ReflectedXssStrategy()]).confirm_outcome(
                cand, sender)
            out.append((p, verdict, unsure, sender.sent))
        else:
            out.append((p, None, None, []))
    return out


def test_an_endpoint_query_redaction_changed_is_never_sent(tmp_path):
    """Review round 1, RU-4 (and the old R2 pin): a POST form's action query and a
    disco-captured request's URL query that redaction changes were stored as ``id=``
    (or ``token=__REDACTED__``) and every probe sent that as the request's own value, a
    new false-negative source. The importer now records the value as a placeholder (by
    name, never by value; PA-0544(1)), and the point builder refuses such a point: the
    test is inconclusive with the reason and nothing is sent (PA-0544(3))."""
    from bs4 import BeautifulSoup

    from fuzzlab.core.forms import form_record
    from fuzzlab.disco.capture import append_record, make_record
    from fuzzlab.oracle.oracle import UNBOUND
    from fuzzlab.tools import store_adapter
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    for html in (f"<form method=post action='/app/edit.php?id={_UUID}'><input name=q></form>",
                 (f"<form method=post action='/app/do.php?token=abc&state={_HEX}'>"
                  "<input name=q></form>")):
        sm.record_form(form_record(BeautifulSoup(html, "html.parser").find("form"),
                                   "http://127.0.0.1:3000/app/f.php"))
    sm.close()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    append_record(run_dir / "capture.jsonl", make_record(
        kind="http", t=1.0, action_id="act-1", method="POST",
        url=f"http://127.0.0.1:3000/api/x?id={_UUID}",
        req_headers={"Content-Type": store_adapter.FORM_URLENCODED},
        req_body=b"q=hello", status=200,
        res_headers={"Content-Type": "text/html"}, res_body=b"ok"))
    (run_dir / "actions.jsonl").write_text("")
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        store_adapter.import_spider(tmp_path / "s.db", store, run)
        store_adapter.import_disco(run_dir, store, run)
        results = _points_and_verdicts(store, run)
        dump = _dump(store)
    urls = [p.url for p, *_r in results]
    assert {"/app/edit.php", "/app/do.php", "/api/x"} <= {urlsplit(u).path for u in urls}
    # no point's own query holds a blanked value: never sent as the request's own
    blanks = [u for u in urls
              if any(part.endswith("=") for part in re.split(r"[&;]", urlsplit(u).query))]
    assert blanks == []
    for p, verdict, unsure, sent in results:
        if R.PLACEHOLDER in p.url:                       # a value redaction replaced
            assert p.replay_refusal, p.url
            assert sent == [] and verdict is None and unsure is not None
            assert unsure.mechanism == UNBOUND
    assert sum(1 for p, *_r in results if R.PLACEHOLDER in p.url) >= 3
    assert "446655440001" not in dump and _HEX not in dump


class _RecordingSession:
    """A requests-like session that records every request (nothing leaves)."""

    def __init__(self):
        self.sent = []

    def request(self, method, url, **kwargs):
        self.sent.append((method, url, kwargs.get("data")))

        class _Resp:
            status_code, text, headers = 200, "ok", {}
        return _Resp()


def test_greybox_never_sends_a_point_the_builder_refused_or_a_placeholder(tmp_path):
    """Review round 2, N4 (PA-0530(5): every caller of the producer): greybox's
    `points_from_store` rebuilt each point as a `GreyboxPoint` and dropped its
    ``replay_refusal``, and `RequestsCorrelatingSender` had no placeholder gate, so the
    form ``action='/app/edit.php?id=<uuid>'`` was sent as ``POST
    /app/edit.php?id=__REDACTED__``. A refused point is now reported in ``skipped``, and
    the sender refuses any URL holding a placeholder before anything is sent."""
    from bs4 import BeautifulSoup

    from fuzzlab.core.forms import form_record
    from fuzzlab.greybox import run as gbrun
    from fuzzlab.tools import store_adapter
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    sm.record_form(form_record(BeautifulSoup(
        f"<form method=post action='/app/edit.php?id={_UUID}'><input name=q></form>",
        "html.parser").find("form"), "http://127.0.0.1:3000/app/f.php"))
    sm.close()
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("greybox", "h")
        store_adapter.import_spider(tmp_path / "s.db", store, run)
        skipped: list = []
        points = gbrun.points_from_store(store, run, "http://127.0.0.1:3000/",
                                         skipped=skipped)
    session = _RecordingSession()
    sender = gbrun.RequestsCorrelatingSender(session=session, id_factory=lambda: "c")
    for p in points:
        sender.send_correlated(p.url, p.param, "1'", method=p.method, location=p.location)
    assert [u for _m, u, _d in session.sent if R.PLACEHOLDER in u or "id=" in u] == []
    assert any(path == "/app/edit.php" and "redaction replaced" in why
               for path, _m, _p, why in skipped), skipped
    # the send-time gate, whoever built the point
    with pytest.raises(ValueError, match="redaction replaced"):
        sender.send_correlated(f"http://127.0.0.1:3000/app/edit.php?id={R.PLACEHOLDER}",
                               "q", "1'", method="POST", location="body")
    assert [u for _m, u, _d in session.sent if R.PLACEHOLDER in u] == []


@pytest.mark.xfail(strict=True, reason="BUG-0556 residual R2 (narrowed in review round 1; "
                   "owner CRAWL): the spider's capture writer stores a request URL's "
                   "identifier-like query value as a blank (`redact_url_identifiers`), "
                   "which the importer cannot tell from an empty value, so its points "
                   "send `id=` -- through `harness.auto` and greybox alike (review round "
                   "2, N4: every caller of the point builder); the fix is the writer "
                   "recording a placeholder (PA-0544(1)) in `tools/spider.py`, held by "
                   "lane BROWSERALIAS this round", raises=AssertionError)
def test_a_spider_captured_request_query_redaction_is_never_sent(tmp_path):
    from fuzzlab.greybox import run as gbrun
    from fuzzlab.tools import store_adapter
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    assert sm.record_request("http://127.0.0.1:3000/app/f.php", "POST",
                             f"http://127.0.0.1:3000/api/y?id={_UUID}",
                             "application/json", b'{"q": "hello"}', "xhr") is None
    sm.close()
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        store_adapter.import_spider(tmp_path / "s.db", store, run)
        results = _points_and_verdicts(store, run)
        greybox = gbrun.points_from_store(store, run, "http://127.0.0.1:3000/",
                                          skipped=[])
    urls = [p.url for p, *_r in results]
    assert urls
    # neither caller of the point builder sends the blank as the request's own value
    sent_blank = ([u for u in urls if "id=" in u and R.PLACEHOLDER not in u],
                  [p.url for p in greybox if "id=" in p.url and R.PLACEHOLDER not in p.url])
    assert sent_blank == ([], [])


# --- what stays ---------------------------------------------------------------------------
BENIGN = [
    "http://h/app/p.php?u=bob&next=/account",
    "http://h/app/p.php?u=bob&next=%2Faccount",
    "http://h/app/p.php?u=bob&next=%2Fsearch%3Fq%3Dhello%2Bworld%26page%3D2",
    "http://h/app/p.php?u=bob&next=%252Fsearch%253Fq%253Dpuppies",
    "http://h/app/p.php?u=bob&return=https%3A%2F%2Fwww.example.org%2Fhome%3Ftab%3D2",
    "http://h/app/p.php?u=bob&a=1;b=2",
    "http://h/app/v;version=2/p.php?u=bob&x=1",
    "http://h/app/p.php?u=bob&q=hello+world&lang=en",
    "http://h/app/p.php?u=bob&css=color:red;font-size:12px",
    "http://h/app/p.php?u=bob&f=YWJjZA%3D%3D",
    "http://h/#/search?q=puppies&page=2",
    "http://h/app/p.php?u=bob&path=/var/www/index.html",
    "http://h/app/p.php?u=bob&when=2026-10-14T10:00:00",
    # review round 1: a layer left encoded behind a raw '/', an '@' that is no userinfo
    "http://h/app/p.php?u=bob&next=/search%3Fq%3Dpuppies%26page%3D2",
    "http://h/app/p.php?u=bob&return=https://www.example.org/home%3Ftab%3D2",
    "http://h/app/p.php?u=bob&next=/users/%40bob/profile",
    "http://h/app/p.php?u=bob&next=https://www.example.org/a/b@c",
    "http://h/app/p.php?u=bob&next=/a%20b/c%2Fd",
    # after the final round: a nested authority's pairs and a backslash-led pair list
    # are walked, and a clean one comes back byte-identical
    "http://h/app/p.php?u=bob&next=https%3A%2F%2Fhost%3Bv%3D2%2Fx",
    "http://h/app/p.php?u=bob&next=%5Cdocs%26lang%3Den",
    "http://h/app/p.php?u=bob&next=https://www.example.org/a%20b/c%20d",
]


@pytest.mark.parametrize("url", BENIGN)
def test_ordinary_nested_values_are_left_byte_identical(url):
    assert R.redact_url_identifiers(url) == url
    assert R.redact_url(url) == url
    assert R.page_url_is_clean(url)
    query = urlsplit(url).query
    for part in query.split("&"):
        name, _eq, raw = part.partition("=")
        assert _api("stored_value")(name, unquote(raw), raw) == raw, part


def test_an_ordinary_nested_link_value_is_stored_as_crawled(tmp_path):
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", ["http://h/app/p.php?u=bob&next=/account",
                                   "http://h/app/q.php?next=%2Fsearch%3Fq%3Dpups"])
    with Store(tmp_path / "u.db") as store:
        import_spider(tmp_path / "s.db", store, store.start_run("auto", "h"))
        examples = {r["name"]: r["example"] for r in store.conn.execute(
            "SELECT name, example FROM parameter").fetchall()}
        entries = [json.loads(r["entries"]) for r in store.conn.execute(
            "SELECT entries FROM form").fetchall()]
    assert examples["next"] in ("/account", "/search?q=pups")
    assert [["u", "bob"], ["next", "/account"]] in entries
    assert [["next", "/search?q=pups"]] in entries


# --- bounds and totality ------------------------------------------------------------------
def test_a_value_past_the_depth_bound_is_redacted_whole():
    """A token nested past the walk's depth bound is redacted whole, never kept. The
    leak is asserted first, and the bound falls back to the fix's value (12) where the
    code has none, so the pre-fix redactors are given the same URL and fail on the hex
    they keep, never on the missing constant (review round 2, N5; PA-0545(6))."""
    depth = getattr(R, "MAX_VALUE_DEPTH", 12)
    value = f"/view?ticket={_HEX}"
    for _ in range(depth + 2):
        value = quote(value, safe="")
    url = f"http://h/app/p.php?u=bob&next={value}"
    for fn in (R.redact_url_identifiers, R.redact_url):
        assert not _leaks(fn(url), _HEX, layers=depth + 3), fn.__name__
    assert not R.page_url_is_clean(url)
    assert R.redact_url_identifiers(url) == "http://h/app/p.php?u=bob&next="
    assert R.redact_url(url) == f"http://h/app/p.php?u=bob&next={R.PLACEHOLDER}"
    assert _api("value_holds_secret")(unquote(value))


def test_a_value_past_the_size_bound_is_redacted_whole(monkeypatch):
    # set even where the code has no bound (review round 2, N5): the pre-fix code then
    # fails on the over-long value it keeps, never on the missing constant
    monkeypatch.setattr(R, "MAX_VALUE_CHARS", 64, raising=False)
    ok, over = "a" * 64, "a" * 65
    assert R.redact_url_identifiers(f"http://h/p?u=bob&x={ok}") == f"http://h/p?u=bob&x={ok}"
    assert R.redact_url_identifiers(f"http://h/p?u=bob&x={over}") == "http://h/p?u=bob&x="
    assert R.redact_url(f"http://h/p?x={over}") == f"http://h/p?x={R.PLACEHOLDER}"


@pytest.mark.parametrize("url", [
    "http://h/p?next=%zz%2", "http://h/p?next=%", "http://h/p?x=%%25%",
    "http://h/p?next=\ud800abc", "http://h/p?next=%ED%A0%80" + _HEX,
    "http://[::1/x?token=a;b=%2F%3F", "http://h/p;;;=?&&;;==#?&=", "", "?", ";", "#",
    "http://h/p?next=" + "%2F%3Fa%3D" * 400,
    "http://h/p?next=//@", "http://h/p?next=https://%40", "http://h/p?next=/%",
    "http://h/p?next=/%zz%3F" + "/%2F%3F" * 400, "http://h/p?next=https://a@b@c%40/",
])
def test_the_redactors_are_total(url):
    """Total on every URL ``urlsplit`` accepts. On one it rejects (``http://[::1/x?…``)
    the URL redactors and `page_url_is_clean` raise ``ValueError``, as the pushed tree's
    did (BUG-0556 r6: the floor raises, and each caller falls back as it did on 7393c90,
    `test_r6_a1_a_url_urlsplit_rejects_is_withheld_by_every_consumer` -- not always
    withholding the value: proxy history keeps what precedes the ``?``, family (d),
    pinned); nothing else raises."""
    try:
        urlsplit(url)
        rejected = False
    except ValueError:
        rejected = True
    for fn, kind in ((R.redact_url, str), (R.redact_url_identifiers, str),
                     (R.page_url_is_clean, bool)):
        try:
            out = fn(url)
        except ValueError:
            assert rejected, (fn.__name__, url)
            continue
        assert isinstance(out, kind), fn.__name__
    assert R.redact_url(None) is None and R.page_url_is_clean(None) is False
    assert _api("value_holds_secret")(None) is False


def _oracle_urls(n: int) -> dict[str, str]:
    """Clean URLs, each taking one part of the walk ``n`` times, so a quadratic step in
    any part is most of its URL's work (review round 2, N8: the first oracle had only
    query pairs -- no path parameter, nested path or fragment):

    - ``path``: ``n`` top-level path segments, each with a path parameter;
    - ``query``: ``5n`` query pairs, ``&`` and ``;`` separated: a value encoded once, a
      plain one, one behind a raw ``/``, one nested three levels deep behind a raw ``/``
      at each level, and a nested URL with a path parameter, encoded segments and an
      encoded fragment route;
    - ``nested``: one value holding a nested URL of ``n`` encoded path segments with
      path parameters (at most 2 500: the value stays under `MAX_VALUE_CHARS`);
    - ``fragment``: a fragment route of ``n`` encoded segments with ``n`` query pairs,
      each a nested URL with a raw fragment route of its own."""
    def deep(i):
        return "/a" + quote("?b=/c" + quote("?d=/e" + quote(f"?f={i}", safe="/"),
                                            safe="/"), safe="/")

    def nested(i):                      # a raw '#' would end the top-level query: %23
        return f"/m/n{i};o=1/q%3Fr%3D{i}/s%3Bt%3D{i}?u={i}%23/v/w%3Fx%3D{i}"
    return {
        "path": "http://h" + "".join(f"/s{i};v{i}=x" for i in range(n)) + "?a=1",
        "query": "http://h/p?" + "&".join(
            f"k{i}=%2Fv%3Fa%3D{i};b{i}=c;d{i}=/w%3Fe%3D{i};g{i}={deep(i)}&h{i}={nested(i)}"
            for i in range(n)),
        "nested": "http://h/p?u=bob&next=/m" + "".join(
            f"/q{i}%3Fr%3D{i};o{i}=1" for i in range(min(n, 2500))) + "?z=1",
        "fragment": "http://h/p#/r/" + "/".join(f"t{i}%3Fu%3D{i}" for i in range(n))
        + "?" + "&".join(f"f{i}=/g/j%3Fh%3D{i}?l={i}#/x/y%3Fz%3D{i}" for i in range(n)),
    }


class _Ops:
    """The C-level work of one walk, counted per call: the characters each wrapped
    function or pattern method was given (review round 2, N8)."""

    def __init__(self):
        self.chars = 0
        self.calls = 0

    def add(self, text) -> None:
        self.chars += len(text) if isinstance(text, (str, bytes)) else 0
        self.calls += 1


class _CountedPattern:
    """A compiled pattern whose every search, match, split and substitution counts the
    characters it is given."""

    _FIRST = ("search", "match", "fullmatch", "split", "finditer", "findall")

    def __init__(self, pattern, ops: _Ops):
        self._pattern, self._ops = pattern, ops

    def __getattr__(self, name):
        attr = getattr(self._pattern, name)
        if name in self._FIRST:
            def counted(string, *a, **k):
                self._ops.add(string)
                return attr(string, *a, **k)
            return counted
        if name in ("sub", "subn"):
            def counted_sub(repl, string, *a, **k):
                self._ops.add(string)
                return attr(repl, string, *a, **k)
            return counted_sub
        return attr


#: The functions of `core.redaction` whose work is counted per call: the percent
#: decodes and encodes, the identifier and name predicates.
_COUNTED_FUNCTIONS = ("unquote", "unquote_plus", "quote", "looks_like_identifier",
                      "is_sensitive_name")


def _counted_walk(url: str, identifiers: bool, monkeypatch):
    """``(output, WalkCounter, _Ops)`` of one walk with every C-level call of the
    module counted: `_COUNTED_FUNCTIONS` and every compiled pattern (``_PAIR_SEP``'s
    split, the escape and raw-structure searches, the authority scan, and the patterns
    the predicates use) are wrapped for the walk and restored after it."""
    ops = _Ops()
    saved = {name: getattr(R, name) for name in _COUNTED_FUNCTIONS if hasattr(R, name)}
    saved.update({name: obj for name, obj in vars(R).items()
                  if isinstance(obj, re.Pattern)})
    for name, obj in saved.items():
        if isinstance(obj, re.Pattern):
            monkeypatch.setattr(R, name, _CountedPattern(obj, ops))
        else:
            def wrapped(text, *a, _fn=obj, **k):
                ops.add(text)
                return _fn(text, *a, **k)
            monkeypatch.setattr(R, name, wrapped)
    counter = R.WalkCounter()
    try:
        out = R._walk_url(url, identifiers, counter)
    finally:
        for name, obj in saved.items():
            monkeypatch.setattr(R, name, obj)
    return out, counter, ops


#: The oracle's constants, per URL character. Measured on the walk (review round 2:
#: each URL of `_oracle_urls`, both modes, at 100, 500 and 4000 items), the worst part:
#: 10.3 steps, 0.79 step calls, 15.4 counted C-level characters (8.5 with names only)
#: and 1.9 C-level calls; the bounds leave about 50% headroom. Each quadratic variant
#: of the oracle test measured at least 50 C-level characters per character on its
#: part's URL at 100 items.
_STEPS_PER_CHAR, _CALLS_PER_CHAR, _OPS_PER_CHAR, _OPS_CALLS_PER_CHAR = 15, 1.2, 23, 2.8


def _linearity_violations(n: int, monkeypatch) -> list:
    """The linearity oracle (PA-0095(2), PA-0135(1)/(2)): an operation count, never a
    timing. In both modes (``identifiers`` True, the strongest redactor; False,
    `redact_url`: proxy history's flush) the walk's own steps (`WalkCounter`) and the
    characters every C-level call of the module is given (`_counted_walk`: decodes,
    encodes, pair splits, pattern searches, predicates) each stay under a constant times
    the URL's length, the calls under a constant per item, and the output is unchanged
    (the URL is clean). An empty list when they hold."""
    if getattr(R, "WalkCounter", None) is None:
        return ["the walk exposes no operation count (PA-0135(2))"]
    violations = []
    for part, url in _oracle_urls(n).items():
        for identifiers in (True, False):
            out, counter, ops = _counted_walk(url, identifiers, monkeypatch)
            size = len(url)
            if out != url:
                violations.append(("the clean URL changed", part, identifiers))
            for what, count, bound in (
                    ("steps", counter.steps, _STEPS_PER_CHAR),
                    ("step calls", counter.calls, _CALLS_PER_CHAR),
                    ("C-level characters", ops.chars, _OPS_PER_CHAR),
                    ("C-level calls", ops.calls, _OPS_CALLS_PER_CHAR)):
                if not 0 < count <= bound * size:
                    violations.append((what, part, identifiers, n, count, size))
    return violations


def test_the_walk_is_linear_in_the_values_length(monkeypatch):
    """PA-0095(2), PA-0135: the walk's operation counts (its own steps, review round 1,
    RU-10, and the C-level work of every call it makes, review round 2, N8) stay under
    a constant times the URL's length at 500 items and at 4000 (a walk that re-read the
    whole query per pair would read ~n times it)."""
    assert _linearity_violations(500, monkeypatch) == []
    assert _linearity_violations(4000, monkeypatch) == []


def test_the_linearity_oracle_flags_a_quadratic_walk(monkeypatch):
    """PA-0135(3), PA-0034(2): the oracle is proven on deliberately quadratic variants,
    each with the real walk's output and the real walk's single ``tick`` per step, so
    only the counted C-level work reveals them (review round 2, N8: the round-1 variant
    A reported its own extra work through ``tick``, and a pair step decoding, splitting
    or encoding the whole list once per pair passed that oracle unseen):
    (A) a pair step that percent-decodes the whole list once per pair; (A2) one that
    splits it; (A3) one that percent-encodes it; (B) a value step that walks every
    value's decoded layer again after the raw walk (2^depth: the design review round 1
    rejected for RU-1); (C) a pair step that judges the whole query per pair; (D) a path
    step that decodes the whole head once per segment; (E) a fragment step that
    re-encodes the whole fragment once per pair of its query."""
    assert getattr(R, "WalkCounter", None) is not None, \
        "the walk exposes no operation count (PA-0135(2))"
    assert _linearity_violations(100, monkeypatch) == []        # the real walk passes
    walk = R._UrlWalk
    real = {attr: getattr(walk, attr) for attr in ("pairs", "value", "path", "fragment")}

    def per_pair(work):
        def pairs(self, text, depth, top):
            self.tick(text)
            parts = R._PAIR_SEP.split(text)
            for i in range(0, len(parts), 2):
                work(text)
                parts[i] = self.pair(parts[i], depth, top)
            return "".join(parts)
        return pairs

    def walk_every_layer_again(self, text, depth, top):
        new = real["value"](self, text, depth, top)
        if new == text and R._PCT.search(text) and depth <= R.MAX_VALUE_DEPTH:
            self.layer(text, depth)
        return new

    def decode_whole_head_per_segment(self, head, depth, nested=False):
        for _seg in head.split("/"):
            R.unquote(head)
        return real["path"](self, head, depth, nested)

    def encode_whole_fragment_per_pair(self, frag, depth, top):
        for _pair in frag.split("&"):
            R.quote(frag, safe="")
        return real["fragment"](self, frag, depth, top)

    variants = (("A", "pairs", per_pair(lambda t: R.unquote(t))),
                ("A2", "pairs", per_pair(lambda t: R._PAIR_SEP.split(t))),
                ("A3", "pairs", per_pair(lambda t: R.quote(t, safe=""))),
                ("B", "value", walk_every_layer_again),
                ("C", "pairs", per_pair(lambda t: R.looks_like_identifier(t))),
                ("D", "path", decode_whole_head_per_segment),
                ("E", "fragment", encode_whole_fragment_per_pair))
    for name, attr, variant in variants:
        monkeypatch.setattr(walk, attr, variant)
        found = _linearity_violations(100, monkeypatch)
        for real_attr, fn in real.items():
            monkeypatch.setattr(walk, real_attr, fn)
        assert found and not any("the clean URL changed" in str(v) for v in found), \
            (name, found)


# --- residuals pinned (PA-0054(3)): body redaction is paused by the owner -----------------
@pytest.mark.xfail(strict=True, reason="BUG-0556 residual R1: a captured body's leaf "
                   "holding a nested token is judged by the flat leaf rule "
                   "(`redact_leaf`); body redaction is paused by the owner (audit defect "
                   "26, AU-REDACT) and this lane may not change it", raises=AssertionError)
def test_a_captured_body_leaf_holding_a_nested_token_is_never_stored(tmp_path):
    from fuzzlab.disco.capture import append_record, make_record
    from fuzzlab.tools import store_adapter
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    append_record(run_dir / "capture.jsonl", make_record(
        kind="http", t=1.0, action_id="act-1", method="POST",
        url="http://127.0.0.1:3000/do",
        req_headers={"Content-Type": store_adapter.FORM_URLENCODED},
        req_body=f"q=hello&next=%2Fview%3Fticket%3D{_HEX}".encode(), status=200,
        res_headers={"Content-Type": "text/html"}, res_body=b"ok"))
    (run_dir / "actions.jsonl").write_text("")
    with Store(tmp_path / "u.db") as store:
        store_adapter.import_disco(run_dir, store, store.start_run("auto", "h"))
        assert _HEX not in _dump(store)


def test_the_cases_cover_every_axis():
    """The generated sweep's axes, named (so a reviewer sees what 'every spelling'
    means): 3 depths x 10 secrets x 3 separators x 7 encodings x 4 nested shapes."""
    axes = {k: sorted({c[i] for c in CASES})
            for i, k in enumerate(("depth", "name", "secret", "sep", "enc", "shape"))}
    assert axes["depth"] == [1, 2, 3]
    assert set(axes["sep"]) == set(_SEPS) and set(axes["enc"]) == set(_ENCODINGS)
    assert set(axes["shape"]) == {"path", "absolute", "query", "userinfo"}
    assert {n for n, _s in SECRETS} <= set(axes["name"])
    assert list(itertools.islice(CASES, 1))
