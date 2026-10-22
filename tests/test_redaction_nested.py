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


def _leaks(text: str, secret: str) -> bool:
    """Whether ``text`` -- or any percent-decoding of it, up to four layers -- holds a
    run of ``secret``."""
    seen = [text]
    for _ in range(4):
        seen.append(unquote(seen[-1]))
    return any(r in t for t in seen for r in _runs(secret))


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
    PA-0545(6))."""
    failures, values = [], []
    for case in CASES:
        url = _case_url(case)
        out = R.redact_url_identifiers(url)
        before, after = urlsplit(url), urlsplit(out)
        names = [p.partition("=")[0] for p in re.split(r"[&;]", before.query)]
        kept = [p.partition("=")[0] for p in re.split(r"[&;]", after.query)]
        if "next=" in before.query:
            values.append((case, before.query.split("next=", 1)[1]))
        if (_leaks(out, case[2]) or R.page_url_is_clean(url)
                or (after.scheme, after.netloc, after.path)
                != (before.scheme, before.netloc, before.path)
                or kept[:2] != names[:2]):
            failures.append((case, out))
    assert failures == []
    holds = getattr(R, "value_holds_secret", None)
    assert holds is not None, "core.redaction has no value_holds_secret (FR-CORE-537)"
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
    assert R.stored_value("next", unquote(value), unquote_plus(value)) == ""


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
    assert R.stored_value("next", unquote(value), unquote_plus(value)) == ""


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


@pytest.mark.xfail(strict=True, reason="BUG-0556 residual R2 (narrowed in review round 1; "
                   "owner CRAWL): the spider's capture writer stores a request URL's "
                   "identifier-like query value as a blank (`redact_url_identifiers`), "
                   "which the importer cannot tell from an empty value, so its points "
                   "send `id=`; the fix is the writer recording a placeholder "
                   "(PA-0544(1)) in `tools/spider.py`, held by lane BROWSERALIAS this round")
def test_a_spider_captured_request_query_redaction_is_never_sent(tmp_path):
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
    urls = [p.url for p, *_r in results]
    assert urls
    assert [u for u in urls if "id=" in u and not R.PLACEHOLDER in u] == []


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
]


@pytest.mark.parametrize("url", BENIGN)
def test_ordinary_nested_values_are_left_byte_identical(url):
    assert R.redact_url_identifiers(url) == url
    assert R.redact_url(url) == url
    assert R.page_url_is_clean(url)
    query = urlsplit(url).query
    for part in query.split("&"):
        name, _eq, raw = part.partition("=")
        assert R.stored_value(name, unquote(raw), raw) == raw, part


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
    value = f"/view?ticket={_HEX}"
    for _ in range(R.MAX_VALUE_DEPTH + 2):
        value = quote(value, safe="")
    url = f"http://h/app/p.php?u=bob&next={value}"
    assert R.redact_url_identifiers(url) == "http://h/app/p.php?u=bob&next="
    assert R.redact_url(url) == f"http://h/app/p.php?u=bob&next={R.PLACEHOLDER}"
    assert R.value_holds_secret(unquote(value))


def test_a_value_past_the_size_bound_is_redacted_whole(monkeypatch):
    monkeypatch.setattr(R, "MAX_VALUE_CHARS", 64)
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
    for fn in (R.redact_url, R.redact_url_identifiers):
        assert isinstance(fn(url), str)
    assert isinstance(R.page_url_is_clean(url), bool)
    assert R.redact_url(None) is None and R.page_url_is_clean(None) is False
    assert R.value_holds_secret(None) is False


def _oracle_url(n: int) -> str:
    """``4n`` pairs, ``&`` and ``;`` separated: a value encoded once, a plain one, one
    behind a raw ``/`` (a layer left encoded in a path segment) and one nested three
    levels deep, each level behind a raw ``/``."""
    def deep(i):
        return "/a" + quote("?b=/c" + quote("?d=/e" + quote(f"?f={i}", safe="/"),
                                            safe="/"), safe="/")
    return "http://h/p?" + "&".join(
        f"k{i}=%2Fv%3Fa%3D{i};b{i}=c;d{i}=/w%3Fe%3D{i};g{i}={deep(i)}" for i in range(n))


#: The oracle's constants. Measured on the walk (review round 1): 8.3 steps and 1.6
#: judged characters per URL character, 12 step calls per pair, the same at 500 and
#: 4000 pairs; the bounds leave about 50% headroom. Variant B below measured 34 steps
#: and 8.3 judged characters per character and 84 calls per pair at 500 pairs.
_STEPS_PER_CHAR, _JUDGED_PER_CHAR, _CALLS_PER_PAIR = 12, 3, 20


def _linearity_violations(n: int, monkeypatch) -> list:
    """The linearity oracle (PA-0095(2), PA-0135(1)/(2)): an operation count, never a
    timing. The walk's own steps (`WalkCounter`: the characters every step was given,
    and the step calls) and the characters the identifier predicate reads each stay
    under a constant times the URL's length, and the output is unchanged (the URL is
    clean). An empty list when they hold."""
    counter_type = getattr(R, "WalkCounter", None)
    if counter_type is None:
        return ["the walk exposes no operation count (PA-0135(2))"]
    judged = []
    real = R.looks_like_identifier
    monkeypatch.setattr(R, "looks_like_identifier",
                        lambda v: judged.append(len(v)) or real(v))
    url = _oracle_url(n)
    counter = counter_type()
    try:
        out = R._walk_url(url, True, counter)
    finally:
        monkeypatch.setattr(R, "looks_like_identifier", real)
    violations = []
    if out != url:
        violations.append("the clean URL changed")
    if not 0 < counter.steps <= _STEPS_PER_CHAR * len(url):
        violations.append(("steps", n, counter.steps, len(url)))
    if not 0 < counter.calls <= _CALLS_PER_PAIR * 4 * n:
        violations.append(("calls", n, counter.calls))
    if not 0 < sum(judged) <= _JUDGED_PER_CHAR * len(url):
        violations.append(("judged", n, sum(judged), len(url)))
    return violations


def test_the_walk_is_linear_in_the_values_length(monkeypatch):
    """PA-0095(2), PA-0135: the walk's operation counts (its own steps, review round 1,
    RU-10, and the identifier predicate's reads) stay under a constant times the URL's
    length at 500 pairs and at 4000 (a walk that re-read the whole query per pair would
    read ~n times it)."""
    assert _linearity_violations(500, monkeypatch) == []
    assert _linearity_violations(4000, monkeypatch) == []


def test_the_linearity_oracle_flags_a_quadratic_walk(monkeypatch):
    """PA-0135(3), PA-0034(2): the oracle is proven on deliberately quadratic variants
    (review round 1, RU-10), each with the real walk's output: (A) a pair step that
    percent-decodes the whole list once per pair -- which the first oracle, counting
    only the identifier predicate's reads, passed; (B) a value step that walks every
    value's decoded layer again after the raw walk (2^depth: the design review round 1
    rejected for RU-1); (C) a pair step that judges the whole query per pair."""
    assert getattr(R, "WalkCounter", None) is not None, \
        "the walk exposes no operation count (PA-0135(2))"
    assert _linearity_violations(100, monkeypatch) == []        # the real walk passes
    walk = R._UrlWalk
    real_pairs, real_value = walk.pairs, walk.value

    def decode_whole_list_per_pair(self, text, depth, top):
        parts = R._PAIR_SEP.split(text)
        for i in range(0, len(parts), 2):
            self.tick(text)
            unquote(text)
            parts[i] = self.pair(parts[i], depth, top)
        return "".join(parts)

    def walk_every_layer_again(self, text, depth, top):
        new = real_value(self, text, depth, top)
        if new == text and R._PCT.search(text) and depth <= R.MAX_VALUE_DEPTH:
            self.layer(text, depth)
        return new

    def judge_whole_query_per_pair(self, text, depth, top):
        parts = R._PAIR_SEP.split(text)
        for i in range(0, len(parts), 2):
            R.looks_like_identifier(text)
            parts[i] = self.pair(parts[i], depth, top)
        return "".join(parts)

    for name, attr, variant in (("A", "pairs", decode_whole_list_per_pair),
                                ("B", "value", walk_every_layer_again),
                                ("C", "pairs", judge_whole_query_per_pair)):
        monkeypatch.setattr(walk, attr, variant)
        found = _linearity_violations(100, monkeypatch)
        monkeypatch.setattr(walk, "pairs", real_pairs)
        monkeypatch.setattr(walk, "value", real_value)
        assert found and "the clean URL changed" not in found, (name, found)


# --- residuals pinned (PA-0054(3)): body redaction is paused by the owner -----------------
@pytest.mark.xfail(strict=True, reason="BUG-0556 residual R1: a captured body's leaf "
                   "holding a nested token is judged by the flat leaf rule "
                   "(`redact_leaf`); body redaction is paused by the owner (audit defect "
                   "26, AU-REDACT) and this lane may not change it")
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
