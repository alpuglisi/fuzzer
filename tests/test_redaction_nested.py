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
percent-encoding, ``+``), separators (``&``, ``;`` and a mix) and credential names and
identifier shapes; each case is proven to store no secret byte, and the benign list
proves ordinary nested values are left byte-identical.
"""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path
from urllib.parse import quote, quote_plus, unquote, urlsplit

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
}


def _inner(name: str, secret: str, sep: tuple[str, str], shape: str) -> str:
    """A nested value holding ``name=secret``: a path with a query, an absolute URL
    with one, or a bare query string; a benign pair and a word with a space first."""
    first, second = sep
    query = f"x=1{first}q=hello world{second}{name}={secret}"
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


CASES = sorted({(d, n, s, sep, enc, shape)
                for d in (1, 2, 3) for (n, s) in SECRETS for sep in _SEPS
                for enc in (_ENCODINGS if d > 1 else ["raw"])
                for shape in (("path", "absolute", "query") if d > 1 else ["query"])})
#: A path parameter in a middle segment (its value percent-encoded: a raw ``/`` would
#: end the segment), alone or after a clean one.
_MATRIX = [f"http://h/app/a;{n}={quote(s, safe='')}/b.php?u=bob" for n, s in SECRETS] + \
    [f"http://h/app/a;x=1;{n}={quote(s, safe='')}/b/c.php?u=bob" for n, s in SECRETS]


def _case_url(case) -> str:
    return _spelling(*case)


def test_the_sweep_is_not_vacuous():
    """Every axis is present; every generated URL holds its secret before redaction."""
    assert len(CASES) == 3 * 10 + 2 * 10 * 3 * 4 * 3
    assert {c[0] for c in CASES} == {1, 2, 3}
    for case in CASES:
        assert _leaks(_case_url(case), case[2]), case


# --- the owner: every spelling is redacted, the URL stays a URL --------------------------
def test_every_nested_spelling_of_a_secret_is_redacted_and_the_url_stays_a_url():
    """BUG-0556: identifier shapes and credential names at any depth, in any encoding and
    behind any separator leave no secret byte in the strongest redactor's output; the
    output parses as the same page (scheme, host, path, the top-level names in order);
    the page is never clean; and the value is one `value_holds_secret` holds for."""
    failures = []
    for case in CASES:
        url = _case_url(case)
        out = R.redact_url_identifiers(url)
        before, after = urlsplit(url), urlsplit(out)
        names = [p.partition("=")[0] for p in re.split(r"[&;]", before.query)]
        kept = [p.partition("=")[0] for p in re.split(r"[&;]", after.query)]
        value = before.query.split("next=", 1)[1] if "next=" in before.query else None
        if (_leaks(out, case[2]) or R.page_url_is_clean(url)
                or (after.scheme, after.netloc, after.path)
                != (before.scheme, before.netloc, before.path)
                or kept[:2] != names[:2]
                or (value is not None and not R.value_holds_secret(unquote(value)))):
            failures.append((case, out))
    assert failures == []


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


def test_a_diagram_reference_holds_no_nested_secret():
    """Finding and trace evidence cite URLs through `core.trace.safe_ref`, which starts
    from `redact_url_identifiers`."""
    from fuzzlab.core.trace import safe_ref
    leaks = [c for c in CASES if _leaks(safe_ref(_case_url(c)), c[2])]
    assert leaks == []


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
])
def test_the_redactors_are_total(url):
    for fn in (R.redact_url, R.redact_url_identifiers):
        assert isinstance(fn(url), str)
    assert isinstance(R.page_url_is_clean(url), bool)
    assert R.redact_url(None) is None and R.page_url_is_clean(None) is False
    assert R.value_holds_secret(None) is False


def test_the_walk_is_linear_in_the_values_length():
    """PA-0095(2): a long ``;``/``&`` list, each value nested once, is walked once per
    level -- the work grows with the length, never with its square."""
    import time
    def cost(n):
        url = "http://h/p?" + "&".join(f"k{i}=%2Fv%3Fa%3D{i};b{i}=c" for i in range(n))
        t0 = time.process_time()
        R.redact_url_identifiers(url)
        return time.process_time() - t0
    small, big = cost(500), cost(4000)
    assert big < small * 8 * 4 + 0.05                     # 8x the input, never 64x


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


@pytest.mark.xfail(strict=True, reason="BUG-0556 residual R2 (pre-existing, PA-0544(1)/(3) "
                   "class, replay binding's scope): a POST form's action query or a "
                   "captured request's URL query is stored as the redactor leaves it and "
                   "its points send that URL; no fresh binding of an endpoint's own query "
                   "exists")
def test_an_endpoint_query_redaction_changed_is_never_a_points_url(tmp_path):
    from bs4 import BeautifulSoup

    from fuzzlab.core.forms import form_record
    from fuzzlab.harness.auto import injection_points_from_store
    from fuzzlab.tools.spider import StorageManager
    from fuzzlab.tools.store_adapter import import_spider
    html = (f"<form method=post action='/app/do.php?token=abc&state={_HEX}'>"
            "<input name=q></form>")
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    sm.record_form(form_record(BeautifulSoup(html, "html.parser").find("form"),
                               "http://h/app/f.php"))
    sm.close()
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        import_spider(tmp_path / "s.db", store, run)
        urls = [p.url for p in injection_points_from_store(store, run, "http://h/app/")]
    assert urls                                               # the form is a point
    assert not [u for u in urls if R.PLACEHOLDER in u or "state=&" in u + "&"]


def test_the_cases_cover_every_axis():
    """The generated sweep's axes, named (so a reviewer sees what 'every spelling'
    means): 3 depths x 10 secrets x 3 separators x 4 encodings x 3 nested shapes."""
    axes = {k: sorted({c[i] for c in CASES})
            for i, k in enumerate(("depth", "name", "secret", "sep", "enc", "shape"))}
    assert axes["depth"] == [1, 2, 3]
    assert set(axes["sep"]) == set(_SEPS) and set(axes["enc"]) == set(_ENCODINGS)
    assert set(axes["shape"]) == {"path", "absolute", "query"}
    assert {n for n, _s in SECRETS} <= set(axes["name"])
    assert list(itertools.islice(CASES, 1))
