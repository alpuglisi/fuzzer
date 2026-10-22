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

import pytest

from fuzzlab.core import redaction as R
from fuzzlab.core.store import Store
from tests.test_redaction_nested import (_PASS, _WORD, _SilentFetcher, _dump, _leaks,
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
