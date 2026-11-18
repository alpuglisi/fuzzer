"""Testing a target on another machine (D73): the out-of-band listener reachable through
an operator-given public URL or an opted-in non-loopback bind (FR-FUZZ-70), and crawled
endpoints on operator-declared origins probed (FR-FUZZ-71). Every scope test uses
non-loopback hosts (PA-0052): a loopback-only test cannot catch a filter that drops a
real target."""

from __future__ import annotations

import sqlite3
import urllib.request

import pytest

from fuzzlab.core.store import Store
from fuzzlab.core.urls import canonical_origin
from fuzzlab.harness import auto_cli
from fuzzlab.harness.auto import header_points_from_store, injection_points_from_store
from fuzzlab.oracle.oob import OobListener, normalize_public_url
from fuzzlab.tools import store_adapter

APP = "https://app.example.com"
API = "https://api.example.com"
OTHER = "https://cdn.example.org"
API_STORED = "https://api.example.com:443"   # another origin is stored canonical (FR-AUD-27)


# --- FR-FUZZ-70: the OOB listener for a remote target ------------------------------

def test_a_non_loopback_bind_is_refused_without_the_opt_in():
    for host in ("0.0.0.0", "203.0.113.7", "cb.example.net"):
        with pytest.raises(ValueError):
            OobListener(host)


def test_a_non_loopback_bind_is_admitted_with_the_opt_in_and_never_bound_until_start():
    listener = OobListener("0.0.0.0", 8000, public_bind=True)   # constructed, not bound
    assert not listener.running and listener.port == 8000
    with pytest.raises(ValueError):
        OobListener("", 8000, public_bind=True)


def test_callback_urls_use_the_public_url_and_a_forwarded_hit_is_recorded():
    """The tunnel's far end is the public URL; its near end delivers to the loopback
    listener. A payload names the public URL; a request carrying its path is a hit."""
    listener = OobListener(public_url="https://cb.example.net/hooks/")
    listener.start()
    try:
        token = listener.register()
        url = listener.callback_url(token)
        assert url == f"https://cb.example.net/hooks/cb/{token}"
        assert "127.0.0.1" not in url
        forwarded = f"http://127.0.0.1:{listener.port}/hooks/cb/{token}"
        with urllib.request.urlopen(forwarded, timeout=5) as resp:
            assert resp.read().decode() == listener.proof(token)
        hit = listener.wait_for(token, timeout=2)
        assert hit is not None and hit.token == token
    finally:
        listener.stop()


def test_without_a_public_url_callbacks_name_the_bind_address():
    listener = OobListener()
    listener.start()
    try:
        assert listener.callback_url("ab").startswith(f"http://127.0.0.1:{listener.port}/")
    finally:
        listener.stop()


@pytest.mark.parametrize("bad", ["", "cb.example.net", "ftp://cb.example.net",
                                 "https://cb.example.net/?x=1", "https://u:p@cb.example.net",
                                 "https://cb.example.net/#f", "https://cb.example.net:99999"])
def test_a_malformed_public_url_is_refused(bad):
    with pytest.raises(ValueError):
        normalize_public_url(bad)


def test_the_cli_parses_oob_listen_and_refuses_bad_values():
    assert auto_cli._oob_bind(None) == ("127.0.0.1", 0)
    assert auto_cli._oob_bind("0.0.0.0:8000") == ("0.0.0.0", 8000)
    assert auto_cli._oob_bind("[::]:8000") == ("::", 8000)
    for bad in ("8000", "host:", "host:x", ":8000", "h:70000"):
        with pytest.raises(ValueError):
            auto_cli._oob_bind(bad)


@pytest.mark.parametrize("argv", [["--oob-public-url", "https://cb.example.net"],
                                  ["--oob-listen", "0.0.0.0:8000"]])
def test_the_oob_options_need_oob(argv, tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        auto_cli.main(["--base-url", APP, "--store", str(tmp_path / "s.db"),
                       "--authorized", "--categories", "xss", *argv])
    assert exc.value.code == 2 and "need --oob" in capsys.readouterr().err


# --- FR-FUZZ-71: declared origins are probed, others never -------------------------

def _store_with(tmp_path, urls):
    db = tmp_path / "spider.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE discovered_pages (url TEXT, status_code INT, source TEXT)")
    con.executemany("INSERT INTO discovered_pages VALUES (?,200,'link')", [(u,) for u in urls])
    con.commit()
    con.close()
    store = Store(tmp_path / "s.db")
    run = store.start_run("crawl", "h")
    store_adapter.import_spider(db, store, run, base_url=APP)
    return store, run


def test_a_declared_origin_is_probed_and_an_undeclared_one_is_not(tmp_path):
    store, run = _store_with(tmp_path, [APP + "/a?x=1", API + "/b?y=1", OTHER + "/c?z=1"])
    with store:
        skipped = []
        undeclared = injection_points_from_store(store, run, APP + "/", skipped=skipped)
        assert [p.url for p in undeclared] == [APP + "/a"]
        assert {s[2] for s in skipped} == {"y", "z"}

        skipped = []
        declared = injection_points_from_store(
            store, run, APP + "/", skipped=skipped,
            scope_origins=frozenset({canonical_origin(API)}))
        assert sorted(p.url for p in declared) == [API_STORED + "/b", APP + "/a"]
        assert [s[2] for s in skipped] == ["z"]
        assert "--scope-origin" in skipped[0][3]


def test_header_points_follow_the_same_scope(tmp_path):
    store, run = _store_with(tmp_path, [APP + "/a", API + "/b", OTHER + "/c"])
    with store:
        pts = header_points_from_store(store, run, APP + "/", ["X-Forwarded-Host"],
                                       skipped=[],
                                       scope_origins=frozenset({canonical_origin(API)}))
        assert sorted({p.url.split("?")[0] for p in pts}) == [API_STORED + "/b", APP + "/a"]


def test_the_cli_canonicalises_scope_origins_and_refuses_paths():
    assert auto_cli._scope_origins(["https://API.example.com/"]) == \
        [canonical_origin("https://api.example.com")]
    for bad in ("api.example.com", "https://api.example.com/v1", "https://api.example.com?q",
                "ftp://api.example.com", "https://u@api.example.com"):
        with pytest.raises(ValueError):
            auto_cli._scope_origins([bad])


def test_auto_refuses_without_authorized(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        auto_cli.main(["--base-url", APP, "--store", str(tmp_path / "s.db"),
                       "--categories", "xss"])
    assert exc.value.code == 2 and "--authorized" in capsys.readouterr().err
    assert not (tmp_path / "s.db").exists()
