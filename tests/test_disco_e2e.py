"""The disco pipeline for real (D70): a real mitmdump (procutil-owned) and a real,
guarded Chromium explore a client-rendered app (`tests/_disco_app.py`) on loopback;
the capture is synthesized; a contract runs against the same app.

These are the measurements the design rests on (CLAUDE.md, rule 8): the guarded
browser's traffic reaches the capture proxy, the listener-only ``div``s and the
validated form are found, the out-of-scope image is never fetched, destructive
controls are never acted on. Under ``FUZZLAB_REQUIRE_BROWSER=1`` a missing browser or
mitmproxy fails instead of skipping (PA-0065)."""

from __future__ import annotations

import json

import pytest

from tests._browser import skip_or_fail
from tests._disco_app import DiscoApp


def _require_real():
    for mod in ("playwright.sync_api", "mitmproxy"):
        try:
            __import__(mod)
        except ImportError as exc:
            skip_or_fail(f"{mod} unavailable: {exc}")


@pytest.fixture(scope="module")
def discovered(tmp_path_factory):
    _require_real()
    from playwright.sync_api import Error as PlaywrightError

    from fuzzlab.disco.explore import Explorer, ExploreOptions
    from fuzzlab.disco.proxyproc import CaptureProxy
    out = tmp_path_factory.mktemp("disco")
    with DiscoApp() as other, DiscoApp(other=other.url) as app:
        with CaptureProxy([app.url], out=out / "capture.jsonl", profile="anon") as proxy:
            try:
                report = Explorer(app.url, scope_urls=[app.url], proxy=proxy.endpoint,
                                  options=ExploreOptions(max_actions=80, deadline_s=240),
                                  actions_log=out / "actions.jsonl").run()
            except PlaywrightError as exc:
                if "Executable doesn't exist" in str(exc) or "launch" in str(exc).lower():
                    skip_or_fail(f"chromium unavailable: {str(exc).splitlines()[0]}")
                raise
        yield {"app": app, "other": other, "out": out, "report": report,
               "stats": proxy.stats()}


def test_the_hidden_api_surface_is_reached(discovered):
    """Listener-only navigation, a validated form (POST), the UUID it returns reused by
    a PUT and by a dialog-only webhook: none of it is in any HTML."""
    paths = discovered["app"].paths()
    assert "/api/projects" in paths and "/api/projects/101/tasks" in paths
    assert "/api/projects/101/tasks" in discovered["app"].paths("POST")
    # a value the script's validator accepts (aria-invalid after blur) and one that fits
    # the `-?[\d]*` pattern: both blocked every submission before (BUG-0502)
    [body] = [json.loads(b) for m, p, _h, b in discovered["app"].hits
              if m == "POST" and p == "/api/projects/101/tasks"][:1]
    assert 1000000 <= int(body["phone"]) <= 9999999999 and body["check"].isdigit()
    assert any(p.startswith("/api/tasks/") for p in discovered["app"].paths("PUT"))
    assert "/api/hooks/notify" in discovered["app"].paths("POST")
    assert discovered["report"].submissions >= 1
    assert "/help" in paths                     # a page that navigates away under the reads
    # one-time and dismissed UI, a hash router and state classes never make a state
    # unrestorable (BUG-0501: Juice Shop's start page was, and nothing was explored)
    assert discovered["report"].unrestorable == 0
    assert discovered["report"].transient_dropped >= 1


def test_a_search_box_is_submitted_by_enter_and_chrome_is_acted_on_once(discovered):
    """BUG-0502: a form-less search box (no submit control) is filled and Enter pressed;
    the toolbar holding it is on every route, and its button -- which shares the search
    box's container, so it looks like a submitter -- is acted on once in the whole run,
    not once per state. A submission counts as sent only when the filled values reach a
    request."""
    searches = [p for p in discovered["app"].paths() if p == "/api/search"]
    assert searches
    actions = [json.loads(ln) for ln in (discovered["out"] / "actions.jsonl").open()]
    assert any(a["kind"] == "enter" for a in actions)
    theme = [a for a in actions if a["label"] == "Theme"]
    assert len(theme) == 1, theme
    report = discovered["report"]
    assert 1 <= report.submissions_sent < report.submissions
    assert report.chrome_skipped >= 1


def test_destructive_controls_and_other_origins_are_never_reached(discovered):
    paths = discovered["app"].paths()
    assert "/api/account/remove" not in paths and "/logout" not in paths
    assert discovered["report"].refused.get("destructive:delete")
    assert discovered["other"].hits == []                 # another loopback port: nothing
    assert discovered["report"].out_of_scope.get("127.0.0.1")


def test_every_exchange_is_recorded_with_its_cause_and_the_tag_never_reaches_the_app(
        discovered):
    from fuzzlab.disco.capture import ACTION_HEADER, read_capture
    read = read_capture(discovered["out"] / "capture.jsonl")
    assert read.quarantined == 0
    api = [r for r in read.records if "/api/" in r.url]
    assert api and all(r.action_id and r.profile == "anon" for r in api)
    assert {r.method for r in api} >= {"GET", "POST", "PUT"}
    assert discovered["stats"]["recorded"] == len(read.records)
    for _m, _p, headers, _b in discovered["app"].hits:
        assert ACTION_HEADER not in {k.lower() for k in headers}
    actions = [json.loads(ln) for ln in (discovered["out"] / "actions.jsonl").open()]
    assert any(a["kind"] == "submit" for a in actions)


def test_the_capture_synthesizes_templates_and_dependencies(discovered):
    from fuzzlab.disco.capture import read_capture
    from fuzzlab.disco.synth import endpoints, synthesize
    inv = synthesize(read_capture(discovered["out"] / "capture.jsonl").records)
    ops = {(m, t): op for t, m, op in endpoints(inv)}
    assert ("GET", "/api/projects/{p1}/tasks") in ops
    post = ops[("POST", "/api/projects/{p1}/tasks")]
    body = post["requestBody"]["content"]["application/json"]["schema"]
    assert body["properties"]["owner_email"].get("format") == "email"
    assert "created_by" in post["x-disco"]["response_only_fields"]
    put = ops[("PUT", "/api/tasks/{p1}")]
    assert put["x-disco"]["dependencies"][0]["producer"] == post["operationId"]
    hook = ops[("POST", "/api/hooks/notify")]
    assert hook["x-disco"]["dependencies"][0]["target"] == "body.$.task_id"


def test_a_contract_built_from_it_runs_against_the_app(discovered, tmp_path):
    """Phase 2 (a fake provider) and Phase 3 (the real HTTP client) on the inventory:
    the app accepts a negative estimate, which the oracle flags."""
    import yaml

    from fuzzlab.disco.capture import read_capture
    from fuzzlab.disco.contract import load_contract
    from fuzzlab.disco.generate import Generation, build_contract
    from fuzzlab.disco.runner import Runner
    from fuzzlab.disco.synth import synthesize
    inv = synthesize(read_capture(discovered["out"] / "capture.jsonl").records)
    none = {"path_params": [], "query": [], "headers": [], "body_json": "", "raw_body": "",
            "content_type_override": ""}

    class Provider:
        def generate(self, system, user, schema):
            payload = json.loads(user)
            ep = payload["endpoint"]
            if ep["method"] != "POST" or not ep["path"].endswith("/tasks"):
                return Generation(text='{"cases": []}')
            dep = payload["context"]["dependencies"][0]
            body = {"title": "abc", "owner_email": "a@b.co", "estimate": -5,
                    "code": "ABC-12", "priority": "low"}
            return Generation(text=json.dumps({"cases": [{
                "class": "boundary", "rationale": "estimate observed 1..10",
                "auth_profile": "anon",
                "setup": [{"call": dep["producer"], "auth_profile": "anon", "path_params": [],
                           "query": [], "body_json": "",
                           "extract": [{"var": "pid", "jsonpath": dep["extract"]}]}],
                "request": dict(none, path_params=[{"name": "p1", "value": "{{pid}}"}],
                                body_json=json.dumps(body)),
                "oracle": {"expect_status_class": ["4xx"],
                           "findings_if": [{"kind": "status_class", "value": "5xx"}]},
                "safety": {"destructive": False, "idempotent": False}}]}))

    contract, report = build_contract(inv, Provider(), run_id="run-e2e")
    assert report.kept == 1
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(contract, sort_keys=False))
    [result] = Runner(load_contract(path), authorized=True).run()
    assert result["status"] == 201 and result["verdict"] == "finding"
    assert result["matched"] == ["expect_status_class"]


def test_the_proxy_refuses_an_out_of_scope_request_on_its_own(tmp_path):
    """The firewall layer alone (no browser): an HTTP client pointed at the capture
    proxy reaches the in-scope app and never the other one."""
    _require_real()
    import requests

    from fuzzlab.disco.capture import read_capture
    from fuzzlab.disco.proxyproc import CaptureExists, CaptureProxy
    with DiscoApp() as other, DiscoApp() as app:
        with CaptureProxy([app.url], out=tmp_path / "c.jsonl") as proxy:
            s = requests.Session()
            s.trust_env = False
            proxies = {"http": f"http://{proxy.endpoint}"}
            assert s.get(app.url + "api/settings", proxies=proxies, timeout=10).json()[
                "theme"] == "light"
            with pytest.raises(requests.RequestException):
                s.get(other.url + "api/settings", proxies=proxies, timeout=10)
        assert other.hits == []
        assert proxy.stats()["blocked"] == {"127.0.0.1": 1}
        assert [r.url for r in read_capture(tmp_path / "c.jsonl").records] == [
            app.url + "api/settings"]
        with pytest.raises(CaptureExists):
            CaptureProxy([app.url], out=tmp_path / "c.jsonl").start()


def test_the_run_directory_feeds_auto(discovered, tmp_path):
    """FR-AUD-23: `fuzzlab auto --disco-run` reads this run as crawl points -- the
    validated form's JSON leaves and the Enter-submitted search's query."""
    from fuzzlab.core.store import Store
    from fuzzlab.harness.auto import injection_points_from_store
    from fuzzlab.tools.store_adapter import import_disco
    actions = [json.loads(ln) for ln in (discovered["out"] / "actions.jsonl").open()]
    assert all(a["url"] for a in actions if a["new_state"])
    assert any(f[0] == "title" for a in actions
               for f in a.get("fields", []))
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("e2e", "hash")
        import_disco(discovered["out"], store, run_id)
        base = discovered["app"].url
        got = {(p.method, p.url.replace(base.rstrip("/"), ""), p.param)
               for p in injection_points_from_store(store, run_id, base)}
    assert ("POST", "/api/projects/101/tasks", "title") in got
    assert ("GET", "/api/search", "q") in got
