"""Phase 10 T10.1: plugin registry, hooks, discovery, isolation, migration 10."""

from fuzzlab.core import migrations
from fuzzlab.core.store import Store
from fuzzlab.plugins import PluginManager, discover
from fuzzlab.plugins.registry import HookRegistry


# --- sample plugins ----------------------------------------------------------
class Tagger:
    """Mutates requests, observes findings, contributes a rule + an oracle."""
    def __init__(self, name, priority=100, calls=None):
        self.name = name
        self.version = "1.0"
        self.priority = priority
        self.calls = calls if calls is not None else []

    def on_request(self, req):
        self.calls.append(self.name)
        return f"{req}|{self.name}"

    def on_finding(self, finding):
        self.calls.append(f"finding:{self.name}")
        return "should-be-ignored"          # observation returns are ignored

    def register_rules(self):
        return [f"rule-{self.name}"]

    def register_oracle(self):
        return f"oracle-{self.name}"


class Boom:
    name = "boom"
    priority = 1                              # would run first if not for the crash
    def on_candidate(self, c):
        raise RuntimeError("kaboom")
    def on_request(self, req):
        return f"{req}|boom"


# --- migration 10 ------------------------------------------------------------
def test_migration_10_adds_run_plugin(tmp_path):
    with Store(tmp_path / "u.db") as store:
        assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS) >= 10
        cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(run_plugin)")}
        assert {"run_id", "name", "version", "priority"} <= cols


# --- ordering + mutation -----------------------------------------------------
def test_priority_orders_dispatch_and_folds():
    calls = []
    m = PluginManager(plugins=[Tagger("b", 20, calls), Tagger("a", 10, calls)])
    assert m.on_request("REQ") == "REQ|a|b"   # priority 10 before 20
    assert calls == ["a", "b"]


def test_mutation_none_return_keeps_prior_value():
    class Noop:
        name = "noop"
        def on_request(self, req):
            return None                       # no change
    assert PluginManager(plugins=[Noop()]).on_request("X") == "X"


# --- observation ignores returns (oracle/advisory split, FR-PLUG-5) ----------
def test_observation_hooks_ignore_returns():
    t = Tagger("obs")
    m = PluginManager(plugins=[t])
    assert m.on_finding({"vuln": "sqli"}) is None   # a return can't become a write
    assert "finding:obs" in t.calls                 # but the hook did run


# --- registration collectors -------------------------------------------------
def test_registration_hooks_collect():
    m = PluginManager(plugins=[Tagger("x"), Tagger("y")])
    assert set(m.rules()) == {"rule-x", "rule-y"}
    assert set(m.oracles()) == {"oracle-x", "oracle-y"}


def test_oracle_is_the_only_plugin_path_to_a_writer():
    class Observer:                            # no register_oracle
        name = "obs"
        def on_finding(self, f):
            return {"forged": True}
    m = PluginManager(plugins=[Observer()])
    assert m.oracles() == []                   # cannot contribute a finding-writer
    assert m.on_finding({}) is None            # and its return is dropped


# --- isolation (FR-PLUG-3) ---------------------------------------------------
def test_failing_plugin_is_disabled_not_fatal():
    calls = []
    m = PluginManager(plugins=[Boom(), Tagger("ok", 50, calls)])
    m.on_candidate({"c": 1})                   # boom raises here
    assert m.disabled() == {"boom"}
    # the run continues; boom is skipped on later hooks, the good plugin still runs
    assert m.on_request("R") == "R|ok"
    assert [i.name for i in m.active()] == ["ok"]


# --- zero plugins is a no-op (NFR-PLUG-optional) -----------------------------
def test_zero_plugins_is_a_noop():
    m = PluginManager()
    assert m.on_request("SAME") == "SAME"
    assert m.on_finding({}) is None
    assert m.rules() == [] and m.oracles() == [] and m.payload_sources() == []
    assert m.active() == []


# --- discovery via injected entry points (FR-PLUG-1) -------------------------
def test_discovery_loads_entry_points_and_contains_failures():
    class FakeEP:
        def __init__(self, name, obj, boom=False):
            self.name = name
            self._obj = obj
            self._boom = boom
        def load(self):
            if self._boom:
                raise ImportError("bad plugin")
            return self._obj                   # a plugin object (or a factory)
    good = Tagger("disc")
    plugins = discover(entry_points=[FakeEP("good", good), FakeEP("bad", None, boom=True)])
    assert [p.name for p in plugins] == ["disc"]     # bad one skipped, run intact


def test_discovery_accepts_a_factory():
    class FakeEP:
        name = "f"
        def load(self):
            return lambda: Tagger("made")      # a zero-arg factory
    (p,) = discover(entry_points=[FakeEP()])
    assert p.name == "made"


# --- reproducibility: record active plugins ----------------------------------
def test_record_writes_active_plugins(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        m = PluginManager(plugins=[Boom(), Tagger("a", 10), Tagger("b", 20)])
        m.on_candidate({})                     # disables boom
        n = m.record(store, run_id)
        assert n == 2
        rows = store.conn.execute(
            "SELECT name, version, priority FROM run_plugin WHERE run_id=? ORDER BY priority",
            (run_id,)).fetchall()
        assert [r["name"] for r in rows] == ["a", "b"]   # boom excluded (disabled)
        assert rows[0]["version"] == "1.0"


def test_registry_defaults_for_bare_plugin():
    class Bare:
        def on_request(self, r):
            return r
    reg = HookRegistry()
    info = reg.register(Bare())
    assert info.name == "Bare" and info.version == "0" and info.priority == 100
