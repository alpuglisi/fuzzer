"""Phase 10 follow-up: the register_payload_source consumer (payload pool)."""

from fuzzlab.mutation.filtermodel import FilterModel
from fuzzlab.mutation.payloads import PayloadPool
from fuzzlab.mutation.search import MutationSearch
from fuzzlab.plugins import PluginManager


class _SqliSource:
    """A register_payload_source plugin contributing extra SQLi seeds."""
    name = "sqli-payloads"
    def payloads_for(self, vuln_class, sink_context=None):
        return ["1) OR (1=1", "admin'--"] if vuln_class == "sql-injection" else []
    def register_payload_source(self):
        return self


def test_pool_has_builtins():
    pool = PayloadPool()
    sqli = pool.payloads("sql-injection")
    assert "' OR '1'='1" in sqli and len(sqli) >= 2
    assert pool.payloads("xss")                        # non-empty for known classes
    assert pool.payloads("nonexistent-class") == []    # unknown → empty (no builtins)


def test_pool_merges_sources_and_dedupes():
    dup = type("Dup", (), {"payloads_for": lambda self, vc, sc=None:
                           ["' OR '1'='1", "extra-1"]})()   # first dups a builtin
    pool = PayloadPool(sources=[dup])
    sqli = pool.payloads("sql-injection")
    assert sqli.count("' OR '1'='1") == 1              # deduped against builtins
    assert "extra-1" in sqli
    assert sqli.index("' OR '1'='1") < sqli.index("extra-1")   # builtins first


def test_bad_source_is_skipped():
    class Boom:
        def payloads_for(self, vc, sc=None):
            raise RuntimeError("bad source")
    pool = PayloadPool(sources=[Boom()])
    assert pool.payloads("sql-injection") == PayloadPool().payloads("sql-injection")


def test_from_plugins_collects_register_payload_source():
    mgr = PluginManager(plugins=[_SqliSource()])
    pool = PayloadPool.from_plugins(mgr)
    sqli = pool.payloads("sql-injection")
    assert "admin'--" in sqli and "1) OR (1=1" in sqli   # plugin seeds present
    assert "' OR '1'='1" in sqli                          # builtins still there


def test_search_pool_runs_search_per_seed():
    fm = FilterModel.from_lab()
    search = MutationSearch(fm, seed=1, budget=20)
    pool = PayloadPool.from_plugins(PluginManager(plugins=[_SqliSource()]))
    results = search.search_pool(pool, "sql-injection")
    # one result per seed payload (builtins + plugin)
    assert len(results) == len(pool.payloads("sql-injection"))
    assert all(hasattr(r, "variant") and r.semantics_ok for r in results)
