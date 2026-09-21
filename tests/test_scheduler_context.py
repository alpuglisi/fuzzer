"""Tests for Phase 4 T4.2: context buckets + catalog-derived priors."""

from fuzzlab.oracle.strategies import default_strategies
from fuzzlab.scheduler import (
    arm_priors,
    catalog_families,
    catalog_priors,
    context_for,
    context_parents,
)


def test_context_parents_specific_to_root():
    assert context_parents("sql-injection:html") == ["sql-injection", ""]
    assert context_parents("sql-injection") == [""]
    assert context_parents("") == []


def test_context_for_buckets():
    assert context_for("sql-injection", "query") == "sql-injection:query"
    assert context_for("xss", "query", "html") == "xss:html"        # sink wins
    assert context_for(None) == "unknown:any"


def test_arm_priors_favor_cheap_mechanisms():
    priors = arm_priors(default_strategies())
    # error-signature (cheap, strong) starts ahead of differential-timing (expensive).
    assert priors["sqli:error-signature"][0] > priors["sqli:differential-timing"][0]
    # every strategy arm has a prior
    assert all(":" in arm for arm in priors)


def test_catalog_families_reads_references():
    fams = catalog_families("sql-injection")
    assert fams and all(isinstance(f, str) for f in fams)           # real .txt families
    assert catalog_families("does-not-exist") == []


def test_catalog_priors_scale_with_family_size():
    priors = catalog_priors("sql-injection")
    assert priors                                                   # non-empty
    for alpha, beta in priors.values():
        assert alpha >= 1.0 and beta == 1.0                         # weak, optimistic
