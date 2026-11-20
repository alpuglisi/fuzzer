"""Tests for the M1 timing-differential ReDoS confirmation strategy
(CC-LAB-0076, `RegexDosStrategy`) -- a genuinely new M1 variant (see the
class's own docstring for why it differs from `_confirm_timing`'s SQLi/
command-injection use). These tests exercise the strategy's *decision
logic* against a fake, deterministic-timing sender (the same convention
`test_oracle_vectors.py::test_command_injection_confirmed_on_rising_delay`
already uses for `_confirm_timing`'s other user) -- the underlying
mechanism itself (that V8's regex engine really does blow up on these
templates, and that escaping really does prevent it) is proven separately,
with real execution and real measured timing, in
`tests/test_labgen_redos.py`."""

from fuzzlab.oracle import Candidate, category_to_oracle_class
from fuzzlab.oracle.probe import Probe
from fuzzlab.oracle.strategies import _REDOS_TEMPLATES, RegexDosStrategy


def _cand():
    return Candidate(url="http://h/search", param="q", vuln_class="redos")


class _RegexEngineSender:
    """Simulates a vulnerable target: any of the known evil-shape templates
    (matched exactly, as the target would receive them verbatim as the
    search term) take much longer than an ordinary term; everything else is
    fast."""

    def __init__(self, evil_elapsed: float = 0.06, benign_elapsed: float = 0.001):
        self.evil_elapsed = evil_elapsed
        self.benign_elapsed = benign_elapsed

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        elapsed = self.evil_elapsed if value in _REDOS_TEMPLATES else self.benign_elapsed
        return Probe(200, "ok", elapsed=elapsed)


class _EscapedSender:
    """Simulates a secure target: escaping means every payload -- benign or
    evil-shaped -- takes the same, fast, ordinary time."""

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        return Probe(200, "ok", elapsed=0.001)


def test_redos_confirmed_on_vulnerable_target():
    v = RegexDosStrategy().confirm(_cand(), _RegexEngineSender())
    assert v is not None and v.confirmed
    assert v.vuln_class == "redos"
    assert v.mechanism == "differential-timing"
    assert len(v.evidence["confirming_templates"]) >= 2


def test_redos_not_confirmed_when_escaped():
    assert RegexDosStrategy().confirm(_cand(), _EscapedSender()) is None


def test_redos_not_confirmed_on_a_single_slow_reading():
    """Never confirm from one slow response -- at least two independent
    evil-shape templates must each clear the threshold (the ReDoS analogue
    of _confirm_timing's two-escalating-delays requirement)."""

    class _OneSlowTemplateSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            if value == _REDOS_TEMPLATES[0]:
                return Probe(200, "ok", elapsed=0.06)
            return Probe(200, "ok", elapsed=0.001)

    assert RegexDosStrategy().confirm(_cand(), _OneSlowTemplateSender()) is None


def test_redos_not_confirmed_when_gap_is_within_jitter():
    """A measured gap that never clears floor/k above the baseline's own
    jitter must not confirm -- ordinary noise is not a finding."""

    class _NoisySender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            # 3ms vs a ~1ms baseline: real jitter-scale noise, well under
            # this strategy's 20ms floor.
            elapsed = 0.003 if value in _REDOS_TEMPLATES else 0.001
            return Probe(200, "ok", elapsed=elapsed)

    assert RegexDosStrategy().confirm(_cand(), _NoisySender()) is None


def test_regular_expression_category_maps_to_redos():
    assert category_to_oracle_class("regular-expression") == "redos"


def test_redos_strategy_applies_to_its_own_category():
    strategy = RegexDosStrategy()
    matching = Candidate(url="http://h/x", param="q", category="regular-expression")
    other = Candidate(url="http://h/x", param="q", category="sql-injection")
    assert strategy.applies(matching) is True
    assert strategy.applies(other) is False


# --- FR-FUZZ-711 (BUG-0733, CC-FUZZ-0711): the threshold is the target's own --------

def test_every_template_has_a_structural_control_minus_its_ambiguity():
    """PA-0117(1)/PA-0630(1): each control is its template with the nested or ambiguous
    quantifier removed -- same group, same class, same `$` anchor, never the template."""
    from fuzzlab.oracle.strategies import _REDOS_CONTROLS
    assert set(_REDOS_CONTROLS) == set(_REDOS_TEMPLATES)
    for evil, control in _REDOS_CONTROLS.items():
        assert control != evil and control.endswith("$") and len(control) < len(evil)
        assert control.startswith("(") and control.count("(") == evil.count("(")


def test_redos_not_confirmed_when_any_regex_shaped_term_is_slow():
    """A target slow for every pattern of this shape (a regex compile or an error path,
    no backtracking) is slow on the control too: no verdict from the ambiguity."""
    class _SlowForAnyPattern:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, "ok", elapsed=0.06 if "(" in value else 0.001)

    assert RegexDosStrategy().confirm(_cand(), _SlowForAnyPattern()) is None


def test_redos_not_confirmed_when_the_slowness_does_not_repeat():
    """Each evil template is re-sent `rounds` times; a slow first answer alone (a GC
    pause, a cold cache) is not a finding."""
    class _SlowOnce:
        def __init__(self):
            self.seen = set()

        def send(self, url, param, value, timing=False, method="GET", location="query"):
            if value in _REDOS_TEMPLATES and value not in self.seen:
                self.seen.add(value)
                return Probe(200, "ok", elapsed=0.06)
            return Probe(200, "ok", elapsed=0.001)

    assert RegexDosStrategy().confirm(_cand(), _SlowOnce()) is None


def test_a_jittery_endpoint_that_is_not_vulnerable_never_confirms():
    """Every answer -- benign, control and evil alike -- takes a uniformly random 0-40 ms
    (twice the former fixed 20 ms floor): over 300 seeded runs, never a verdict."""
    import random

    class _Jittery:
        def __init__(self, seed):
            self.rng = random.Random(seed)

        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, "ok", elapsed=self.rng.uniform(0.0, 0.040))

    confirmed = [seed for seed in range(300)
                 if RegexDosStrategy().confirm(_cand(), _Jittery(seed)) is not None]
    assert confirmed == []


def test_a_vulnerable_endpoint_behind_the_same_jitter_still_confirms():
    """The same 0-40 ms jitter on every answer, with the evil templates 400 ms slower:
    the threshold follows the measured spread and still confirms."""
    import random

    class _JitteryVulnerable:
        def __init__(self, seed):
            self.rng = random.Random(seed)

        def send(self, url, param, value, timing=False, method="GET", location="query"):
            extra = 0.4 if value in _REDOS_TEMPLATES else 0.0
            return Probe(200, "ok", elapsed=extra + self.rng.uniform(0.0, 0.040))

    for seed in range(50):
        v = RegexDosStrategy().confirm(_cand(), _JitteryVulnerable(seed))
        assert v is not None and v.confirmed, seed
        assert all("control" in t for t in v.evidence["confirming_templates"])
