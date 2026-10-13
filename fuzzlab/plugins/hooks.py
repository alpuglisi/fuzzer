"""Hook names and their dispatch kinds (Phase 10 T10.1, FR-PLUG-2).

Three kinds of hook, dispatched differently by the registry:

- **mutation** — folded: each plugin may return a modified value, threaded to the next
  (``on_request`` rewrites the outgoing request);
- **observation** — fan-out: every plugin is called for its side effects and its return
  value is **ignored** (this is where the oracle/advisory split is enforced — an
  ``on_finding`` observer cannot cause a write, FR-PLUG-5);
- **registration** — collected: at startup, plugins contribute capability (rules,
  payload sources, an oracle, a confirmation-budget prioritizer), and the returns are
  gathered;
- **post-run** — run one by one after the pipeline, each as its own unit of work under
  the advisory write guard (`guard.py`), with its result or contained error reported
  back (CC-PLUG-0005; the ML stages attach here, FR-ML-6).
"""

from __future__ import annotations

ON_REQUEST = "on_request"
ON_RESPONSE = "on_response"
ON_CANDIDATE = "on_candidate"
ON_FINDING = "on_finding"
REGISTER_RULES = "register_rules"
REGISTER_PAYLOAD_SOURCE = "register_payload_source"
REGISTER_ORACLE = "register_oracle"
REGISTER_PRIORITIZER = "register_prioritizer"
AFTER_RUN = "after_run"

MUTATION_HOOKS = frozenset({ON_REQUEST})
OBSERVATION_HOOKS = frozenset({ON_RESPONSE, ON_CANDIDATE, ON_FINDING})
REGISTRATION_HOOKS = frozenset({REGISTER_RULES, REGISTER_PAYLOAD_SOURCE, REGISTER_ORACLE,
                                REGISTER_PRIORITIZER})
POST_RUN_HOOKS = frozenset({AFTER_RUN})
ALL_HOOKS = MUTATION_HOOKS | OBSERVATION_HOOKS | REGISTRATION_HOOKS | POST_RUN_HOOKS
