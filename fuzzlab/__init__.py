"""fuzzlab — a modular, lab-only injection security-testing toolkit.

Phase 0 foundations: a shared ``core`` library (config, store, migrations,
logging, request budget, HTTP seam, versioned features), a ground-truth label
contract, an integration harness, and a local web control panel.

Lab-only and authorized-use only. Nothing here is intended to be pointed at a
target you do not own, and the toolkit never runs against the target without an
explicit choice by the user (the no-auto-run principle, decision D11).
"""

__version__ = "0.0.0"
