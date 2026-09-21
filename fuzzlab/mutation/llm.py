"""Gated, offline LLM catalog expansion — scaffold (Phase 8 T8.6, FR-MUT-5).

Optionally expand the payload catalog with a generative step. Two hard rules
(NFR-MUT-offline): it is **default off**, and it **never calls an external service** —
the generator is an injected, offline callable (e.g. a local model on-host), or nothing.
Anything it produces is **quarantined for human review** and is not trusted until a
person approves it; the AST/semantics gate still applies before an approved entry is used.

This phase ships the gate and the review queue only; wiring a real local model is on-host
and deferred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

# An offline generator: seeds -> new candidate payloads. Injected; never network-backed.
Generator = Callable[[list[str]], list[str]]


@dataclass
class LlmExpander:
    enabled: bool = False                       # default OFF
    generator: Generator | None = None          # injected offline model, or None
    _pending: list[str] = field(default_factory=list, init=False)
    _approved: list[str] = field(default_factory=list, init=False)

    def expand(self, seeds: list[str]) -> list[str]:
        """Generate candidates into the review queue. Returns [] — nothing is trusted
        until reviewed. A no-op unless enabled AND an offline generator is provided."""
        if not self.enabled or self.generator is None:
            return []
        for cand in self.generator(list(seeds)):
            if cand and cand not in self._pending and cand not in self._approved:
                self._pending.append(cand)      # quarantine, do not trust
        return []

    def pending(self) -> list[str]:
        """Candidates awaiting human review (not yet usable)."""
        return list(self._pending)

    def approve(self, candidate: str) -> bool:
        """A human approves one quarantined candidate for use."""
        if candidate in self._pending:
            self._pending.remove(candidate)
            self._approved.append(candidate)
            return True
        return False

    def approved(self) -> list[str]:
        """Human-reviewed candidates cleared for use (still subject to the semantics gate)."""
        return list(self._approved)
