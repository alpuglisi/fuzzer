"""Pipeline verdict engine (T-LAB0.1) + safety-matrix loader (T-LAB0.2).

Implements the binary verdict model decided in D20
(``docs/DECISIONS_AND_ROADMAP.md``): a cell's verdict, derived from
``(transform, sink_context)`` against a versioned safety matrix, is
**VULNERABLE or SECURE only**. A partially-neutralized transform is
VULNERABLE-but-harder, surfaced via a ``difficulty`` tier on the
:class:`Verdict` — never a third verdict value.

``verdict()`` is a pure function: for a fixed ``matrix``, the same
``(pipeline, sink_context)`` always produces the same output. Snapshot-tested
in ``tests/test_labgen_verdict.py`` so its behavior cannot silently drift for
a given ``safety_matrix_version``; a real behavior change is a new matrix
version (or a new, additive matrix entry), never an edit to how an existing
``(op, sink_family)`` entry is interpreted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from .schema import Pipeline, SinkContext

DEFAULT_SAFETY_MATRIX_SCHEMA_PATH = Path("lab/schemas/safety_matrix.schema.json")
DEFAULT_SAFETY_MATRIX_PATH = Path("lab/safety_matrix.yaml")

# Ordered least -> most difficult. A VULNERABLE verdict always gets one of
# these; a SECURE verdict never has a difficulty (None).
DIFFICULTY_TIERS: tuple[str, ...] = ("trivial", "easy", "medium", "hard", "very_hard")


class SafetyMatrixError(ValueError):
    """Raised for a missing/invalid safety-matrix file, or a pipeline that
    references an (op, sink_family) pair the matrix does not cover."""


class Effect(str, Enum):
    NEUTRALISES = "neutralises"
    PARTIAL = "partial"
    NO_EFFECT = "no_effect"
    INTRODUCES = "introduces"


@dataclass(frozen=True)
class MatrixEntry:
    op: str
    sink_family: str
    effect: Effect
    neutralizes: tuple[str, ...] = ()
    introduces: tuple[str, ...] = ()


@dataclass(frozen=True)
class SafetyMatrix:
    """A versioned, open registry of ``(op, sink_family) -> effect`` entries.

    Callers pin ``version`` (via ``safety_matrix_version`` on a manifest) so
    a corpus generated under an older matrix stays re-derivable under that
    matrix's rules even after new entries/versions are added (CR-LAB-0001 §5
    risk mitigation; additive-only, per this project's append-only
    convention for change-control-style logs).
    """

    version: int
    entries: dict[tuple[str, str], MatrixEntry]

    def lookup(self, op: str, sink_family: str) -> MatrixEntry:
        key = (op, sink_family)
        try:
            return self.entries[key]
        except KeyError as exc:
            raise SafetyMatrixError(
                f"no safety-matrix entry for op={op!r} sink_family={sink_family!r} "
                f"(matrix v{self.version}) — add one to lab/safety_matrix.yaml "
                "rather than defaulting silently"
            ) from exc


def load_safety_matrix_schema(path: str | Path = DEFAULT_SAFETY_MATRIX_SCHEMA_PATH) -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise SafetyMatrixError(f"safety-matrix schema not found at {path!r}")
    return json.loads(path.read_text("utf-8"))


def load_safety_matrix(
    path: str | Path = DEFAULT_SAFETY_MATRIX_PATH,
    *,
    schema_path: str | Path | None = None,
) -> SafetyMatrix:
    """Load and validate ``lab/safety_matrix.yaml`` (or an equivalent file)."""
    path = Path(path)
    if not path.is_file():
        raise SafetyMatrixError(f"safety matrix not found at {path!r}")
    data = yaml.safe_load(path.read_text("utf-8"))
    schema = load_safety_matrix_schema(schema_path) if schema_path is not None else load_safety_matrix_schema()
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        raise SafetyMatrixError(f"safety matrix: {exc.message} at {list(exc.path)}") from exc

    entries: dict[tuple[str, str], MatrixEntry] = {}
    for raw_entry in data["entries"]:
        entry = MatrixEntry(
            op=raw_entry["op"],
            sink_family=raw_entry["sink_family"],
            effect=Effect(raw_entry["effect"]),
            neutralizes=tuple(raw_entry.get("neutralizes", ())),
            introduces=tuple(raw_entry.get("introduces", ())),
        )
        key = (entry.op, entry.sink_family)
        if key in entries:
            raise SafetyMatrixError(f"duplicate safety-matrix entry for (op={key[0]!r}, sink_family={key[1]!r})")
        entries[key] = entry
    return SafetyMatrix(version=data["version"], entries=entries)


@dataclass(frozen=True)
class Verdict:
    """The derived output of ``verdict()``. Never asserted by a manifest
    author — always computed from ``(pipeline, sink_context)`` and a
    :class:`SafetyMatrix`.
    """

    verdict: str  # "VULNERABLE" | "SECURE"
    difficulty: str | None
    safety_matrix_version: int
    satisfied: tuple[str, ...]
    missing: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "difficulty": self.difficulty,
            "safety_matrix_version": self.safety_matrix_version,
            "satisfied": list(self.satisfied),
            "missing": list(self.missing),
        }


def _difficulty_tier(score: int) -> str:
    index = min(max(score, 0), len(DIFFICULTY_TIERS) - 1)
    return DIFFICULTY_TIERS[index]


def verdict(pipeline: Pipeline, sink_context: SinkContext, matrix: SafetyMatrix) -> Verdict:
    """Derive the binary verdict for one ``(pipeline, sink_context)`` cell
    against ``matrix`` (D20).

    Algorithm (pure, order-sensitive over ``pipeline.ops``):

    1. Start with ``required`` = ``sink_context.required_neutralizations``.
    2. Walk the pipeline in order. For each op, look up its effect at this
       sink family:
       - ``neutralises`` fully satisfies the concerns it names (and clears
         any earlier ``partial`` credit for the same concerns).
       - ``partial`` credits the concerns it names as *partially* addressed
         (tracked separately; never counted as fully satisfied).
       - ``no_effect`` does nothing.
       - ``introduces`` adds new concerns to ``required`` (and revokes any
         prior full/partial credit for those specific concerns — a later op
         can still neutralize them again).
    3. ``missing`` = ``required`` minus fully-satisfied concerns.
       - Empty ``missing`` -> **SECURE**, no ``difficulty``.
       - Non-empty ``missing`` -> **VULNERABLE**; ``difficulty`` rises with
         the number of ``missing`` concerns that got at least partial credit
         (harder to see through) and with pipeline length beyond one op.

    An ``(op, sink_family)`` pair not present in ``matrix`` raises
    :class:`SafetyMatrixError` rather than silently defaulting to
    ``no_effect`` — an authoring gap should fail loud, not derive a quiet
    wrong answer.
    """
    required: set[str] = set(sink_context.required_neutralizations)
    fully: set[str] = set()
    partially: set[str] = set()

    for op in pipeline.ops:
        entry = matrix.lookup(op, sink_context.family)
        if entry.effect is Effect.NEUTRALISES:
            fully |= set(entry.neutralizes)
            partially -= set(entry.neutralizes)
        elif entry.effect is Effect.PARTIAL:
            partially |= set(entry.neutralizes) - fully
        elif entry.effect is Effect.INTRODUCES:
            newly_required = set(entry.introduces)
            required |= newly_required
            fully -= newly_required
            partially -= newly_required
        elif entry.effect is Effect.NO_EFFECT:
            pass
        else:  # pragma: no cover - Effect is a closed Enum
            raise SafetyMatrixError(f"unknown effect {entry.effect!r}")

    missing = required - fully
    if not missing:
        return Verdict(
            verdict="SECURE",
            difficulty=None,
            safety_matrix_version=matrix.version,
            satisfied=tuple(sorted(fully)),
            missing=(),
        )

    difficulty_score = len(partially & missing) + max(len(pipeline.ops) - 1, 0)
    return Verdict(
        verdict="VULNERABLE",
        difficulty=_difficulty_tier(difficulty_score),
        safety_matrix_version=matrix.version,
        satisfied=tuple(sorted(fully)),
        missing=tuple(sorted(missing)),
    )
