"""``StackEnv`` for the ``node_express`` stack (``CR-LAB-0001`` Addendum D).

Addendum D adds ``StackEnv`` to the module schema for stacks whose emitter is
multi-file and framework-routed (unlike ``php_current``, which is
filesystem-routed and needs none of this). This module defines the concrete
``StackEnv`` type and the one instance this emitter uses -- kept local to
this emitter package rather than added to ``fuzzlab.labgen.schema`` (a
shared, read-only file for this lane, per the task's scope-discipline
instructions); a future cross-emitter refactor that lifts ``StackEnv`` into
a shared module can absorb this instance unchanged, since its shape already
matches Addendum D's schema field-for-field.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

SCAFFOLD_ROOT = Path(__file__).parent / "scaffold"


@dataclass(frozen=True)
class StackEnv:
    """Per-stack build/runtime environment (Addendum D, adapted from
    BaxBench's ``Env``).

    Fields match Addendum D's list exactly: ``language``, ``framework``,
    ``framework_version``, a digest-pinned ``base_image``, ``workdir``,
    ``entrypoint_cmd``, ``is_multi_file``, ``scaffold_files`` (rendered once
    per stack), ``accumulators`` (files fed by one fragment per cell), and
    ``file_roles`` (path templates per per-cell artifact type).
    """

    language: str
    framework: str
    framework_version: str
    base_image: str
    workdir: str
    entrypoint_cmd: tuple[str, ...]
    is_multi_file: bool
    scaffold_files: dict[str, bytes] = field(default_factory=dict)
    accumulators: tuple[str, ...] = ()
    file_roles: dict[str, str] = field(default_factory=dict)


def _load_scaffold_files() -> dict[str, bytes]:
    """Read this stack's per-stack scaffold files once, deterministically,
    from ``scaffold/`` on disk -- never generated per cell. Sorted by path
    so the resulting dict's insertion order (and any caller that iterates
    it) is itself deterministic, per this project's general "never rely on
    unordered dict/set iteration" rule.
    """
    files: dict[str, bytes] = {}
    for path in sorted(SCAFFOLD_ROOT.rglob("*")):
        if path.is_file():
            rel = path.relative_to(SCAFFOLD_ROOT).as_posix()
            files[rel] = path.read_bytes()
    return files


#: The Node LTS base image, pinned by digest per CR-LAB-0001 Addendum D's
#: "soft-guarantee digest-pinned + SBOM-recorded" split determinism
#: guarantee -- see scaffold/Dockerfile's own header comment for the digest's
#: provenance and the re-pin command to run before a real build.
_BASE_IMAGE = (
    "node@sha256:93a7d0e0f6a1407b7e3d83325f9efcc096ead281667613141430347a925fe918"
    "  # node:22-bookworm-slim, Node 22 LTS ('Jod')"
).split("  #")[0]

NODE_EXPRESS_STACK_ENV = StackEnv(
    language="node",
    framework="express",
    framework_version="4.22.3",
    base_image=_BASE_IMAGE,
    workdir="/app",
    entrypoint_cmd=("node", "app.js"),
    is_multi_file=True,
    scaffold_files=_load_scaffold_files(),
    # `app.js`'s route-registration lines: one fragment per supported cell,
    # merged and sorted by cell ID at render time -- never by append/
    # iteration order (Addendum D's determinism rule) -- see
    # __init__.py's render_route_accumulator().
    accumulators=("app.js",),
    file_roles={
        "controller": "routes/{cell_id_lower}.js",
        "route": "app.js",
    },
)
