"""Where the store is when ``--store`` is not given: the one resolution (FR-CORE-400).

Every command that takes ``--store`` and the web UI's config (`core.config.load_config`)
resolve the store here, so a CLI command and the UI it was launched from always agree
(PA-0003, PA-0021). In order:

1. ``--store PATH`` (an explicit empty value is a usage error, never "unset");
2. ``$FUZZLAB_STORE``;
3. ``$FUZZLAB_STORE_PATH`` (the config key's long-standing environment form);
4. :data:`DEFAULT_STORE` -- ``fuzzlab.db`` in the current directory, the shared project
   store the web UI has always used.

``FUZZLAB_STORE`` wins over ``FUZZLAB_STORE_PATH`` everywhere; an empty variable counts as
unset; ``~`` is expanded. :func:`from_environ` never raises, so `load_config` -- called by
commands that never touch the store -- cannot fail because of it.

Nothing here writes to the filesystem: :func:`resolve` is pure, and the boundary checks
(:func:`check_readable`, :func:`check_writable`) only stat. ``Store(path)`` creates the
file, and only writers open a store that does not exist yet (`docs/CLI_WORKING_VS_
TRAINING_DESIGN.md` §4.2). Stdlib only: sends nothing, imports no tool.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

#: The default store, relative to the current directory. The one literal: config's
#: ``DEFAULTS["store_path"]`` refers to it.
DEFAULT_STORE = "fuzzlab.db"

#: The environment variables, highest precedence first.
ENV_NAMES = ("FUZZLAB_STORE", "FUZZLAB_STORE_PATH")

#: The source label of the default.
DEFAULT_SOURCE = "default"

#: How the default is stated in help text (built from :data:`DEFAULT_STORE`, never restated).
DEFAULT_RULE = f"$FUZZLAB_STORE, else $FUZZLAB_STORE_PATH, else ./{DEFAULT_STORE}"


def store_help(what: str) -> str:
    """``--store`` help for a command: ``what`` plus the default rule."""
    return f"{what} (default: {DEFAULT_RULE})"


class StorePathError(ValueError):
    """A store path that cannot be used, said in a sentence a CLI prints as a usage error."""


@dataclass(frozen=True)
class ResolvedStore:
    path: Path      # absolute
    source: str     # "--store" | "FUZZLAB_STORE" | "FUZZLAB_STORE_PATH" | "default"

    @property
    def is_default(self) -> bool:
        return self.source == DEFAULT_SOURCE


def from_environ(environ: Mapping[str, str] | None = None) -> tuple[str, str] | None:
    """``(path, variable name)`` from the environment, or None. Never raises."""
    env = os.environ if environ is None else environ
    for name in ENV_NAMES:
        raw = env.get(name)
        if raw is not None and raw.strip():
            return os.path.expanduser(raw.strip()), name
    return None


def resolve(value: str | None, *, environ: Mapping[str, str] | None = None) -> ResolvedStore:
    """The store to use for ``--store value`` (None when the flag is absent). Pure."""
    if value is not None:
        if not value.strip():
            raise StorePathError("--store: empty path (omit --store to use the default store)")
        return ResolvedStore(_absolute(os.path.expanduser(value)), "--store")
    found = from_environ(environ)
    if found is not None:
        return ResolvedStore(_absolute(found[0]), found[1])
    return ResolvedStore(_absolute(DEFAULT_STORE), DEFAULT_SOURCE)


def resolve_store(value: str | None) -> Path:
    """The store path for ``--store value`` (None when absent)."""
    return resolve(value).path


def _absolute(path: str) -> Path:
    return Path(os.path.abspath(path))


def _where(rs: ResolvedStore) -> str:
    return f"{rs.path} ({_label(rs)})"


def _label(rs: ResolvedStore) -> str:
    return "default store" if rs.is_default else rs.source


def describe(rs: ResolvedStore) -> str:
    """The line printed in run summaries, e.g. ``store: /home/u/proj/fuzzlab.db (default)``."""
    return f"store: {rs.path} ({rs.source})"


def check_readable(rs: ResolvedStore) -> None:
    """Refuse a store that does not exist or is not a regular file (never creates one)."""
    try:
        st = os.stat(rs.path)
    except FileNotFoundError:
        hint = ("; run a command that writes one first, or pass --store PATH"
                if rs.is_default else "")
        raise StorePathError(f"no such store: {_where(rs)}{hint}") from None
    except OSError as exc:
        raise StorePathError(f"cannot read store {_where(rs)}: {exc.strerror}") from None
    if not stat.S_ISREG(st.st_mode):
        raise StorePathError(f"not a store file: {_where(rs)}")


def check_writable(rs: ResolvedStore) -> None:
    """Refuse a store whose directory is missing, or a path that is not a regular file."""
    try:
        st = os.stat(rs.path)
    except FileNotFoundError:
        parent = rs.path.parent
        if not parent.is_dir():
            raise StorePathError(
                f"cannot create store {_where(rs)}: directory {parent} does not exist"
            ) from None
        return
    except OSError as exc:
        raise StorePathError(f"cannot use store {_where(rs)}: {exc.strerror}") from None
    if not stat.S_ISREG(st.st_mode):
        raise StorePathError(f"not a store file: {_where(rs)}")
