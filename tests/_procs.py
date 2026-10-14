"""Test-only process helpers (BUG-0125)."""

from __future__ import annotations

from fuzzlab import procutil


def raw_members(kind: str, ident: int, since: int) -> list[procutil.ProcStat]:
    """For assertions only (never used to signal): every live process carrying this
    group (``kind="pgid"``) or session (``"sid"``) id and started no earlier than
    ``since`` -- whether or not the leader pid is still held, unlike ``procutil``'s
    trusted enumeration."""
    return [st for st in procutil._iter_stats()
            if (st.pgid if kind == "pgid" else st.sid) == ident and st.start >= since
            and st.state != "Z"]
