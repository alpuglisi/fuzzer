"""A store writer in **another process**, driven step by step (AU-SITETREE, D4).

The web server is one process and a launched scan is another: SQLite's locks, its
shared-memory index and its WAL fold are per process, so a claim about what the web
process sees while a tool writes is tested with the tool in another process, never with
a second connection in the test's own process (two reviewers measured the difference:
DRAFT-AU-SITETREE §1.4, X1/X3).

``Writer(path)`` starts one child (``multiprocessing`` *spawn*: a fresh interpreter that
inherits no SQLite state, and no ``subprocess`` spawn for the PA-0125 guard to own) and
answers one command at a time over a pipe, so a test interleaves the child's commits
with its own reads exactly:

    with Writer(path) as w:
        w("open")            # a Store on the existing file; starts a run
        w("ins", 3)          # three one-row commits
        w("close")

The child exits when the pipe closes (the test ended or failed), and ``__exit__`` joins
it, terminating it only if it did not exit (its own pid, recorded at start).
"""

from __future__ import annotations

import multiprocessing as mp
import os


def _serve(path: str, end) -> None:
    import sqlite3

    from fuzzlab.core.store import Store

    store = None
    conn = None
    run_id = None
    n = 0
    while True:
        try:
            cmd, args = end.recv()
        except EOFError:
            break
        try:
            if cmd == "open":
                store = Store(path, create=False)
                conn = store.conn
                run_id = store.start_run("xproc", "h")
                out = run_id
            elif cmd == "open_plain":              # sqlite3.connect: no fuzzlab pragmas
                conn = sqlite3.connect(path)
                out = conn.execute("PRAGMA journal_mode").fetchone()[0]
            elif cmd == "close":
                (store or conn).close()
                store = conn = None
                out = None
            elif cmd == "ins":                     # args: count[, row size]
                count, size = args[0], (args[1] if len(args) > 1 else 40)
                for _ in range(count):
                    conn.execute("INSERT INTO endpoint (run_id, url, method) VALUES "
                                 "(?, ?, 'GET')", (run_id, f"/x/{n:06d}/" + "y" * size))
                    conn.commit()
                    n += 1
                out = n
            elif cmd == "sql":                     # args: one statement, then a commit
                conn.execute(args[0], tuple(args[1:]))
                conn.commit()
                out = None
            elif cmd == "empty":                   # a write transaction that writes nothing
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("COMMIT")
                out = None
            elif cmd == "checkpoint":              # args: PASSIVE | FULL | RESTART | TRUNCATE
                out = tuple(conn.execute(f"PRAGMA wal_checkpoint({args[0]})").fetchone())
            elif cmd == "wal_header":              # the writer's own WAL header (its process)
                with open(path + "-wal", "rb") as fh:
                    head = fh.read(32)
                out = {"checkpoint_seq": int.from_bytes(head[12:16], "big"),
                       "salts": head[16:24].hex()}
            elif cmd == "count":
                out = conn.execute(args[0]).fetchone()[0]
            elif cmd == "quit":
                end.send(("ok", None))
                break
            else:
                raise ValueError(f"unknown command {cmd!r}")
            end.send(("ok", out))
        except Exception as exc:                   # noqa: BLE001 - reported to the test
            end.send(("err", f"{type(exc).__name__}: {exc}"))
    if store is not None or conn is not None:
        (store or conn).close()


class XprocError(RuntimeError):
    """The writer process answered a command with an error."""


class Writer:
    """One writer process for the store at ``path`` (see the module docstring)."""

    def __init__(self, path) -> None:
        ctx = mp.get_context("spawn")
        self._end, child = ctx.Pipe()
        self._proc = ctx.Process(target=_serve, args=(os.fspath(path), child), daemon=True)
        self._proc.start()
        self.pid = self._proc.pid
        child.close()

    def __call__(self, cmd: str, *args):
        self._end.send((cmd, args))
        if not self._end.poll(60):
            raise XprocError(f"{cmd}: no answer from the writer process in 60 s")
        status, out = self._end.recv()
        if status != "ok":
            raise XprocError(f"{cmd}: {out}")
        return out

    def stop(self) -> None:
        try:
            if self._proc.is_alive():
                self("quit")
        except (OSError, EOFError, XprocError):
            pass
        finally:
            self._end.close()
            self._proc.join(30)
            if self._proc.is_alive():              # only the pid this helper started
                self._proc.terminate()
                self._proc.join(10)

    def __enter__(self) -> "Writer":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def one_commit(path, sql: str, *params) -> None:
    """A short writer in another process: open, one commit, close (a CLI tool's shape)."""
    with Writer(path) as w:
        w("open")
        w("sql", sql, *params)
        w("close")
