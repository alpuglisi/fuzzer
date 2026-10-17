"""Start and stop the capture proxy (mitmdump + `recorder`) for one discovery run.

The proxy is a child process tree owned through `procutil` (SP-22, SP-31): started on a
free loopback port, ready only once its own process listens there, checked loopback-only
right after boot (PA-0130), and stopped as a group. mitmdump flushes the recorder on
its shutdown hook, so a normal stop loses nothing; records are flushed one by one, so
an abrupt one loses at most the record being written.

**One capture per run (PA-0450).** The capture file must not exist yet: a discovery run
never appends to, or is credited with, a file an earlier run left behind.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from fuzzlab import procutil
from fuzzlab.core.urls import origin_scope

#: How long the proxy may take to listen.
BOOT_TIMEOUT_S = 60.0


class CaptureExists(FileExistsError):
    """The capture path already holds an earlier run's file."""


@dataclass
class CaptureProxy:
    """``with CaptureProxy([url], out=Path('run/capture.jsonl')) as proxy:`` -- then
    ``proxy.endpoint`` (``127.0.0.1:PORT``) goes to `navguard.browser_launch_args` and
    `navguard.chromium_launch_kwargs` as ``proxy=``."""
    scope_urls: list[str]
    out: Path
    keep_tag: bool = False
    upstream_insecure: bool = False
    profile: str = ""
    endpoint: str | None = None
    _handle: object = field(default=None, repr=False)
    _log: object = field(default=None, repr=False)

    @property
    def stats_path(self) -> Path:
        return self.out.with_name(self.out.name + ".stats.json")

    def options(self) -> list[str]:
        """The recorder's options (everything but the listener, which `start` pins)."""
        workdir = self.out.parent
        return ["--scope", ",".join(self.scope_urls), "--out", str(self.out),
                "--stats", str(self.stats_path), "--confdir", str(workdir / "mitm-conf"),
                "--profile", self.profile,
                *(["--keep-tag"] if self.keep_tag else []),
                *(["--upstream-insecure"] if self.upstream_insecure else [])]

    def start(self) -> "CaptureProxy":
        if not origin_scope(*self.scope_urls):
            raise ValueError("a capture needs at least one in-scope origin")
        if self.out.exists():
            raise CaptureExists(f"{self.out} exists: give each discovery run its own "
                                f"capture file (PA-0450)")
        self.out.parent.mkdir(parents=True, exist_ok=True)
        (self.out.parent / "mitm-conf").mkdir(mode=0o700, exist_ok=True)
        self.out.touch()                    # this run's file, and only this run's
        self._log = open(self.out.with_name(self.out.name + ".proxy.log"), "ab")
        try:
            h, port = procutil.start_server_on_free_port(
                lambda port: [sys.executable, "-m", "fuzzlab.disco.mitm",
                              "--listen-host", "127.0.0.1", "--port", str(port),
                              *self.options()], boot_timeout=BOOT_TIMEOUT_S,
                env_for=lambda port: capture_env(), stdout=self._log, stderr=self._log)
            procutil.assert_loopback_only(h)
        except BaseException:
            self._log.close()
            raise
        self._handle, self.endpoint = h, f"127.0.0.1:{port}"
        return self

    def stop(self) -> None:
        try:
            if self._handle is not None:
                procutil.stop_server(self._handle)
        finally:
            self._handle = None
            if self._log is not None:
                self._log.close()
                self._log = None

    def stats(self) -> dict:
        """The recorder's refusal stats (``blocked`` per host, ``recorded``,
        ``dropped``), or an empty dict when it wrote none."""
        try:
            doc = json.loads(self.stats_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (ValueError, RecursionError):
            return {"unreadable": True}
        return doc if isinstance(doc, dict) else {"unreadable": True}

    def __enter__(self) -> "CaptureProxy":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def capture_env() -> dict[str, str]:
    """The proxy's environment: this process's, minus any proxy of its own (the capture
    proxy talks to the target directly; an inherited ``HTTP(S)_PROXY`` would send lab
    traffic to another hop)."""
    return {k: v for k, v in os.environ.items()
            if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
