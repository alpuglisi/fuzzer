"""A loopback HTTP/1.1 peer that keeps connections alive (BUG-0549).

``KeepAlivePeer(reply)`` listens on 127.0.0.1 (an ephemeral port), serves each accepted
connection on its own thread and answers every request on it until the client closes,
so a test can see which connection each request came on and when the client closed a
connection. ``reply(conn, k, req)`` returns the bytes to answer the ``k``-th request
(from 0) of connection ``conn`` (from 1) with, a one-tuple ``(bytes,)`` to answer and
then close, or None to close that connection without an answer; it may block (a test
holding an answer). ``req`` is a `Seen`. With
``tls`` (an ``ssl.SSLContext``) the peer completes a TLS handshake per connection first.

Everything recorded is the test's own traffic: the peer is started by the test and
nothing else connects to it (PA-0150).
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from dataclasses import dataclass, field


@dataclass
class Seen:
    conn: int
    k: int
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def ok(body: bytes = b"ok", *extra: str) -> bytes:
    """A well-framed HTTP/1.1 200 answer with ``Content-Length``."""
    head = ["HTTP/1.1 200 OK", f"Content-Length: {len(body)}", *extra]
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


def echo(conn: int, k: int, req: Seen) -> bytes:
    """The default answer: the request's own path, so a mixed-up answer shows."""
    return ok(req.path.encode())


class KeepAlivePeer:
    def __init__(self, reply=echo, *, tls: ssl.SSLContext | None = None):
        self.reply = reply
        self._tls = tls
        self._cond = threading.Condition()
        self.seen: list[Seen] = []
        self.connections = 0
        self.handshakes = 0
        self.closed: set[int] = set()
        self._live: list[socket.socket] = []
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(64)
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return                                   # the listener was closed
            with self._cond:
                self.connections += 1
                n = self.connections
                self._live.append(conn)
            threading.Thread(target=self._serve, args=(conn, n), daemon=True).start()

    def _serve(self, conn: socket.socket, n: int) -> None:
        try:
            if self._tls is not None:
                conn = self._tls.wrap_socket(conn, server_side=True)
                with self._cond:
                    self.handshakes += 1
                    self._live.append(conn)
            buf = b""
            k = 0
            while True:
                req, buf = self._read_request(conn, buf, n, k)
                if req is None:
                    break
                with self._cond:
                    self.seen.append(req)
                    self._cond.notify_all()
                answer = self.reply(n, k, req)
                k += 1
                close_after = isinstance(answer, tuple)
                if close_after:
                    answer = answer[0]                   # (bytes, ...): close after it
                if answer is None:
                    break
                conn.sendall(answer)
                if close_after:
                    break
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._cond:
                self.closed.add(n)
                self._cond.notify_all()

    @staticmethod
    def _read_request(conn, buf: bytes, n: int, k: int):
        while b"\r\n\r\n" not in buf:
            data = conn.recv(65536)
            if not data:
                return None, b""
            buf += data
        head, buf = buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        method, path = lines[0].split(" ")[:2]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers.setdefault(name.strip().lower(), value.strip())
        if "chunked" in headers.get("transfer-encoding", "").lower():
            while b"0\r\n\r\n" not in buf:
                data = conn.recv(65536)
                if not data:
                    return None, b""
                buf += data
            body, buf = buf.split(b"0\r\n\r\n", 1)
        else:
            length = int(headers.get("content-length") or 0)
            while len(buf) < length:
                data = conn.recv(65536)
                if not data:
                    return None, b""
                buf += data
            body, buf = buf[:length], buf[length:]
        return Seen(n, k, method, path, headers, body), buf

    def wait(self, predicate, timeout: float = 10.0) -> bool:
        """Wait until ``predicate(self)`` holds (re-checked at every request or close)."""
        end = time.monotonic() + timeout
        with self._cond:
            while not predicate(self):
                left = end - time.monotonic()
                if left <= 0:
                    return False
                self._cond.wait(left)
            return True

    def conn_of(self, path: str) -> list[int]:
        """The connections the requests for ``path`` came on, in order."""
        with self._cond:
            return [s.conn for s in self.seen if s.path == path]

    def close(self) -> None:
        try:
            self._srv.close()
        except OSError:
            pass
        with self._cond:
            live = list(self._live)
        for s in live:
            try:
                s.close()
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
