"""Live-boot conformance check for `php_laravel`'s response-header-injection
cell (`CC-LAB-0218`, CircleFeed -- category 2's Facebook pick, third
designed cell): a real, executed, raw-socket-level proof of a genuine
HTTP response-splitting differential.

**Why this does not use `LiveBootHarness`/`php artisan serve` (unlike
every other CircleFeed live-boot test).** `CC-LAB-0218`'s change-control
entry records the empirical finding this test proves the practical
consequence of: PHP's own `header()` function has unconditionally rejected
a header string containing an embedded `\\r`/`\\n` since PHP 5.1.2 (this
project independently re-verified it here too -- see
`test_the_generated_controllers_own_header_call_cannot_be_spliced_through_a_real_php_sapi`
below). A real HTTP request to the *generated Laravel controller*
(`LABGEN-CF-0005`'s literal `header("Location: " . $next); exit;` call,
`raw_redirect_dispatch.php.j2`) therefore cannot itself demonstrate a
spliced header when mediated by `php -S`/`php artisan serve`'s SAPI --
confirmed directly below, not merely asserted. This is not a surprise
unique to this project: this project's own
`docs/research/corpus-examples/header-injection/php/
vulnerable-raw-socket-response-4.php` already documents the real,
still-current residual case -- "a hand-rolled response writer ... that
bypasses `header()` entirely and writes the response line-by-line itself"
-- which is exactly why the safety matrix's vulnerable op for this family
is named `raw_socket_response_write`.

**The proof.** `_RAW_SOCKET_RESPONDER_PHP` below is a small, standalone,
single-shot raw-socket HTTP responder, ported near-verbatim from this
project's own `vulnerable-raw-socket-response-4.php`/
`idiomatic-http-header-filtered-4.php` corpus pair (the SSRF row's own
"ports ... almost verbatim" precedent) -- it implements the *same* two
ops' real logic (`raw_socket_response_write`'s unconditional raw
concatenation vs. `allowlist_and_runtime_crlf_rejection`'s runtime
CRLF/control-character + same-origin-relative-path check, copied from
`allowlist_and_runtime_crlf_rejection.php.j2` verbatim) at the one layer
where the difference is genuinely observable on the wire: a hand-rolled
socket responder, not a framework route. It is never part of the
generated CircleFeed app itself (it exists in this test file only, never
written into `stack/`/shipped anywhere).

Started as a real `php` subprocess on an ephemeral loopback port and
exercised over a real raw Python `socket` (never `http.client`/`requests`,
which normalize/merge headers and reject malformed status lines -- exactly
the failure mode that would mask a genuine split). The vulnerable
responder's crafted `next` value (containing a literal `%0D%0A`-encoded
CRLF introducing a second, attacker-chosen `Set-Cookie` header) is asserted
to result in the raw response bytes genuinely containing that second
header, on its own line, inside the header section (before the blank line
that ends it) -- read directly off the socket, not merely asserted a
priori. The secure responder's identical crafted value is rejected with a
real HTTP 400 and never reaches a `Location`/`Set-Cookie` line at all.

Skip-guarded on a real `php` CLI being on PATH (PA-0005 pattern, though
this test needs no `composer`/network round trip -- only `live_boot.py`'s
`LiveBootHarness`-based tests need that). Marked `@pytest.mark.slow`.
"""

from __future__ import annotations

import shutil
import socket as socket_module
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("php") is None,
    reason="php CLI not available on this build host (PA-0005 pattern)",
)

# Ported near-verbatim from docs/research/corpus-examples/header-injection/
# php/vulnerable-raw-socket-response-4.php (the raw-write half) and
# fuzzlab/labgen/emitters/php_laravel/templates/transforms/
# allowlist_and_runtime_crlf_rejection.php.j2 (the runtime check, copied
# verbatim so this test proves the SAME check the generated secure twin's
# transform applies, not a re-invented one).
_RAW_SOCKET_RESPONDER_PHP = r"""<?php
// Standalone raw-socket HTTP responder used ONLY by CC-LAB-0218's live-boot
// test to prove a genuine, real, executed response-splitting differential.
// Never part of the generated CircleFeed app itself.
//
// Usage: php raw_socket_redirect_responder.php <port> <mode>
// <mode> is "vulnerable" (raw_socket_response_write) or "secure"
// (allowlist_and_runtime_crlf_rejection). Accepts exactly ONE connection,
// handles ONE request, then exits.

$port = (int) $argv[1];
$mode = $argv[2];

$server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "listen failed: {$errstr}\n");
    exit(1);
}
echo "READY\n";
fflush(STDOUT);

$conn = stream_socket_accept($server, 30);
if ($conn === false) {
    exit(1);
}

$requestLine = fgets($conn, 8192);
while (($line = fgets($conn, 8192)) !== false) {
    if (trim($line) === '') {
        break;
    }
}

$next = '';
if (preg_match('#^[A-Z]+\s+(\S+)\s+HTTP/#', (string) $requestLine, $m)) {
    $target = $m[1];
    $query = parse_url($target, PHP_URL_QUERY) ?: '';
    parse_str($query, $params);
    $next = rawurldecode($params['next'] ?? '');
}

if ($mode === 'vulnerable') {
    // raw_socket_response_write: no CR/LF stripping, no allowlist -- the
    // redirect target reaches the raw response exactly as supplied. This
    // bypasses header()'s own built-in CRLF rejection entirely by writing
    // to the socket directly.
    fwrite($conn, "HTTP/1.1 302 Found\r\n");
    fwrite($conn, "Location: " . $next . "\r\n");
    fwrite($conn, "Content-Length: 0\r\n");
    fwrite($conn, "\r\n");
} else {
    // allowlist_and_runtime_crlf_rejection, copied verbatim from
    // fuzzlab/labgen/emitters/php_laravel/templates/transforms/
    // allowlist_and_runtime_crlf_rejection.php.j2.
    if (preg_match('/[\x00-\x1F\x7F]/', $next) === 1
        || !preg_match('#^/[A-Za-z0-9/_\-\.]*$#', $next)) {
        fwrite($conn, "HTTP/1.1 400 Bad Request\r\n");
        fwrite($conn, "Content-Length: 0\r\n");
        fwrite($conn, "\r\n");
    } else {
        fwrite($conn, "HTTP/1.1 302 Found\r\n");
        fwrite($conn, "Location: " . $next . "\r\n");
        fwrite($conn, "Content-Length: 0\r\n");
        fwrite($conn, "\r\n");
    }
}
fclose($conn);
fclose($server);
"""

_CRAFTED_NEXT = "/x\r\nSet-Cookie: injected=1"
# The %0D%0A-encoded wire form a real browser/client would send for the
# crafted value above (raw CR/LF bytes never travel in a real request line
# -- they arrive percent-encoded and are decoded server-side, exactly what
# rawurldecode() above does, mirroring $_GET's own automatic decoding).
_CRAFTED_NEXT_WIRE = "/x%0D%0ASet-Cookie:%20injected=1"


def _find_free_port() -> int:
    with socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _RawSocketResponder:
    """Boots the standalone raw-socket PHP responder above as a real
    subprocess, waits for its own "READY" line (real process
    synchronization, not a sleep), and gives a raw-bytes request/response
    round trip over a real `socket`."""

    def __init__(self, tmp_path, mode: str) -> None:
        script_path = tmp_path / f"raw_socket_redirect_responder_{mode}.php"
        script_path.write_text(_RAW_SOCKET_RESPONDER_PHP)
        self.port = _find_free_port()
        self._proc = subprocess.Popen(
            [shutil.which("php"), str(script_path), str(self.port), mode],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 10.0
        line = self._proc.stdout.readline()
        while line.strip() != "READY" and time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"raw socket responder ({mode}) exited early: {self._proc.stderr.read()}")
            line = self._proc.stdout.readline()
        assert line.strip() == "READY", f"raw socket responder ({mode}) never signalled readiness"

    def raw_request(self, next_value_wire: str, timeout: float = 10.0) -> bytes:
        with socket_module.create_connection(("127.0.0.1", self.port), timeout=timeout) as sock:
            req = f"GET /?next={next_value_wire} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode("ascii"))
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)

    def close(self) -> None:
        self._proc.wait(timeout=10)


def _header_lines(raw_response: bytes) -> list[str]:
    head = raw_response.split(b"\r\n\r\n", 1)[0]
    return head.decode("iso-8859-1").split("\r\n")


@pytest.mark.slow
def test_vulnerable_responder_genuinely_splices_a_real_extra_header(tmp_path) -> None:
    responder = _RawSocketResponder(tmp_path, "vulnerable")
    try:
        raw = responder.raw_request(_CRAFTED_NEXT_WIRE)
        lines = _header_lines(raw)
        assert lines[0] == "HTTP/1.1 302 Found", lines
        # The genuinely spliced-in extra header, read directly off the raw
        # socket bytes -- a real, distinct header line inside the header
        # section (before the blank line), not body text after it.
        assert "Set-Cookie: injected=1" in lines, lines
        assert "Location: /x" in lines, lines
    finally:
        responder.close()


@pytest.mark.slow
def test_secure_responder_rejects_the_crafted_value_with_a_real_400_and_never_splices(tmp_path) -> None:
    responder = _RawSocketResponder(tmp_path, "secure")
    try:
        raw = responder.raw_request(_CRAFTED_NEXT_WIRE)
        lines = _header_lines(raw)
        assert lines[0] == "HTTP/1.1 400 Bad Request", lines
        assert not any(line.startswith("Set-Cookie:") for line in lines), lines
        assert not any(line.startswith("Location:") for line in lines), lines
    finally:
        responder.close()


@pytest.mark.slow
def test_secure_responder_still_accepts_an_ordinary_relative_redirect(tmp_path) -> None:
    """Confirms the secure responder's own functional path still works for
    a legitimate value -- not just that it rejects a crafted one."""
    responder = _RawSocketResponder(tmp_path, "secure")
    try:
        raw = responder.raw_request("/feed")
        lines = _header_lines(raw)
        assert lines[0] == "HTTP/1.1 302 Found", lines
        assert "Location: /feed" in lines, lines
    finally:
        responder.close()


@pytest.mark.slow
def test_the_generated_controllers_own_header_call_cannot_be_spliced_through_a_real_php_sapi(tmp_path) -> None:
    """Direct, independent evidence for the claim this module's docstring
    (and CC-LAB-0218's change-control entry) makes: a real `php -S`
    built-in server request to a script using the exact vulnerable sink
    shape (`header("Location: " . $value); exit;`, LABGEN-CF-0005's own
    literal code) never produces a spliced header -- PHP's own SAPI
    rejects/strips the call outright. Proves the *reason* this test file
    cannot use `LiveBootHarness`/`php artisan serve` for the real proof
    above, rather than only asserting it in prose."""
    script = tmp_path / "sapi_header_probe.php"
    script.write_text(
        "<?php\n"
        "$next = $_GET['next'] ?? '';\n"
        'header("Location: " . $next);\n'
        'echo "body\\n";\n'
    )
    port = _find_free_port()
    proc = subprocess.Popen(
        [shutil.which("php"), "-S", f"127.0.0.1:{port}", str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10.0
        connected = False
        while time.monotonic() < deadline:
            try:
                with socket_module.create_connection(("127.0.0.1", port), timeout=0.5):
                    connected = True
                    break
            except OSError:
                time.sleep(0.1)
        assert connected, "php -S never started listening"

        with socket_module.create_connection(("127.0.0.1", port), timeout=10) as sock:
            req = (
                f"GET /?next={_CRAFTED_NEXT_WIRE} HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            sock.sendall(req.encode("ascii"))
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
        lines = _header_lines(raw)
        # PHP's own SAPI-level protection: no Location header at all (the
        # single header() call with an embedded CR/LF is rejected outright,
        # a real E_WARNING, not sent), and certainly no spliced Set-Cookie.
        assert not any(line.startswith("Location:") for line in lines), lines
        assert not any(line.startswith("Set-Cookie:") for line in lines), lines
    finally:
        proc.terminate()
        proc.wait(timeout=10)
