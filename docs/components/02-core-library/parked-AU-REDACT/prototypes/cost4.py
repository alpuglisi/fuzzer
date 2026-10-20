"""Revision 4 cost: every crafted shape from both reviewers' probes (cost.py, cost_r3.py,
cost3.py) and this lane's, each at 1 MiB and at 8 MiB, through the owner prototype.
Time and ops; one run each. --mem traces the peak instead."""
import base64
import json
import sys
import time
import tracemalloc

import proto3

MEM = "--mem" in sys.argv
CANARY = b'<input type="hidden" name="csrf" value="v">'


def fill(unit, size, head=b"<html>", tail=b""):
    return head + unit * ((size - 64 - len(head) - len(tail)) // len(unit)) + tail


def b64state(size):
    blobs, n, i = [], 0, 0
    while n < size:
        b = base64.b64encode(json.dumps({"id": i, "name": f"item{i}", "tags": ["a", "b"]},
                                        separators=(",", ":")).encode())
        blobs.append(b)
        n, i = n + len(b), i + 1
    return b'<html><body><div data-state="' + b"".join(blobs)[:size - 64] + b'"></div>'


SHAPES = {   # name: (builder(size), content type)
    "A lex_tag '=' x60k per tag": (lambda z: fill(b'<a name="csrf" ' + b"=" * 60000 + b">", z), "text/html"),
    "A lex_tag '=' x4k per tag": (lambda z: fill(b'<a name="csrf" ' + b"=" * 4000 + b">", z), "text/html"),
    "A in_bind_attr walk 120 '/'": (lambda z: fill(b"/" * 120 + b" token ", z), "text/html"),
    "A type=hidden, no '<'": (lambda z: fill(b"type=hidden ", z, head=b"<html>" + b"x" * 70000), "text/html"),
    "A type=hidden, tag 60k back": (lambda z: fill(b"<i " + b"type=hidden " * 5000 + b">", z), "text/html"),
    "A token=1& one line": (lambda z: fill(b"token=1&", z, head=b""), "text/plain"),
    "A token:[1,...] in JS": (lambda z: fill(b"token:[" + b"1," * 2000 + b"1],", z), "application/javascript"),
    "A name=csrf after 8 '<'": (lambda z: fill(b'<b title="' + b"<x>" * 8 + b'" name="csrf" value="v">', z), "text/html"),
    "A benign html": (lambda z: fill(b"<p>The quick brown fox jumps over the lazy dog.</p>\n", z), "text/html"),
    "A3 eyJ run, no dot": (lambda z: fill(b"eyJ", z, head=b"<p>"), "text/html"),
    "A3 base64-JSON state attribute": (lambda z: b64state(z), "text/html"),
    "A3 unclosed <script> + csrf input": (lambda z: fill(b"<script>", z, tail=b"<input name=csrf value=x>"), "text/html"),
    "A3 unprovable + identifier-like tags": (lambda z: fill(b"<Ab1Cd2Ef3Gh4Ij5Kl6>", z, head=b'<html><input name="csrf" value="unterminated'), "text/html"),
    "A3 PEM BEGIN x N, END at end": (lambda z: fill(b"-----BEGIN RSA PRIVATE KEY-----\n", z, head=b"", tail=b"-----END RSA PRIVATE KEY-----"), "text/plain"),
    "B3 unclosed <script>x + binding": (lambda z: fill(b"<script>x", z, tail=CANARY), "text/html"),
    "B3 eyJ run (text/plain)": (lambda z: fill(b"eyJ", z, head=b""), "text/plain"),
    "B3 unclosed <style + binding": (lambda z: fill(b"<style ", z, tail=CANARY), "text/html"),
    "L <input name=csrf value=1>": (lambda z: fill(b"<input name=csrf value=1>", z), "text/html"),
    "L many hidden inputs": (lambda z: fill(b'<input type="hidden" name="a" value="x1y2z3w4v5u6t7s8">', z), "text/html"),
    "L json leaves": (lambda z: b"[" + b'{"note":"token: x","q":"a&key=b"},' * ((z - 64) // 35) + b"{}]", "text/plain"),
    "L unterminated quote attrs + hits": (lambda z: fill(b"<a title='x name=csrf>", z), "text/html"),
    "L '@' look backs (a:b@c( dense)": (lambda z: fill(b"a:b@c(", z, head=b""), "text/plain"),
    "L Bearer tokens dense": (lambda z: fill(b"Bearer abcdefgh12 ", z, head=b""), "text/plain"),
    "L '//' dense, no '@'": (lambda z: fill(b"//" + b"a" * 30 + b" ", z, head=b""), "text/plain"),
}


def run(body, ct):
    st = {}
    if MEM:
        tracemalloc.start()
    t0 = time.perf_counter()
    out = proto3.new_redact_body(body, ct, st)
    dt = time.perf_counter() - t0
    peak = tracemalloc.get_traced_memory()[1] if MEM else 0
    if MEM:
        tracemalloc.stop()
    return dt, st, out, peak


print(f"{'shape':40s} {'1 MiB ms':>9s} {'ops':>8s} {'8 MiB ms':>9s} {'ops':>8s}  result at 8 MiB")
worst = (0, "")
for name, (build, ct) in SHAPES.items():
    cells = []
    for size in (1 << 20, 8 << 20):
        dt, st, out, peak = run(build(size), ct)
        cells.append((dt, st.get("ops"), out, peak))
        if dt > worst[0]:
            worst = (dt, f"{name} @ {size >> 20} MiB")
    res = cells[1][2]
    res = ("omitted: " + res.split(b": ", 1)[1].split(b")")[0].decode()) if res.startswith(b"__BODY_OMITTED__") \
        else ("unchanged" if False else "redacted/kept")
    if MEM:
        print(f"{name:40s} {cells[0][3] / 2**20:8.1f}M {'':8s} {cells[1][3] / 2**20:8.1f}M")
    else:
        print(f"{name:40s} {cells[0][0] * 1e3:9.0f} {cells[0][1]:8d} {cells[1][0] * 1e3:9.0f} "
              f"{cells[1][1]:8d}  {res}")
print("worst:", f"{worst[0] * 1e3:.0f} ms", worst[1])
