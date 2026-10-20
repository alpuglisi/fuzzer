"""pytest plugin (scratchpad, non-vacuity run): route every producer to the rev-3
prototypes -- the owner (`proto3`), the proxy's fail-closed framing (`framing3`), the
spider's page text, the auditor's write site and cut sites, and the importer's example
rule -- to check that tests/test_text_body_redaction.py passes against the drafted design.
Run: pytest -p proto3_plugin (with this directory on PYTHONPATH)."""
import os
from urllib.parse import parse_qsl as _parse_qsl

REVERT = os.environ.get("REVERT", "")

import importlib

import proto3

framing3 = importlib.import_module("framing3_rev3" if REVERT == "rev3framing" else "framing4")

import fuzzlab.core.redaction as r
import fuzzlab.disco.capture as c
import fuzzlab.disco.runner as ru
import fuzzlab.proxy.history as ph
import fuzzlab.proxy.redact as pr
import fuzzlab.tools.fetcher as F
import fuzzlab.tools.spider as sp
import fuzzlab.tools.store_adapter as sa
from fuzzlab.proxy.message import RawMessage


def redact_body(body, content_type, *, stats=None):
    return proto3.new_redact_body(body, content_type, stats)


_orig_redact = pr.redact


def _hdr(msg, name):
    return [v.decode("latin-1", "replace") for v in msg.get_all(name)]


def judge_framed(msg, body, *, stats=None):
    return framing3.judge(_hdr(msg, "Transfer-Encoding"), _hdr(msg, "Content-Encoding"),
                          (msg.get("Content-Type") or b"").decode("latin-1"), body, stats)


def redact(raw, extra_headers=()):
    msg = RawMessage.from_bytes(raw)
    framed = msg.body and (msg.get("Transfer-Encoding") is not None
                           or msg.get("Content-Encoding") is not None)
    if not framed:
        return _orig_redact(raw, extra_headers)
    body = msg.body
    head = RawMessage.from_bytes(_orig_redact(msg.with_body(b"").raw, extra_headers))
    judged = judge_framed(msg, body)
    if judged == body:
        return head.with_body(body).raw
    out = head.without_header("Transfer-Encoding").without_header("Content-Encoding")
    out = out.with_body(judged)
    return out.with_header("Content-Length", str(len(judged))).raw


def redact_body_for(raw, body):
    if not body:
        return body
    msg = RawMessage.from_bytes(raw or b"")
    if msg.get("Transfer-Encoding") is not None or msg.get("Content-Encoding") is not None:
        return judge_framed(msg, body)
    return redact_body(body, (msg.get("Content-Type") or b"").decode("latin-1"))


FramingStats = framing3.Stats


# spider: page text from the redacted HTML, and title/content redacted at the write
_orig_parse_html = sp._parse_html
_orig_mark_visited = sp.StorageManager.mark_visited


def _parse_html(html, base):
    title, _text, links = _orig_parse_html(html, base)
    red = proto3.new_redact_body(html.encode("utf-8", "replace"), "text/html")
    if red.startswith(b"__BODY_OMITTED__"):
        return title, None, links
    t2, text, _l = _orig_parse_html(red.decode("utf-8", "replace"), base)
    return t2, text, links


def mark_visited(self, url, status_code, depth, title=None, content=None, *a, **k):
    title = proto3.redact_page_text(title) if title else title
    content = proto3.redact_page_text(content) if content else content
    return _orig_mark_visited(self, url, status_code, depth, title, content, *a, **k)


# auditor: redact before every cut; the write site redacts page_url and html_context
_orig_log_finding = F.log_finding
_orig_field = F.PageContext._field


def record_url(u):
    """`redact_record_url`: the stored-URL rule (sensitive and identifier-like query
    values) and the record rule (query-shaped fragments, userinfo, matrix parameters);
    the path is kept."""
    return r.redact_for_record("url", r.redact_url_identifiers(u))


def rule_unsafe_target_blank(ctx, emit):
    for link in (ctx.soup.find_all("a", href=True) if ctx.soup else []):
        if (link.get("target") or "").lower() != "_blank":
            continue
        rel = " ".join(link.get("rel") or []).lower()
        if "noopener" in rel or "noreferrer" in rel:
            continue
        href = link["href"][:120] if REVERT == "cutfirst" else link["href"]
        emit(record_url(href)[:120], f"target=_blank without rel=noopener on {ctx.path}")


def log_finding(cursor, url, category, trans_type, target, context="", reference=None):
    target = record_url(target) if ("?" in target or "#" in target) and "=" in target \
        else target
    if REVERT == "idblank":
        target, url = proto3.redact_record_text(target), proto3.redact_record_text(url)
    return _orig_log_finding(cursor, record_url(url), category, trans_type,
                             target,
                             proto3.redact_record_text(context or ""), reference)


def _field(self, el, action, method, in_form):
    f = _orig_field(self, el, action, method, in_form)
    if f:
        f["html"] = (proto3.redact_record_text(str(el)[:150]) if REVERT == "cutfirst"
                     else proto3.redact_record_text(str(el))[:150])
    return f


def rule_action_attributes(ctx, emit):
    for form in (ctx.soup.find_all("form") if ctx.soup else []):
        target = F._form_target(ctx.url, form)
        method = (form.get("method") or "GET").upper()
        emit(target, f"method={method} {proto3.redact_record_text(str(form))[:150]}")


def _qv(name, value, n):
    """`_quote_value`: the leaf rule (a sensitive name or an identifier-like value is
    blanked), then the cut."""
    return str(r.redact_leaf([name], value))[:n]


def _by_name(ctx, emit, vocabulary, label):
    for target, name, value, where in ctx.candidates():
        if name.lower() in vocabulary:
            emit(target, f"{label} ({where}), example value: {_qv(name, value, 60)}")


def rule_query_strings(ctx, emit):
    for name, value in ctx.params:
        emit(f"{ctx.path}?{name}", f"example value: {_qv(name, value, 80)}")


def rule_predictable_ids(ctx, emit):
    for name, value in ctx.params:
        if value.isdigit():
            emit(f"{ctx.path}?{name}", f"numeric value: {_qv(name, value, 80)}")


def rule_duplicated_parameters(ctx, emit):
    seen = {}
    for name, value in ctx.params:
        seen.setdefault(name, []).append(value)
    for name, values in seen.items():
        if len(values) > 1:
            emit(f"{ctx.path}?{name}",
                 f"supplied {len(values)}x: {', '.join(_qv(name, v, 20) for v in values)}")


def rule_privileged_hidden_fields(ctx, emit):
    for f in ctx.fields:
        if f["name"].lower() in F.PRIVILEGED_FIELDS:
            emit(f["target"], f"privileged-looking {f['ftype']} field, value="
                 f"'{_qv(f['name'], f['value'], 40)}' {f['html']}")


def rule_serialized_tokens(ctx, emit):
    haystacks = [("response body", ctx.html)]
    haystacks += [(f"parameter {name}", value) for name, value in ctx.params]
    haystacks += [(f"field {f['name']}", f["value"]) for f in ctx.fields if f["value"]]
    for where, text in haystacks:
        for pattern, kind in F.SERIALIZED_TOKEN_PATTERNS:
            match = pattern.search(text or "")
            if match:
                emit(f"{ctx.path} [{kind}]", f"{kind} found in {where}: "
                     f"{proto3.redact_record_text(match.group(0))[:60]}...")


_RULE_REPLACEMENTS = {f.__name__: f for f in (
    rule_action_attributes, rule_query_strings, rule_predictable_ids,
    rule_duplicated_parameters, rule_privileged_hidden_fields, rule_serialized_tokens,
    rule_unsafe_target_blank)}


def _sa_parse_qsl(qs, **kw):
    return [(n, "" if r.is_sensitive_name(n) else v) for n, v in _parse_qsl(qs, **kw)]


def pytest_configure(config):
    for m in (r, c, ru, pr):
        m.redact_body = redact_body
    r.TEXT_OPS_CAP, r.TEXT_MAX_HITS = proto3.OPS_CAP, proto3.MAX_HITS
    r.TEXT_SKELETON_SCAN = proto3.SKELETON_SCAN
    pr.redact, pr.redact_body_for = redact, redact_body_for
    ph.redact, ph.redact_body_for = redact, redact_body_for
    pr.FramingStats, pr.judge_framed = FramingStats, judge_framed
    pr.FRAME_MEMBER_CAP, pr.FRAME_FIRST_PIECE = framing3.MEMBER_CAP, framing3.FIRST_PIECE
    framing3.CAP_SOURCE = pr
    sp._parse_html = _parse_html
    sp.StorageManager.mark_visited = mark_visited
    F.log_finding = log_finding
    F.PageContext._field = _field
    F.rule_action_attributes = rule_action_attributes
    F._by_name = _by_name
    F.RULES = {k: _RULE_REPLACEMENTS.get(v.__name__, v) for k, v in F.RULES.items()}
    sa.parse_qsl = _sa_parse_qsl
