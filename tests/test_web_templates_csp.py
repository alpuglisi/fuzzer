"""BUG-0064 / PA-0065: no template may contain markup the app's own CSP blocks.

`fuzzlab.web.app._CSP` is `script-src 'self'; style-src 'self'` (CC-UI-0026). A template
with an inline `<script>`, a `<style>` block, a `style=""` attribute, an `on*=` handler or
a `javascript:` URL renders fine in every `TestClient` test and is silently refused by a
real browser — which is how the no-FOUC preferences script and the Overview severity bar
went dead. This guard scans every template statically (the real-browser counterpart is
`tests/test_web_pages_browser.py`). Each pattern is proven on must-match and
must-not-match fixtures first (PA-0034(2), PA-0022).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from fuzzlab.web import app as web_app

TEMPLATES = Path(web_app.__file__).resolve().parent / "templates"

# `<script` whose attributes carry no src= (attribute-anchored, case-insensitive)
_INLINE_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.I)
_STYLE_BLOCK = re.compile(r"<style\b", re.I)
# a style= attribute: preceded by whitespace inside a tag, word-anchored
_STYLE_ATTR = re.compile(r"<[^>]*\sstyle\s*=", re.I)
# an inline event handler attribute: whitespace, then on<letters>=, inside a tag
_HANDLER_ATTR = re.compile(r"<[^>]*\son[a-z]+\s*=", re.I)
_JS_URL = re.compile(r"""(?:href|src|action|formaction)\s*=\s*["']?\s*javascript:""", re.I)

CHECKS = {
    "inline <script> (no src)": _INLINE_SCRIPT,
    "<style> block": _STYLE_BLOCK,
    "style= attribute": _STYLE_ATTR,
    "on*= event handler": _HANDLER_ATTR,
    "javascript: URL": _JS_URL,
}


@pytest.mark.parametrize("pattern, text", [
    (_INLINE_SCRIPT, "<script>\n  try { x() } catch (e) {}\n</script>"),
    (_INLINE_SCRIPT, '<SCRIPT type="text/javascript">x()</SCRIPT>'),
    (_STYLE_BLOCK, "<style>.a{color:red}</style>"),
    (_STYLE_ATTR, '<div class="ft2" style="margin-top:.7rem">Live output</div>'),
    (_STYLE_ATTR, '<div class="sev-seg"\n     style="width:{{ w }}%"></div>'),
    (_HANDLER_ATTR, '<button onclick="go()">x</button>'),
    (_HANDLER_ATTR, '<img src="a.png"\n  onerror = "x()">'),
    (_JS_URL, '<a href="javascript:void(0)">x</a>'),
    (_JS_URL, "<form action='  javascript:alert(1)'>"),
])
def test_guard_patterns_catch_the_blocked_constructs(pattern, text):
    assert pattern.search(text), text


@pytest.mark.parametrize("text", [
    '<script src="/static/js/prefs.js"></script>',
    '<script type="module" src="/static/js/shell.js"></script>',
    '<a href="/proxy" data-section="proxy">Proxy</a>',
    '<meta name="viewport" content="width=device-width">',
    '<button aria-controls="panel-1" data-onboarding="1">x</button>',
    '<rect class="sev-seg" x="0" width="50" height="10"></rect>',
    '<link rel="stylesheet" href="/static/css/shell.css">',
    "<p>The page styles itself; onclick handlers live in JS modules.</p>",
    '<a href="/docs/javascript-notes">notes</a>',
])
def test_guard_patterns_ignore_legitimate_markup(text):
    hits = [name for name, pat in CHECKS.items() if pat.search(text)]
    assert hits == [], (text, hits)


def test_the_csp_this_guard_enforces_is_still_strict():
    # if the CSP is ever loosened, this guard's premise (and PA-0065) must be revisited
    assert "script-src 'self'" in web_app._CSP and "style-src 'self'" in web_app._CSP
    assert "unsafe-inline" not in web_app._CSP


def test_no_template_contains_csp_blocked_markup():
    templates = sorted(TEMPLATES.rglob("*.html"))
    assert templates, "no templates found"
    offenders = []
    for path in templates:
        text = path.read_text(encoding="utf-8")
        for name, pat in CHECKS.items():
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                offenders.append(f"{path.relative_to(TEMPLATES)}:{line}: {name}")
    assert offenders == [], "\n".join(offenders)
