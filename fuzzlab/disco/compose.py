"""The explorer's read of a page's composed UI tree (FR-CRAWL-39, FR-CRAWL-40; BUG-0551).

`read_page` reads what a page offers across its composed tree:

* **Open shadow roots** -- every document is walked through `tools.composed.COMPOSED_JS`
  (SP-70). A control inside a web component is described like any other. Its
  ``ancestry`` goes on past the shadow root: ``^shadow<`` and the host, for every host
  above it. The element signature (`fingerprint.element_signature`) therefore says
  which component it is in, and a step on it is re-found there on replay.
* **Frames** -- a frame is read only when it is visible, its document is same-origin
  with the page that holds it, and its document URL and ``src`` are in scope. It is
  read by the same script run in that frame's own main-world context: the DevTools
  listener query sees only its own realm's listeners (measured, BUG-0551). Up to
  `MAX_FRAMES` frames are read, `MAX_FRAME_DEPTH` deep. A frame's elements carry
  ``frame`` (the frame-marker keys from the page down) and an ancestry that ends
  ``^frame<iframe#id<@/path`` for every frame above. `frame_scope` turns the keys into
  the Playwright frame locators that act on them.
* **Listener and delegated candidates** -- in each document, DevTools' Command Line API
  ``getEventListeners`` (``Runtime.evaluate`` with ``includeCommandLineAPI``) runs inside
  the read: one round trip per document instead of one per candidate. A candidate with
  an action listener of its own is a ``listener`` element, as before. A candidate with no
  listener and no pointer cursor is a **delegated** candidate when an ancestor in its
  composed path -- an element, a shadow root, its document or its window -- listens for
  `DELEGATE_LISTENERS` (``document.addEventListener('click', ...)`` serving the element
  it targets). Such a candidate must have text, an icon or an aria-label, must hold no
  other candidate and no described element (a container's click lands on what it
  holds), and must not cover a quarter of the viewport. Only the first of each shape is
  kept, at most `MAX_DELEGATED` per read. The explorer tries each once (`Trials`) and
  keeps the ones whose click made a request or changed the state.
* **Workflow markers** (FR-CRAWL-31, BUG-0539) -- each described element carries
  ``sel`` (a select's value, a box's checked state, ARIA selection), and each document
  read returns its page-level markers (``PageRead.marks``: named hidden inputs, and the
  ``aria-current`` elements it did not describe), across its composed tree, in the same
  read as the elements. `fingerprint.execution_key` reads them; a delegated candidate's
  are never part of it (`fingerprint.counts_for_state`).

What is not read is counted in the run report, never claimed (`PageRead`):

* closed shadow roots -- every element of a document read that hosts one, on any host
  (a ``div`` as well as a custom element; one that slots visible light children as
  well as one that renders nothing), found by one ``DOM.getDocument`` of the whole
  page with every shadow root pierced (`_census`; BUG-0551 review B4);
* frames that are cross-origin or out of scope;
* every bound a read hit (``budget_limited``).

Without DevTools (a non-Chromium browser), the read runs through Playwright: no listener
or delegated candidates, and no closed-root census (its elements counted unchecked).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from fuzzlab.disco.fingerprint import normalise_route
from fuzzlab.tools.composed import COMPOSED_JS

#: Listener types on an element that make it actionable itself.
ACTION_LISTENERS = ("click", "mousedown", "mouseup", "pointerdown", "pointerup",
                    "keydown", "touchstart", "dblclick")
#: Listener types on an ancestor that may serve a click on a descendant (delegation).
#: ``mousedown``/``touchstart``/``keydown`` on a document are mostly focus monitors and
#: dismiss handlers, not actions, and are left out.
DELEGATE_LISTENERS = ("click", "dblclick", "mouseup", "pointerup")
#: Elements described per read, across the page and its frames.
MAX_ELEMENTS = 400
#: Non-semantic candidates checked for listeners per document.
MAX_CDP_CANDIDATES = 200
#: Delegated candidates kept per read (the first of each shape).
MAX_DELEGATED = 16
#: Delegated candidates tried per run; the rest are counted ``delegated_unexplored``.
MAX_DELEGATED_TRIALS = 48
#: Elements a document's walk visits before it stops (counted ``budget_limited.nodes``).
MAX_NODES = 30000
#: Frames read per page read, and how deep (``budget_limited.frames`` counts the rest,
#: and a frame whose read failed because it was navigating under it).
MAX_FRAMES = 8
MAX_FRAME_DEPTH = 3
#: The bounds a read reports in ``budget_limited`` (what each left out): described
#: elements, listener candidates, delegated candidates, a document's walk, frames, and
#: the elements whose shadow roots the closed-root census did not check (`_census`).
BUDGET_KINDS = ("elements", "candidates", "delegated", "nodes", "frames", "census")

#: One document's read. Its argument is ``[maxElements, maxCand, maxDelegated, maxNodes,
#: frameKey, frameLinks, actionTypes, delegateTypes]``. The last read's markers go first,
#: in every open shadow root (PA-0502(3)).
READ_JS = r"""
([maxElements, maxCand, maxDelegated, maxNodes, frameKey, frameLinks, actionTypes,
  delegateTypes]) => {""" + COMPOSED_JS + r"""
  const NATIVE = 'a[href],button,input,select,textarea,summary,[role=button],[role=link],'
    + '[role=menuitem],[role=tab],[role=checkbox],[role=combobox],[role=option],'
    + '[role=switch],[role=radio],[onclick],[contenteditable=true],[tabindex]:not([tabindex="-1"])';
  const CANDS = 'div,span,li,img,svg,td,p,i,section,article,label';
  const MARKS = ['data-disco-id', 'data-disco-cand', 'data-disco-frame'];
  const visible = (e) => {
    if (!e.isConnected) return false;
    const r = e.getClientRects();
    if (!r.length) return false;
    const s = getComputedStyle(e);
    return s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0';
  };
  const all = [];
  const deep = new Set();
  let nodes = 0, shadows = 0, shape = 2166136261;
  const tags = new Map();
  composedWalk(document, (e) => {
    nodes++;
    // the composed tree's shape (each element's tag and light child count, in walk
    // order): the closed-root census runs again only when it changed (`_census`)
    let t = tags.get(e.tagName);
    if (t === undefined) { t = tags.size + 1; tags.set(e.tagName, t); }
    shape = Math.imul(shape ^ (t * 64 + Math.min(e.childElementCount, 63)), 16777619) >>> 0;
    for (const m of MARKS) if (e.hasAttribute(m)) e.removeAttribute(m);
    if (all.length < maxNodes) all.push(e);
    if (e.shadowRoot) {
      shadows++;
      for (let x = e; x && !deep.has(x); x = composedParent(x)) deep.add(x);
    }
  });
  const out = [];
  const pre = frameKey ? frameKey + ':' : '';
  let n = 0;
  const cls = (e) => Array.from(e.classList || []).slice(0, 4).sort().join('.');
  const node = (e) => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (cls(e) ? '.' + cls(e) : '');
  // the short ancestor chain, then every shadow host above and the frames above
  // (`frameLinks`): an element's identity says which component and frame it is in
  const ancestry = (e) => {
    const chain = [];
    let a = e.parentElement;
    while (a && a !== document.body && chain.length < 3) { chain.push(node(a)); a = a.parentElement; }
    let root = e.getRootNode(), hosts = 0;
    while (root && root.host && hosts < 8) {
      chain.push('^shadow', node(root.host));
      root = root.host.getRootNode();
      hosts++;
    }
    return chain.concat(frameLinks).join('<');
  };
  const TYPED_ANY = 'input:not([type=hidden]):not([type=button]):not([type=submit])'
    + ':not([type=checkbox]):not([type=radio]),textarea,select';
  // a <form>, else the nearest ancestor holding typed inputs, else -- the walk reached the
  // top of a shadow tree -- that shadow root when it holds one: a widget whose input and
  // button sit directly under its root (Lit, Stencil) has no container element, and
  // `parentElement` ends there (BUG-0551 review B1). A root is no <form>: no action.
  const formLike = (e) => {
    if (e.form) return e.form;
    const f = e.closest('form'); if (f) return f;
    let a = e.parentElement, k = 0;
    while (a && a !== document.body && k < 6) {
      if (deepFind(deep, a, TYPED_ANY)) return a;
      a = a.parentElement; k++;
    }
    const root = e.getRootNode();
    if (!a && root.host && deepFind(deep, root, TYPED_ANY)) return root;
    return null;
  };
  // the control values that select a workflow (FR-CRAWL-31's markers, BUG-0539): a
  // select's value, a box's checked state, ARIA selection; never typed text
  const selState = (e) => {
    const tag = e.tagName.toLowerCase(), parts = [];
    if (tag === 'select') parts.push('value=' + String(e.value).slice(0, 64));
    if (tag === 'input' && (e.type === 'checkbox' || e.type === 'radio'))
      parts.push('checked=' + e.checked);
    for (const a of ['aria-selected', 'aria-current', 'aria-checked']) {
      const v = e.getAttribute(a);
      if (v !== null && v !== '' && v !== 'false') parts.push(a + '=' + String(v).slice(0, 32));
    }
    return parts.join(';');
  };
  window.__discoLayout = {cls, ancestry, formLike, selState};
  const TYPED = 'input:not([type=hidden]):not([type=button]):not([type=submit])'
    + ':not([type=checkbox]):not([type=radio]):not([type=reset]):not([type=image]),textarea';
  const described = [];
  const describe = (e, how) => {
    const id = pre + String(n++);
    e.setAttribute('data-disco-id', id);
    described.push(e);
    const form = formLike(e);
    const typed = form ? deepAll(deep, form, TYPED) : [];
    const label = (e.getAttribute('aria-label') || e.getAttribute('title') || e.innerText
                   || e.value || e.getAttribute('placeholder') || '').trim().slice(0, 80);
    const tag = e.tagName.toLowerCase();
    const type = (e.getAttribute('type') || (tag === 'button' ? 'submit' : '')).toLowerCase();
    out.push({disco_id: id, how, tag, role: e.getAttribute('role') || '', type,
              name: e.getAttribute('name') || '', id: e.id || '', cls: cls(e), ancestry: ancestry(e),
              href: tag === 'a' ? e.href : '', label,
              // a form-less container has no action: location.href put the route into
              // every signature inside it, so a toolbar was new on each route (BUG-0502)
              action: form && form.tagName === 'FORM' ? (form.action || location.href) : '',
              in_form: !!form, disabled: !!e.disabled, cursor: getComputedStyle(e).cursor,
              sel: selState(e),
              // the Enter rule (`enter_submits`): what the element's container holds
              form_tag: !!(form && form.tagName === 'FORM'), typed: typed.length,
              last_typed: typed.length > 0 && typed[typed.length - 1] === e,
              submitters: form ? deepAll(deep, form,
                'button:not([type=button]):not([type=reset]),input[type=submit],'
                + 'input[type=image]').length : 0});
  };
  let overElements = 0, overCand = 0, overDeleg = 0;
  for (const e of all) {
    if (!e.matches(NATIVE)) continue;
    // a disabled control is kept only as a submitter (filling its form enables it)
    if (!(visible(e) && (!e.disabled || (e.tagName === 'BUTTON' && formLike(e))))) continue;
    if (out.length >= maxElements) { overElements++; continue; }
    describe(e, 'native');
  }
  const cands = [];
  for (const e of all) {
    if (!e.matches(CANDS)) continue;
    if (e.hasAttribute('data-disco-id') || !visible(e)) continue;
    if (composedClosest(e, '[data-disco-id]')) continue;
    if (out.length + cands.length >= maxElements || cands.length >= maxCand) { overCand++; continue; }
    if (getComputedStyle(e).cursor === 'pointer'
        && !(e.parentElement && getComputedStyle(e.parentElement).cursor === 'pointer')) {
      describe(e, 'pointer');
      continue;
    }
    e.setAttribute('data-disco-cand', String(cands.length));
    cands.push(e);
  }
  // listener and delegated candidates: DevTools' Command Line API, when the read runs
  // through it, sees this realm's listeners
  const cli = typeof getEventListeners === 'function';
  const ACTION = new Set(actionTypes), DELEG = new Set(delegateTypes);
  const memo = new Map();
  const typesOf = (t) => {
    let v = memo.get(t);
    if (v === undefined) {
      v = [];
      try { v = Object.keys(getEventListeners(t) || {}); } catch (x) { v = []; }
      memo.set(t, v);
    }
    return v;
  };
  const listens = (t, set) => typesOf(t).some((x) => set.has(x));
  const lite = (e, how, id) => ({disco_id: id, how, tag: e.tagName.toLowerCase(),
    role: e.getAttribute('role') || '', type: '', name: '', id: e.id || '', cls: cls(e),
    ancestry: ancestry(e), href: '',
    label: (e.getAttribute('aria-label') || e.innerText || '').trim().slice(0, 80),
    action: '', in_form: !!e.closest('form'), cursor: getComputedStyle(e).cursor,
    sel: selState(e)});
  if (cli) {
    let k = 0;
    for (const e of cands) {
      const own = typesOf(e).filter((x) => ACTION.has(x)).sort();
      if (!own.length) continue;
      const id = pre + 'L' + String(k++);
      e.setAttribute('data-disco-id', id);
      described.push(e);
      const d = lite(e, 'listener', id);
      d.listeners = own;
      out.push(d);
    }
  }
  // an ancestor in the composed path (an element, a shadow root, the document, the
  // window) listens for a delegate type
  const delegating = (e) => {
    for (let x = e; ; ) {
      const p = x.parentNode;
      if (!p) return false;
      if (p.nodeType === 9) return listens(p, DELEG) || listens(window, DELEG);
      if (p.nodeType === 11) {
        if (!p.host) return false;
        if (listens(p, DELEG)) return true;
        x = p.host;
      } else {
        x = p;
      }
      if (listens(x, DELEG)) return true;
    }
  };
  if (cli && maxDelegated >= 0) {
    // every composed ancestor of a candidate or of a described element: a container is
    // not a delegated action (its click lands on what it holds)
    const holds = new Set();
    for (const e of cands.concat(described)) {
      for (let a = composedParent(e); a && !holds.has(a); a = composedParent(a)) holds.add(a);
    }
    const shapes = new Set();
    const viewport = innerWidth * innerHeight;
    let k = 0;
    for (const e of cands) {
      if (e.hasAttribute('data-disco-id') || holds.has(e)) continue;
      if (composedClosest(e, '[data-disco-id]')) continue;
      const tag = e.tagName.toLowerCase();
      if (!(e.innerText || '').trim() && !e.getAttribute('aria-label')
          && tag !== 'img' && tag !== 'svg' && tag !== 'i') continue;
      const r = e.getBoundingClientRect();
      if (r.width * r.height > 0.25 * viewport) continue;
      if (!delegating(e)) continue;
      const shape = tag + '|' + cls(e) + '|' + ancestry(e);
      if (shapes.has(shape)) continue;
      shapes.add(shape);
      if (k >= maxDelegated) { overDeleg++; continue; }
      const id = pre + 'D' + String(k++);
      e.setAttribute('data-disco-id', id);
      out.push(lite(e, 'delegated', id));
    }
  }
  // the document's page-level workflow markers (`fingerprint.workflow_markers`,
  // FR-CRAWL-31), across its composed tree: each named hidden input (at most 50, its
  // value cut at 65 characters: longer is no marker) and each aria-current element the
  // read did not describe itself (a stepper's position; at most 20 looked at). A
  // delegated candidate is no part of a state's identity (BUG-0551 R7), so its
  // aria-current is a page marker, as it was before it was a candidate.
  const own = new Set(described);
  const marks = [];
  let hiddenN = 0, currentN = 0;
  for (const e of all) {
    if (e.tagName === 'INPUT' && e.matches('input[type=hidden][name]')) {
      if (hiddenN++ < 50)
        marks.push(['hidden', e.getAttribute('name') || '', String(e.value || '').slice(0, 65)]);
      continue;
    }
    if (!e.matches('[aria-current]:not([aria-current="false"])') || currentN++ >= 20) continue;
    if (own.has(e)) continue;                   // a described element: its own `sel`
    const p = e.parentElement || e.parentNode;  // a shadow tree's top: its root's children
    const idx = p && p.children ? Array.from(p.children).indexOf(e) : 0;
    marks.push(['current', e.tagName.toLowerCase() + '<' + ancestry(e), idx,
                String(e.getAttribute('aria-current')).slice(0, 32)]);
  }
  const frames = [];
  let fk = 0;
  for (const f of all) {
    if (f.tagName !== 'IFRAME' && f.tagName !== 'FRAME') continue;
    const key = (frameKey ? frameKey + '.' : '') + String(++fk);
    f.setAttribute('data-disco-frame', key);
    let url = null, same = false;
    try {
      const w = f.contentWindow;
      if (w) {
        url = w.document.URL;
        same = w.origin === window.origin;
        if (same) w.__discoFrame = key;
      }
    } catch (x) { url = null; same = false; }
    frames.push({key, node: node(f), src: f.src || '', url, same, visible: visible(f)});
  }
  return {elements: out, marks, frames, shadow_roots: shadows, nodes, shape,
          cut: nodes > all.length, listeners: cli,
          over: {elements: overElements, candidates: overCand, delegated: overDeleg}};
}
"""

#: A submitter's form controls, each marked ``data-disco-field`` (`Explorer._fill`). The
#: markers of an earlier form go first, in every open shadow root of the document: a
#: stale ``data-disco-field="0"`` earlier in the document was filled in place of this
#: form's first control (BUG-0502), and a selector pierces open shadow roots.
FIELDS_JS = r"""
(e) => {""" + COMPOSED_JS + r"""
  composedWalk(e.ownerDocument, (c) => {
    if (c.hasAttribute('data-disco-field')) c.removeAttribute('data-disco-field');
  });
  const lay = window.__discoLayout;
  const form = (lay && lay.formLike(e)) || e.form || e.closest('form') || e.parentElement
    || e.getRootNode();
  const ctrls = composedAll(form, 'input,select,textarea');
  return ctrls.map((c, i) => {
    c.setAttribute('data-disco-field', String(i));
    const lab = (c.labels && c.labels[0] && c.labels[0].innerText) || '';
    return {field: String(i), tag: c.tagName.toLowerCase(), type: (c.getAttribute('type') || '').toLowerCase(),
            name: c.getAttribute('name') || '', id: c.id || '', label: lab.trim().slice(0, 80),
            aria_label: c.getAttribute('aria-label') || '', placeholder: c.getAttribute('placeholder') || '',
            autocomplete: c.getAttribute('autocomplete') || '', pattern: c.getAttribute('pattern') || '',
            min: c.getAttribute('min'), max: c.getAttribute('max'), step: c.getAttribute('step'),
            minlength: c.getAttribute('minlength'), maxlength: c.getAttribute('maxlength'),
            required: c.required, disabled: c.disabled, readonly: c.readOnly,
            value: c.type === 'password' ? '' : String(c.value || '').slice(0, 64),
            options: c.tagName === 'SELECT' ? Array.from(c.options).map(o => o.value) : []};
  });
}
"""


def _pw_error():
    """Playwright's error class (resolved lazily: importing this module needs no browser
    extra). The one external failure a read maps to "not done" (PA-0106)."""
    from playwright.sync_api import Error
    return Error


def frame_scope(page, keys):
    """What locates an element of the frame ``keys`` names (the page's own document for
    none): a frame locator per frame marker, from the page down."""
    scope = page
    for key in keys or ():
        scope = scope.frame_locator(f'[data-disco-frame="{key}"]')
    return scope


def classify_frame(info: dict, in_scope) -> str | None:
    """Whether a frame is read (``"read"``), and if not, why: ``"out_of_scope"`` (its
    ``src`` or its document is outside the scope) or ``"cross_origin"`` (its document is
    not same-origin with the page holding it, so no script of ours may read it). A frame
    that is not visible shows nothing: None, neither read nor counted."""
    if not info.get("visible"):
        return None
    for url in (info.get("src"), info.get("url")):
        if url and urlsplit(url).scheme in ("http", "https") and not in_scope(url):
            return "out_of_scope"
    if not info.get("same"):
        return "cross_origin"
    return "read"


def _frame_path(url: str | None) -> str:
    """The path that names a frame's document in an ancestry (``about:srcdoc`` is
    ``srcdoc``)."""
    parts = urlsplit(url or "")
    return parts.path or (url or "")


@dataclass
class PageRead:
    """One read: its elements (each with ``frame``), its documents' page-level workflow
    markers (``marks``: `fingerprint.workflow_markers`' ``page_marks``, the page's own
    document first), and what it noted for the report: ``counts`` (kind -> its number in
    this read: ``shadow_roots``, and ``budget.<bound>`` for what a bound left out) and
    ``distinct`` (kind -> the keys it saw)."""
    elements: list = field(default_factory=list)
    marks: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    distinct: dict = field(default_factory=dict)

    def count(self, kind: str, n: int) -> None:
        if n:
            self.counts[kind] = self.counts.get(kind, 0) + n

    def one(self, kind: str, key: str) -> None:
        self.distinct.setdefault(kind, set()).add(key)


class Reader:
    """Runs a read in one document of a page: the page's own, or a frame's by its marker
    key. Through DevTools when the browser has it (``Runtime.evaluate`` with the Command
    Line API, in the frame's main-world context), else through Playwright."""

    def __init__(self, page, ctx):
        self.page = page
        self.cdp = None
        self._contexts: list[dict] = []
        self._keys: dict[str, int] = {}
        self._enabled = False
        try:
            self.cdp = ctx.new_cdp_session(page)
        except _pw_error():   # a browser without DevTools: Playwright, no listeners
            self.cdp = None

    def close(self) -> None:
        if self.cdp is not None:
            try:
                self.cdp.detach()
            except _pw_error():  # the page may have gone already
                pass

    def run(self, key: str, script: str, arg):
        """``script(arg)`` in the document ``key`` names; None when that frame is gone."""
        if self.cdp is None:
            frame = self._frame(key)
            return None if frame is None else frame.evaluate(script, arg)
        params = {"expression": f"({script})({json.dumps(arg)})",
                  "includeCommandLineAPI": True, "returnByValue": True}
        if key:
            context = self._context(key)
            if context is None:
                return None
            params["contextId"] = context
        got = self.cdp.send("Runtime.evaluate", params)
        if got.get("exceptionDetails"):     # as page.evaluate raises it
            details = got["exceptionDetails"]
            text = (details.get("exception") or {}).get("description") or details.get("text")
            raise _pw_error()(f"disco read: {text}")
        return (got.get("result") or {}).get("value")

    def _frame(self, key: str):
        if not key:
            return self.page.main_frame
        for frame in self.page.frames:
            if frame is self.page.main_frame:
                continue
            try:
                if frame.evaluate("() => window.__discoFrame || null") == key:
                    return frame
            except _pw_error():  # a frame detached under the read
                continue
        return None

    def _context(self, key: str) -> int | None:
        """The main-world context of the frame whose window carries ``key`` (written by
        its parent's read). Contexts are listed once (``Runtime.enable`` replays every
        existing one, measured); an unknown key re-asks the contexts not mapped yet."""
        if not self._enabled:
            self.cdp.on("Runtime.executionContextCreated",
                        lambda ev: self._contexts.append(ev.get("context") or {}))
            self.cdp.send("Runtime.enable")
            self._enabled = True
        if key not in self._keys:
            mapped = set(self._keys.values())
            for ctx in list(self._contexts):
                cid = ctx.get("id")
                if cid in mapped or not (ctx.get("auxData") or {}).get("isDefault"):
                    continue
                try:
                    got = self.cdp.send("Runtime.evaluate", {
                        "expression": "window.__discoFrame || null", "contextId": cid,
                        "returnByValue": True})
                except _pw_error():  # a context destroyed since
                    continue
                value = (got.get("result") or {}).get("value")
                if value:
                    self._keys[value] = cid
        return self._keys.get(key)

    def closed_hosts(self) -> list[tuple[str, str]] | None:
        """Every element of the page hosting a closed shadow root, as (the frame key of
        its document -- ``""`` for the page's own --, its ``tag#id.class``): one
        ``DOM.getDocument`` of the whole tree, every shadow root (closed ones included)
        and every in-process frame document pierced. A frame's document carries the key
        its parent's read wrote on the frame element (``data-disco-frame``); one with no
        key was not read and is left out. None without DevTools."""
        if self.cdp is None:
            return None
        root = self.cdp.send("DOM.getDocument", {"depth": -1, "pierce": True}).get("root") or {}
        out: list[tuple[str, str]] = []
        stack = [(root, "")]
        while stack:
            node, key = stack.pop()
            roots = node.get("shadowRoots") or []
            if any(r.get("shadowRootType") == "closed" for r in roots):
                out.append((key, _node_desc(node)))
            stack.extend((r, key) for r in roots)
            stack.extend((c, key) for c in node.get("children") or [])
            doc = node.get("contentDocument")
            frame = _attributes(node).get("data-disco-frame")
            if doc is not None and frame:
                stack.append((doc, frame))
        return out


def _attributes(node: dict) -> dict[str, str]:
    """A DevTools node's attributes (a flat ``[name, value, ...]`` list) as a dict."""
    flat = node.get("attributes") or []
    return dict(zip(flat[0::2], flat[1::2]))


def _node_desc(node: dict) -> str:
    """``tag#id.class`` of a DevTools element node, as `READ_JS`'s ``node`` writes it:
    its first four class tokens, sorted."""
    attrs = _attributes(node)
    classes = list(dict.fromkeys((attrs.get("class") or "").split()))[:4]
    out = (node.get("localName") or node.get("nodeName") or "").lower()
    if attrs.get("id"):
        out += "#" + attrs["id"]
    if classes:
        out += "." + ".".join(sorted(classes))
    return out


def read_page(page, ctx, in_scope, *, max_delegated: int = MAX_DELEGATED,
              censused: set | None = None) -> PageRead:
    """The page's composed read (module doc). The page's own document first, then each
    frame it reads, breadth first; elements in that order. ``censused`` (the run's)
    holds the page shapes whose closed roots were already counted: an unchanged page
    is not checked again (`_census`)."""
    reader = Reader(page, ctx)
    try:
        return _read(reader, in_scope, max_delegated, censused)
    finally:
        reader.close()


def _read(reader: Reader, in_scope, max_delegated: int, censused: set | None) -> PageRead:
    read = PageRead()
    queue: list[tuple[str, list, list]] = [("", [], [])]
    room, deleg, frames = MAX_ELEMENTS, max_delegated, 0
    #: each document read: its frame key -> (its frame links, its elements, its shape)
    docs: dict[str, tuple[list, int, int]] = {}
    while queue:
        key, path, links = queue.pop(0)
        arg = [room, MAX_CDP_CANDIDATES, deleg, MAX_NODES, key, links,
               list(ACTION_LISTENERS), list(DELEGATE_LISTENERS)]
        if not key:
            got = reader.run(key, READ_JS, arg)    # the page's own: a failure is the read's
        else:
            try:
                got = reader.run(key, READ_JS, arg)
            except _pw_error():      # a frame navigating under the read: not read this time
                got = None
        if got is None:                      # the frame went away under the read
            if key:
                read.count("budget.frames", 1)
            continue
        for el in got["elements"]:
            el["frame"] = list(path)
            read.elements.append(el)
        read.marks.extend(got.get("marks") or [])
        room = max(0, room - len(got["elements"]))
        deleg = max(0, deleg - sum(1 for el in got["elements"] if el["how"] == "delegated"))
        read.count("shadow_roots", got["shadow_roots"])
        for bound, n in (got.get("over") or {}).items():
            read.count(f"budget.{bound}", n)
        if got.get("cut"):
            read.count("budget.nodes", got["nodes"] - MAX_NODES)
        docs[key] = (links, int(got.get("nodes") or 0), int(got.get("shape") or 0))
        for info in got["frames"]:
            verdict = classify_frame(info, in_scope)
            if verdict is None:
                continue
            here = ["^frame", info["node"], "@" + _frame_path(info.get("url")), *links]
            if verdict != "read":
                read.one(f"frames_{verdict}", info.get("src") or "<".join(here))
                continue
            if len(path) >= MAX_FRAME_DEPTH or frames >= MAX_FRAMES:
                read.count("budget.frames", 1)
                continue
            frames += 1
            read.one("frames", "<".join(here))
            queue.append((info["key"], [*path, info["key"]], here))
    _census(reader, read, docs, censused)
    return read


def _census(reader: Reader, read: PageRead, docs: dict, censused: set | None) -> None:
    """Count the closed shadow roots of the documents read (`Reader.closed_hosts`), each
    once per route by its host and frames (``closed_shadow_roots``).

    Bounded, and never claimed: a page whose documents read hold more than `MAX_NODES`
    elements is not checked, nor is one read without DevTools or whose check failed (it
    navigated under it); their elements are counted ``budget.census``. One full
    ``DOM.getDocument`` costs about 25 us per node (measured: 230 ms for 6 000
    elements, 1.3-1.9 s for 24 000-30 000), so a page whose route and documents' shapes
    were already checked this run (``censused``) is not checked again."""
    total = sum(n for _links, n, _shape in docs.values())
    key = (normalise_route(reader.page.url),
           tuple(sorted((k, n, shape) for k, (_links, n, shape) in docs.items())))
    if censused is not None and key in censused:
        return
    hosts = None
    if total <= MAX_NODES:
        try:
            hosts = reader.closed_hosts()
        except _pw_error():          # the page navigated under the check: not checked
            hosts = None
    if hosts is None:
        read.count("budget.census", total)
        return
    for frame, desc in hosts:
        if frame in docs:
            read.one("closed_shadow_roots", "<".join([desc, *docs[frame][0]]))
    if censused is not None:
        censused.add(key)


class Coverage:
    """What the run's reads noted, aggregated so that a page read again adds nothing:
    a kind counted per read keeps its largest count per route; a kind of keys counts
    each key once per route. `add` returns the increase per kind (for the live report)."""

    def __init__(self):
        self._max: dict[tuple[str, str], int] = {}
        self._seen: set[tuple[str, str, str]] = set()

    def add(self, route: str, read: PageRead) -> dict[str, int]:
        delta: dict[str, int] = {}
        for kind, n in read.counts.items():
            prev = self._max.get((kind, route), 0)
            if n > prev:
                self._max[(kind, route)] = n
                delta[kind] = delta.get(kind, 0) + n - prev
        for kind, keys in read.distinct.items():
            for key in keys:
                if (kind, route, key) not in self._seen:
                    self._seen.add((kind, route, key))
                    delta[kind] = delta.get(kind, 0) + 1
        return delta


class Trials:
    """Delegated candidates' verdicts, one per element signature for the whole run: a
    candidate is tried once (``claim``), and is ``live`` when its click made a request
    or changed the state, else ``inert``. At most ``budget`` trials start; a candidate
    still untried after that is ``unexplored`` (counted, never acted on)."""

    def __init__(self, budget: int = MAX_DELEGATED_TRIALS):
        self.budget = budget
        self.verdicts: dict[str, str] = {}
        self.started = 0
        self.unexplored: set[str] = set()

    def verdict(self, sig: str) -> str | None:
        """``live``, ``inert``, ``trying``, or None (untried)."""
        return self.verdicts.get(sig)

    def spent(self) -> bool:
        return self.started >= self.budget

    def claim(self, sig: str) -> str:
        """``live`` (act on it), ``trial`` (this caller tries it now), or why not:
        ``inert``, ``trying`` (another worker is trying it) or ``spent``."""
        got = self.verdicts.get(sig)
        if got is not None:
            return got
        if self.spent():
            self.unexplored.add(sig)
            return "spent"
        self.verdicts[sig] = "trying"
        self.started += 1
        return "trial"

    def decide(self, sig: str, live: bool) -> None:
        self.verdicts[sig] = "live" if live else "inert"

    def release(self, sig: str) -> None:
        """A trial that never clicked (its element gone, its page gone): untried again,
        and its budget back."""
        if self.verdicts.get(sig) == "trying":
            del self.verdicts[sig]
            self.started -= 1
