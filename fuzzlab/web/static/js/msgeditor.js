// Shared HTTP message editor (U3 / CC-UI-0030 · CC-PROXY-0018, R-04 resolved).
//
// One `<message-editor>` custom element per message — Request (editable) or
// Response (read-only) — used by both Intercept and Repeater (and History's
// read-only flow detail). API: `{editable, bytes, meta}` in as properties,
// `getBytes()` out.
//
// Hard constraints carried over from the resolved R-04 marker in
// docs/UI_IMPLEMENTATION_PLAN.md — do not relax these without re-opening it:
//  - The editable pane is a plain <textarea>; its `.value` is the single
//    byte-exact source of truth. `getBytes()` reads *only* that textarea.
//  - `contenteditable` and the CSS Custom Highlight API can't target a
//    textarea's internal text, so Pretty rendering and Ctrl-F search both
//    paint into a separate, read-only mirror `<pre>` — never by span-injecting
//    the textarea's own content.
//  - Raw is the only editable mode, and the default mode. Pretty/Hex are
//    always read-only views derived from the current bytes.
//  - No vendored highlighting/editor library — hand-rolled tokenizer + DOM.
//  - Light DOM only (no shadow root): section CSS applies directly, and
//    callers can pin ids via `textarea-id` / `mirror-id` for tests and
//    automation that need a stable element to target.
//
// The CRLF toggle only changes *display* (control bytes rendered as visible
// glyphs); it never mutates the underlying bytes. `toWire()` in common.js
// remains the single documented `\n` -> `\r\n` restoration point applied right
// before a byte-exact send — msgeditor.js does not duplicate that logic.

const HIGHLIGHT_NAME = "msgeditor-search";
const HAS_HIGHLIGHT_API = typeof CSS !== "undefined" && "highlights" in CSS && typeof Highlight === "function";

/** Render control bytes as visible glyphs for display only — never mutates `s`. */
function withGlyphs(s) {
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === "\n") out += "␤\n";        // NL pictogram, then the real break
    else if (ch === "\r") out += "␍";      // CR pictogram
    else if (ch === "\t") out += "␉\t";    // TAB pictogram, then the real tab
    else if (c < 0x20) out += String.fromCodePoint(0x2400 + c);
    else out += ch;
  }
  return out;
}

/** Split raw HTTP bytes into {startLine, headers:[[name,rest]], sep, body}. */
function parseMessage(bytes) {
  const idx = bytes.indexOf("\n\n") !== -1 && bytes.indexOf("\r\n\r\n") === -1
    ? bytes.indexOf("\n\n") + 2
    : (bytes.indexOf("\r\n\r\n") !== -1 ? bytes.indexOf("\r\n\r\n") + 4 : -1);
  const head = idx === -1 ? bytes : bytes.slice(0, idx);
  const body = idx === -1 ? "" : bytes.slice(idx);
  const lines = head.split(/\r\n|\n/).filter((_, i, a) => !(i === a.length - 1 && a[i] === ""));
  const startLine = lines.shift() || "";
  const headers = [];
  for (const line of lines) {
    const m = /^([^:]+):\s?(.*)$/.exec(line);
    if (m) headers.push([m[1], m[2]]);
    else if (line) headers.push([line, ""]);
  }
  return { startLine, headers, body };
}

function prettyBody(body, headers) {
  const ct = (headers.find((h) => h[0].toLowerCase() === "content-type") || ["", ""])[1];
  if (/json/i.test(ct)) {
    try { return JSON.stringify(JSON.parse(body), null, 2); } catch (_) { /* not JSON, fall through */ }
  }
  return body;
}

/** Build the read-only "Pretty" tree into `pre` using only createElement/textContent. */
function renderPretty(pre, bytes, { crlf }) {
  pre.replaceChildren();
  const { startLine, headers, body } = parseMessage(bytes);
  const disp = (s) => (crlf ? withGlyphs(s) : s);
  const startEl = document.createElement("div");
  startEl.className = "me-startline";
  startEl.textContent = disp(startLine);
  pre.appendChild(startEl);
  for (const [name, val] of headers) {
    const row = document.createElement("div");
    row.className = "me-hdr";
    const n = document.createElement("span");
    n.className = "me-hdr-name"; n.textContent = disp(name);
    const v = document.createElement("span");
    v.className = "me-hdr-val"; v.textContent = ": " + disp(val);
    row.append(n, v);
    pre.appendChild(row);
  }
  const blank = document.createElement("div");
  blank.className = "me-blank";
  pre.appendChild(blank);
  if (body) {
    const bodyEl = document.createElement("div");
    bodyEl.className = "me-body-text";
    bodyEl.textContent = disp(prettyBody(body, headers));
    pre.appendChild(bodyEl);
  }
}

/** Read-only "Raw" mirror — plain text, one node, so search/highlighting is simple. */
function renderRawMirror(pre, bytes, { crlf }) {
  pre.replaceChildren();
  pre.textContent = crlf ? withGlyphs(bytes) : bytes;
}

function renderHex(pre, bytes) {
  pre.replaceChildren();
  const buf = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hex = [];
    let asc = "";
    for (let i = 0; i < chunk.length; i++) {
      const c = chunk.codePointAt(i) & 0xff;
      hex.push(c.toString(16).padStart(2, "0"));
      asc += c >= 0x20 && c < 0x7f ? chunk[i] : ".";
    }
    buf.push(
      off.toString(16).padStart(8, "0") + "  " +
      hex.join(" ").padEnd(16 * 3 - 1, " ") + "  " + asc,
    );
  }
  pre.textContent = buf.join("\n");
}

/** Clear/paint CSS Custom Highlight ranges over a read-only mirror's text nodes. */
function paintSearch(mirror, query) {
  if (!HAS_HIGHLIGHT_API) return 0;
  CSS.highlights.delete(HIGHLIGHT_NAME);
  if (!query) return 0;
  const walker = document.createTreeWalker(mirror, NodeFilter.SHOW_TEXT);
  const q = query.toLowerCase();
  const ranges = [];
  let node;
  while ((node = walker.nextNode())) {
    const text = node.textContent.toLowerCase();
    let at = 0;
    while ((at = text.indexOf(q, at)) !== -1) {
      const r = new Range();
      r.setStart(node, at);
      r.setEnd(node, at + q.length);
      ranges.push(r);
      at += q.length;
    }
  }
  if (ranges.length) CSS.highlights.set(HIGHLIGHT_NAME, new Highlight(...ranges));
  return ranges.length;
}

export class MessageEditor extends HTMLElement {
  connectedCallback() {
    if (this._built) return;
    this._built = true;
    this._mode = "raw";          // "raw" | "pretty" | "hex" (hex only when !editable)
    this._crlf = false;
    this._meta = {};
    this._build();
    if (this._pendingBytes != null) this._setRaw(this._pendingBytes);
  }

  get editable() { return this.hasAttribute("editable"); }
  set editable(v) { this.toggleAttribute("editable", !!v); }

  get bytes() { return this._ta ? this._ta.value : (this._pendingBytes || ""); }
  set bytes(v) {
    if (!this._built) { this._pendingBytes = v; return; }
    this._setRaw(v == null ? "" : String(v));
  }

  get meta() { return this._meta; }
  set meta(m) {
    this._meta = m || {};
    if (this._built) this._renderStat();
  }

  /** The one documented way to read byte-exact content back out. */
  getBytes() { return this._ta.value; }

  _setRaw(v) {
    if (this._ta.value !== v) this._ta.value = v;
    this._refreshView();
  }

  _build() {
    const editable = this.editable;
    const taId = this.getAttribute("textarea-id");
    const mirrorId = this.getAttribute("mirror-id");

    this.classList.add("msgeditor");

    const toolbar = document.createElement("div");
    toolbar.className = "me-toolbar";

    const modes = document.createElement("div");
    modes.className = "me-modes";
    modes.setAttribute("role", "tablist");
    const rawBtn = this._modeBtn("Raw", "raw");
    const prettyBtn = this._modeBtn("Pretty", "pretty");
    modes.append(rawBtn, prettyBtn);
    if (!editable) modes.append(this._modeBtn("Hex", "hex"));

    const crlfBtn = document.createElement("button");
    crlfBtn.type = "button"; crlfBtn.className = "me-crlf tbtn";
    crlfBtn.textContent = "CRLF ␤";
    crlfBtn.setAttribute("aria-pressed", "false");
    crlfBtn.title = "Show CR/LF and non-printing bytes as glyphs (display only)";
    crlfBtn.addEventListener("click", () => {
      this._crlf = !this._crlf;
      crlfBtn.setAttribute("aria-pressed", String(this._crlf));
      this._refreshView();
    });

    const searchBtn = document.createElement("button");
    searchBtn.type = "button"; searchBtn.className = "me-search-toggle tbtn";
    searchBtn.textContent = "⌕ Find";
    searchBtn.title = "Search this message (Ctrl/Cmd-F)";
    searchBtn.addEventListener("click", () => this._toggleSearch());

    toolbar.append(modes, crlfBtn, searchBtn);

    const stat = document.createElement("div");
    stat.className = "me-stat";

    const search = document.createElement("div");
    search.className = "me-searchbar"; search.hidden = true;
    const sInput = document.createElement("input");
    sInput.type = "search"; sInput.placeholder = "find in message…";
    sInput.setAttribute("aria-label", "Search this message");
    const sCount = document.createElement("span");
    sCount.className = "me-search-count muted";
    const sClose = document.createElement("button");
    sClose.type = "button"; sClose.textContent = "✕"; sClose.className = "tbtn";
    sClose.setAttribute("aria-label", "Close search");
    sClose.addEventListener("click", () => this._toggleSearch(false));
    sInput.addEventListener("input", () => this._runSearch(sInput.value));
    search.append(sInput, sCount, sClose);
    this._searchInput = sInput; this._searchCount = sCount;

    const body = document.createElement("div");
    body.className = "me-body";

    const ta = document.createElement("textarea");
    ta.className = "me-raw"; ta.spellcheck = false;
    ta.wrap = "off";
    if (taId) ta.id = taId;
    if (!editable) { ta.readOnly = true; ta.tabIndex = -1; ta.hidden = true; ta.setAttribute("aria-hidden", "true"); }
    ta.addEventListener("input", () => { if (this._mode !== "raw") this._refreshView(); });

    const mirror = document.createElement("pre");
    mirror.className = "me-mirror";
    // Editable case: the mirror is a decorative overlay (textarea is the real
    // content). Read-only case: the mirror *is* the content in every mode,
    // including Raw — a read-only <textarea> has no accessible innerText, so
    // callers (and tests) read the response back from this <pre> instead.
    mirror.setAttribute("aria-hidden", editable ? "true" : "false");
    if (mirrorId) mirror.id = mirrorId;
    mirror.hidden = editable;   // read-only editors show the mirror from the start
    mirror.tabIndex = 0;

    body.append(ta, mirror);

    this.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
        e.preventDefault();
        this._toggleSearch(true);
      } else if (e.key === "Escape" && !search.hidden) {
        this._toggleSearch(false);
      }
    });

    this.replaceChildren(toolbar, stat, search, body);
    this._ta = ta; this._mirror = mirror; this._stat = stat;
    this._modeButtons = { raw: rawBtn, pretty: prettyBtn, hex: modes.querySelector('[data-mode="hex"]') };
    this._setMode("raw");
    this._renderStat();
  }

  _modeBtn(label, mode) {
    const b = document.createElement("button");
    b.type = "button"; b.className = "me-mode tbtn";
    b.textContent = label; b.dataset.mode = mode;
    b.setAttribute("role", "tab");
    b.addEventListener("click", () => this._setMode(mode));
    return b;
  }

  _setMode(mode) {
    this._mode = mode;
    for (const [m, btn] of Object.entries(this._modeButtons)) {
      if (!btn) continue;
      btn.setAttribute("aria-selected", String(m === mode));
      btn.classList.toggle("active", m === mode);
    }
    this._refreshView();
  }

  _refreshView() {
    const bytes = this._ta.value;
    if (this.editable && this._mode === "raw" && !this._searching) {
      // Raw is the only editable view; CRLF display there would defeat byte-exact
      // editing, so the glyph toggle only affects the read-only mirror views.
      this._ta.hidden = false;
      this._mirror.hidden = true;
    } else if (this.editable && this._mode === "raw" && this._searching) {
      this._ta.hidden = true;
      this._mirror.hidden = false;
      renderRawMirror(this._mirror, bytes, { crlf: this._crlf });
    } else {
      // Read-only editors always render through the mirror, in every mode
      // (including Raw) — see the aria-hidden/hidden comment in `_build`.
      this._ta.hidden = true;
      this._mirror.hidden = false;
      if (this._mode === "pretty") renderPretty(this._mirror, bytes, { crlf: this._crlf });
      else if (this._mode === "hex") renderHex(this._mirror, bytes);
      else renderRawMirror(this._mirror, bytes, { crlf: this._crlf });
    }
    if (this._searchInput && this._searchInput.value) this._runSearch(this._searchInput.value);
  }

  _renderStat() {
    const m = this._meta || {};
    const parts = [];
    if (m.status != null) parts.push(`${m.status}${m.reason ? " " + m.reason : ""}`);
    if (m.elapsed_ms != null) parts.push(`${m.elapsed_ms} ms`);
    if (m.byte_length != null) parts.push(`${m.byte_length} B`);
    else if (this._ta) parts.push(`${this._ta.value.length} B`);
    if (m.content_type) parts.push(m.content_type);
    if (m.label) parts.unshift(m.label);
    this._stat.textContent = parts.join(" · ");
    this._stat.hidden = parts.length === 0;
  }

  _toggleSearch(force) {
    const bar = this.querySelector(".me-searchbar");
    const show = force == null ? bar.hidden : force;
    bar.hidden = !show;
    this._searching = show;
    if (show) {
      this._searchInput.focus();
      this._runSearch(this._searchInput.value);
    } else {
      paintSearch(this._mirror, "");
      this._refreshView();   // restore the editable textarea if Raw was overlaid
    }
  }

  _runSearch(q) {
    // Highlight ranges can't target a <textarea>'s internal text (R-04), so
    // search always paints into the read-only mirror: for a read-only editor
    // that mirror is already the visible content in every mode; for an
    // editable one in Raw mode, show a synced read-only overlay of the same
    // bytes just for the duration of the search — the textarea underneath is
    // never touched and stays the source of truth `getBytes()` reads.
    if (this.editable && this._mode === "raw") {
      this._ta.hidden = true;
      this._mirror.hidden = false;
      renderRawMirror(this._mirror, this._ta.value, { crlf: this._crlf });
    }
    const n = paintSearch(this._mirror, q);
    this._searchCount.textContent = q ? `${n} match${n === 1 ? "" : "es"}` : "";
  }
}

if (!customElements.get("message-editor")) customElements.define("message-editor", MessageEditor);

// --- vanilla resizable splitter (no library) -----------------------------
//
// `container` must be `display: grid` with two panes and a handle already in
// its markup; this only wires the drag behavior and writes a `--a` custom
// property (px) the container's own CSS uses for the first track, e.g.
//   .me-split { grid-template-columns: var(--a, 50%) 6px 1fr; }
//   .me-split.vertical { grid-template-rows: var(--a, 50%) 6px 1fr; grid-template-columns: 1fr; }
export function attachSplitter(container, { handleSelector = ".me-split-handle", vertical = false, storageKey } = {}) {
  const handle = container.querySelector(handleSelector);
  if (!handle) return;
  handle.setAttribute("role", "separator");
  handle.setAttribute("aria-orientation", vertical ? "horizontal" : "vertical");
  handle.tabIndex = 0;

  const axis = () => (container.classList.contains("vertical") ? "row" : "column");
  const sizePx = () => (axis() === "row" ? container.clientHeight : container.clientWidth);

  function apply(px) {
    const max = Math.max(40, sizePx() - 46);
    const clamped = Math.min(Math.max(px, 40), max);
    container.style.setProperty("--a", clamped + "px");
    if (storageKey) {
      try { localStorage.setItem(storageKey, String(clamped)); } catch (_) { /* private mode etc. */ }
    }
  }

  if (storageKey) {
    try {
      const saved = localStorage.getItem(storageKey);
      if (saved) container.style.setProperty("--a", saved + "px");
    } catch (_) { /* ignore */ }
  }

  let dragging = false;
  handle.addEventListener("pointerdown", (e) => {
    dragging = true;
    handle.setPointerCapture(e.pointerId);
  });
  handle.addEventListener("pointermove", (e) => {
    if (!dragging) return;
    const rect = container.getBoundingClientRect();
    const pos = axis() === "row" ? e.clientY - rect.top : e.clientX - rect.left;
    apply(pos);
  });
  function end(e) { dragging = false; try { handle.releasePointerCapture(e.pointerId); } catch (_) { /* noop */ } }
  handle.addEventListener("pointerup", end);
  handle.addEventListener("pointercancel", end);
  handle.addEventListener("lostpointercapture", () => { dragging = false; });

  handle.addEventListener("keydown", (e) => {
    const step = 24;
    const cur = parseFloat(getComputedStyle(container).getPropertyValue("--a")) || sizePx() / 2;
    if (e.key === "ArrowLeft" || e.key === "ArrowUp") { apply(cur - step); e.preventDefault(); }
    else if (e.key === "ArrowRight" || e.key === "ArrowDown") { apply(cur + step); e.preventDefault(); }
  });
}
