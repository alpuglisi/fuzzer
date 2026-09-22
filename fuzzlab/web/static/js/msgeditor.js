// fuzzlab control panel — shared HTTP message editor (U3: proxy workbench rebuild).
//
// One reusable component: `<message-editor>` (a custom element defined here) renders
// ONE message (a request or a response) with Raw | Pretty tabs (+ read-only Hex when
// the pane itself is read-only), a status/timing strip, an in-message Ctrl-F search,
// and a CRLF/non-printing-char display toggle. Intercept uses a single instance (the
// held message, always editable); Repeater and the History detail view use two
// instances side by side (request editable, response read-only) joined by the
// `attachSplitter` helper this module also exports.
//
// Contract (kept stable — two views in this lane consume it directly):
//   el.editable = true|false   // settable any time; response panes never set this
//   el.bytes    = "<latin-1 text>"   // the logical byte content, as decoded text
//   el.meta     = {status, reason, ms} | null   // timing/status overlay (optional)
//   el.getBytes() -> string    // current bytes: the live <textarea>.value for an
//                               // editable pane (the byte-exact source of truth),
//                               // or the stored `bytes` for a read-only one.
//
// Byte-exactness: `bytes` is expected to already be a 1:1 decode of raw bytes (the
// backend uses latin-1, which is lossless for arbitrary octets — see proxy.js). This
// module never re-encodes or normalizes that text; `getBytes()` only ever reads the
// textarea's `.value` back out. The one documented newline transform (`\n` -> `\r\n`
// on send) stays in `toWire` (js/http.js) — callers apply it at the send/forward call
// site, never inside this component (single documented transform point, per the U3
// plan). Raw is the only editable view; Pretty and Hex are display-only derivations
// that are recomputed from `bytes`/the textarea on each render and never written back.
//
// No vendored editor/highlighting library (v1 scope, R-04): the editable surface stays
// a plain monospace <textarea>. Ctrl-F search paints matches with the CSS Custom
// Highlight API (`Highlight` + `CSS.highlights`) over Ranges in a read-only <pre>
// mirror — never by injecting <span> markup into the live editable buffer. When the
// active pane is the editable one, opening search swaps the visible surface to a
// read-only mirror of the current textarea value (search view only; the textarea and
// its `.value` are untouched and reappear when search closes).

const HL_MATCH = "me-match";
const HL_CURRENT = "me-current";
let _meUid = 0;

function h(tag, props, children) {
  const el = document.createElement(tag);
  if (props) for (const [k, v] of Object.entries(props)) {
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("data-")) {
      // el["data-tab"] would set a plain JS property, not the attribute .dataset
      // reads — a real HTML data-* attribute needs either setAttribute or .dataset.
      el.dataset[k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = v;
    } else if (k.startsWith("aria-") || k === "role" || k === "tabindex" || k === "title"
             || k === "type" || k === "placeholder") el.setAttribute(k, v);
    else el[k] = v;
  }
  for (const c of children || []) if (c) el.appendChild(c);
  return el;
}

// --- pretty-print (view-only; never round-trips) ---------------------------
function splitHeadBody(raw) {
  const sep = raw.indexOf("\r\n\r\n");
  const sep2 = raw.indexOf("\n\n");
  let at = -1, len = 0;
  if (sep >= 0 && (sep2 < 0 || sep <= sep2)) { at = sep; len = 4; }
  else if (sep2 >= 0) { at = sep2; len = 2; }
  if (at < 0) return { head: raw, body: "" };
  return { head: raw.slice(0, at), body: raw.slice(at + len) };
}

function parseHead(head) {
  const lines = head.split(/\r\n|\n/);
  const startLine = lines[0] || "";
  const headers = [];
  for (const line of lines.slice(1)) {
    const c = line.indexOf(":");
    if (c < 0) { if (line) headers.push([line, ""]); continue; }
    headers.push([line.slice(0, c).trim(), line.slice(c + 1).trim()]);
  }
  return { startLine, headers };
}

function findHeader(headers, name) {
  const low = name.toLowerCase();
  for (const [k, v] of headers) if (k.toLowerCase() === low) return v;
  return "";
}

function prettyBody(body, contentType) {
  const ct = (contentType || "").toLowerCase();
  if (ct.includes("json") && body.trim()) {
    try { return JSON.stringify(JSON.parse(body), null, 2); } catch (_) { /* fall through */ }
  }
  if (ct.includes("x-www-form-urlencoded") && body.trim()) {
    try {
      return body.split("&").filter(Boolean).map((pair) => {
        const [k, v = ""] = pair.split("=");
        return `${decodeURIComponent(k.replace(/\+/g, " "))} = ${decodeURIComponent(v.replace(/\+/g, " "))}`;
      }).join("\n");
    } catch (_) { /* malformed encoding — show raw */ }
  }
  return body;
}

function renderPretty(container, raw) {
  container.replaceChildren();
  const { head, body } = splitHeadBody(raw);
  const { startLine, headers } = parseHead(head);
  container.appendChild(h("div", { class: "me-pretty-start", text: startLine }));
  const table = h("table", { class: "me-pretty-headers" });
  const tbody = h("tbody");
  for (const [k, v] of headers) {
    tbody.appendChild(h("tr", null, [
      h("th", { text: k }),
      h("td", { text: v }),
    ]));
  }
  table.appendChild(tbody);
  container.appendChild(table);
  if (body) {
    const ct = findHeader(headers, "content-type");
    container.appendChild(h("h4", { text: "Body" }));
    container.appendChild(h("pre", { class: "me-pretty-body", text: prettyBody(body, ct) }));
  }
}

// --- hex dump (read-only pane only) -----------------------------------------
function hexDump(raw) {
  const lines = [];
  for (let off = 0; off < raw.length; off += 16) {
    const chunk = raw.slice(off, off + 16);
    let hex = "", asc = "";
    for (let i = 0; i < 16; i++) {
      if (i < chunk.length) {
        const code = chunk.charCodeAt(i) & 0xff;
        hex += code.toString(16).padStart(2, "0") + " ";
        asc += (code >= 32 && code < 127) ? chunk[i] : ".";
      } else {
        hex += "   ";
      }
      if (i === 7) hex += " ";
    }
    lines.push(off.toString(16).padStart(8, "0") + "  " + hex + " " + asc);
  }
  return lines.join("\n") || "(empty)";
}

// --- CRLF / non-printing-char display substitution (view-only) ------------
function withVisibleControls(raw) {
  return raw.replace(/\r/g, "␤\r").replace(/\0/g, "␀")
    .replace(/[\x01-\x08\x0b\x0c\x0e-\x1f]/g, (c) =>
      String.fromCharCode(0x2400 + c.charCodeAt(0)));
}

class MessageEditor extends HTMLElement {
  constructor() {
    super();
    this._bytes = "";
    this._meta = null;
    this._built = false;
    this._activeTab = "raw";
    this._showControls = false;
    this._searchOpen = false;
    this._searchHits = [];
    this._searchIdx = -1;
  }

  connectedCallback() {
    if (!this._built) this._build();
    this._renderAll();
  }

  get editable() { return this.hasAttribute("editable"); }
  set editable(v) {
    this.toggleAttribute("editable", !!v);
    if (this._built) { this._syncTabsForEditable(); this._renderAll(); }
  }

  get bytes() { return this._bytes; }
  set bytes(v) {
    this._bytes = v == null ? "" : String(v);
    if (this._built) this._renderAll();
  }

  get meta() { return this._meta; }
  set meta(v) {
    this._meta = v || null;
    if (this._built) this._renderStrip();
  }

  getBytes() {
    return (this.editable && this._textarea) ? this._textarea.value : this._bytes;
  }

  _build() {
    this._built = true;
    this.classList.add("message-editor");
    const uid = `me${_meUid++}`;

    this._strip = h("div", { class: "me-strip" });

    // Raw's aria-controls is skipped: which element is visible under this tab
    // (the <textarea> when editable, the read-only mirror otherwise) can change at
    // runtime, and aria-controls must not point at a hidden element — aria-labelledby
    // on each candidate panel (below) still gives assistive tech the association.
    const tabRaw = h("button", { type: "button", class: "me-tab", "data-tab": "raw",
      id: `${uid}-tab-raw`, role: "tab", "aria-selected": "true", text: "Raw" });
    const tabPretty = h("button", { type: "button", class: "me-tab", "data-tab": "pretty",
      id: `${uid}-tab-pretty`, role: "tab", "aria-selected": "false",
      "aria-controls": `${uid}-panel-pretty`, text: "Pretty" });
    const tabHex = h("button", { type: "button", class: "me-tab", "data-tab": "hex",
      id: `${uid}-tab-hex`, role: "tab", "aria-selected": "false",
      "aria-controls": `${uid}-panel-hex`, text: "Hex" });
    this._tabButtons = { raw: tabRaw, pretty: tabPretty, hex: tabHex };
    const tabList = h("div", { class: "me-tabs", role: "tablist", "aria-label": "View" },
      [tabRaw, tabPretty, tabHex]);
    for (const btn of [tabRaw, tabPretty, tabHex]) {
      btn.addEventListener("click", () => this._selectTab(btn.dataset.tab));
    }
    tabList.addEventListener("keydown", (e) => this._onTabKey(e));

    this._ctrlToggle = h("input", { type: "checkbox", class: "me-crlf" });
    this._ctrlToggle.addEventListener("change", () => {
      this._showControls = this._ctrlToggle.checked;
      this._renderRaw();
    });
    const ctrlLabel = h("label", { class: "me-toggle" },
      [this._ctrlToggle, document.createTextNode(" show CRLF/NUL")]);

    const searchBtn = h("button", { type: "button", class: "me-search-btn", title: "Search (Ctrl-F)",
      text: "\u{1F50D}" });
    searchBtn.addEventListener("click", () => this._openSearch());

    const bar = h("div", { class: "me-bar" }, [tabList, ctrlLabel, searchBtn]);

    this._textarea = h("textarea", { class: "me-raw-edit", spellcheck: false,
      id: `${uid}-panel-raw`, role: "tabpanel", "aria-labelledby": `${uid}-tab-raw` });
    this._textarea.addEventListener("input", () => {
      if (this._mirrorLive) this._renderRaw();       // keep the search mirror in sync
    });
    this._rawMirror = h("pre", { class: "me-raw-view", tabindex: "0",
      id: `${uid}-panel-raw-ro`, role: "tabpanel", "aria-labelledby": `${uid}-tab-raw` });
    this._pretty = h("div", { class: "me-pretty", tabindex: "0",
      id: `${uid}-panel-pretty`, role: "tabpanel", "aria-labelledby": `${uid}-tab-pretty` });
    this._hex = h("pre", { class: "me-hex", tabindex: "0",
      id: `${uid}-panel-hex`, role: "tabpanel", "aria-labelledby": `${uid}-tab-hex` });

    this._searchBar = this._buildSearchBar();

    this._panes = h("div", { class: "me-panes" },
      [this._textarea, this._rawMirror, this._pretty, this._hex]);

    this.replaceChildren(this._strip, bar, this._panes, this._searchBar);
    this.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
        e.preventDefault();
        this._openSearch();
      } else if (e.key === "Escape" && this._searchOpen) {
        this._closeSearch();
      }
    });

    this._syncTabsForEditable();
    this._selectTab("raw");
  }

  _buildSearchBar() {
    const input = h("input", { type: "text", class: "me-search-input", placeholder: "Find in message…" });
    const count = h("span", { class: "me-search-count" });
    const prev = h("button", { type: "button", class: "me-search-prev", "aria-label": "Previous match", text: "↑" });
    const next = h("button", { type: "button", class: "me-search-next", "aria-label": "Next match", text: "↓" });
    const close = h("button", { type: "button", class: "me-search-close", "aria-label": "Close search", text: "×" });
    input.addEventListener("input", () => this._runSearch(input.value));
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); this._stepSearch(e.shiftKey ? -1 : 1); }
      else if (e.key === "Escape") { e.preventDefault(); this._closeSearch(); }
    });
    prev.addEventListener("click", () => this._stepSearch(-1));
    next.addEventListener("click", () => this._stepSearch(1));
    close.addEventListener("click", () => this._closeSearch());
    this._searchInput = input;
    this._searchCount = count;
    return h("div", { class: "me-search", hidden: true }, [input, count, prev, next, close]);
  }

  _syncTabsForEditable() {
    this._tabButtons.hex.hidden = this.editable;   // Hex is response/read-only-only (v1)
    if (this.editable && this._activeTab === "hex") this._activeTab = "raw";
  }

  _onTabKey(e) {
    const order = ["raw", "pretty", "hex"].filter((t) => !this._tabButtons[t].hidden);
    const i = order.indexOf(this._activeTab);
    let next = null;
    if (e.key === "ArrowRight") next = order[(i + 1) % order.length];
    else if (e.key === "ArrowLeft") next = order[(i - 1 + order.length) % order.length];
    else if (e.key === "Home") next = order[0];
    else if (e.key === "End") next = order[order.length - 1];
    if (next) { e.preventDefault(); this._selectTab(next); this._tabButtons[next].focus(); }
  }

  _selectTab(tab) {
    this._activeTab = tab;
    for (const [name, btn] of Object.entries(this._tabButtons)) {
      btn.setAttribute("aria-selected", String(name === tab));
    }
    this._textarea.hidden = !(tab === "raw" && this.editable && !this._searchOpen);
    this._rawMirror.hidden = !(tab === "raw" && (!this.editable || this._searchOpen));
    this._pretty.hidden = tab !== "pretty";
    this._hex.hidden = tab !== "hex";
    if (tab === "raw") this._renderRaw();
    else if (tab === "pretty") renderPretty(this._pretty, this._currentBytes());
    else if (tab === "hex") this._hex.textContent = hexDump(this._currentBytes());
  }

  _currentBytes() {
    return (this.editable && this._textarea) ? this._textarea.value : this._bytes;
  }

  _renderAll() {
    if (this.editable) this._textarea.value = this._bytes;
    if (this._activeTab === "raw") this._renderRaw();
    else if (this._activeTab === "pretty") renderPretty(this._pretty, this._currentBytes());
    else if (this._activeTab === "hex") this._hex.textContent = hexDump(this._currentBytes());
    this._renderStrip();
  }

  _renderRaw() {
    const text = this._currentBytes();
    this._rawMirror.textContent = this._showControls ? withVisibleControls(text) : text;
  }

  _renderStrip() {
    const raw = this._currentBytes();
    const { head } = splitHeadBody(raw);
    const { startLine, headers } = parseHead(head);
    const m = /^HTTP\/\d(?:\.\d)?\s+(\d{3})\s*(.*)$/.exec(startLine);
    const meta = this._meta || {};
    const status = meta.status != null ? meta.status : (m ? m[1] : null);
    const reason = meta.reason != null ? meta.reason : (m ? m[2] : "");
    const contentType = findHeader(headers, "content-type");
    const { body } = splitHeadBody(raw);
    const parts = [];
    if (status) parts.push(h("span", { class: "me-strip-status", text: `${status} ${reason}`.trim() }));
    if (meta.ms != null) parts.push(h("span", { class: "me-strip-ms", text: `${meta.ms} ms` }));
    parts.push(h("span", { class: "me-strip-len", text: `${body.length} B` }));
    if (contentType) parts.push(h("span", { class: "me-strip-ctype", text: contentType }));
    this._strip.replaceChildren(...parts);
    this._strip.hidden = parts.length === 0;
  }

  // --- Ctrl-F search: CSS Custom Highlight over the read-only mirror only ---
  _openSearch() {
    if (this._activeTab !== "raw") this._selectTab("raw");
    this._mirrorLive = true;
    this._textarea.hidden = true;
    this._rawMirror.hidden = false;
    this._renderRaw();
    this._searchOpen = true;
    this._searchBar.hidden = false;
    this._searchInput.value = "";
    this._searchInput.focus();
    this._runSearch("");
  }

  _closeSearch() {
    this._searchOpen = false;
    this._mirrorLive = false;
    this._searchBar.hidden = true;
    this._clearHighlights();
    this._selectTab(this._activeTab);
    if (this.editable) this._textarea.focus();
  }

  _clearHighlights() {
    if (typeof CSS !== "undefined" && CSS.highlights) {
      CSS.highlights.delete(HL_MATCH);
      CSS.highlights.delete(HL_CURRENT);
    }
  }

  _runSearch(query) {
    this._searchHits = [];
    this._searchIdx = -1;
    this._clearHighlights();
    if (!query) { this._searchCount.textContent = ""; return; }
    const node = this._rawMirror.firstChild;
    const text = this._rawMirror.textContent || "";
    const q = query;
    if (!node || node.nodeType !== Node.TEXT_NODE) { this._searchCount.textContent = "0/0"; return; }
    let from = 0;
    while (true) {
      const at = text.indexOf(q, from);
      if (at < 0) break;
      this._searchHits.push([at, at + q.length]);
      from = at + Math.max(q.length, 1);
    }
    if (typeof CSS !== "undefined" && CSS.highlights && window.Highlight) {
      const matchHL = new Highlight();
      for (const [start, end] of this._searchHits) {
        const r = document.createRange();
        r.setStart(node, start); r.setEnd(node, end);
        matchHL.add(r);
      }
      CSS.highlights.set(HL_MATCH, matchHL);
    }
    this._searchIdx = this._searchHits.length ? 0 : -1;
    this._paintCurrent();
    this._searchCount.textContent = `${this._searchHits.length ? 1 : 0}/${this._searchHits.length}`;
  }

  _stepSearch(dir) {
    if (!this._searchHits.length) return;
    this._searchIdx = (this._searchIdx + dir + this._searchHits.length) % this._searchHits.length;
    this._paintCurrent();
    this._searchCount.textContent = `${this._searchIdx + 1}/${this._searchHits.length}`;
  }

  _paintCurrent() {
    if (typeof CSS === "undefined" || !CSS.highlights || !window.Highlight) return;
    if (this._searchIdx < 0) { CSS.highlights.delete(HL_CURRENT); return; }
    const node = this._rawMirror.firstChild;
    const [start, end] = this._searchHits[this._searchIdx];
    const r = document.createRange();
    r.setStart(node, start); r.setEnd(node, end);
    const curHL = new Highlight(); curHL.add(r);
    CSS.highlights.set(HL_CURRENT, curHL);
    // scroll the match into view without touching the DOM structure
    const rect = r.getBoundingClientRect();
    if (rect.width || rect.height) {
      this._rawMirror.scrollTop += rect.top - this._rawMirror.getBoundingClientRect().top
        - this._rawMirror.clientHeight / 2;
    }
  }
}

if (!customElements.get("message-editor")) customElements.define("message-editor", MessageEditor);

// --- resizable splitter (vanilla; no library) -------------------------------
// A CSS-grid track (`--a`) sized in px, dragged via pointer capture. Persists the
// dragged size (px) to localStorage per orientation, and supports arrow-key resize
// on the handle (WCAG 2.2 AA — the `separator` role's expected keyboard model).
export function attachSplitter(root, { orientKey, min = 120 } = {}) {
  const handle = root.querySelector(".me-handle");
  const paneA = root.querySelector(".me-pane-a");
  let orient = root.dataset.orient || "horizontal";
  let dragging = false, startPos = 0, startSize = 0;

  const sizeProp = () => (orient === "horizontal" ? "width" : "height");
  const totalSize = () => root.getBoundingClientRect()[sizeProp()];
  const keyFor = (o) => (orientKey ? `${orientKey}:${o}` : null);

  function apply(px) { root.style.setProperty("--a", `${px}px`); }
  function save(px) {
    try { const k = keyFor(orient); if (k) localStorage.setItem(k, String(Math.round(px))); } catch (_) { /* ignore */ }
  }
  function load() {
    try {
      const k = keyFor(orient);
      const v = k && localStorage.getItem(k);
      return v ? parseFloat(v) : null;
    } catch (_) { return null; }
  }

  function setOrient(o) {
    orient = o;
    root.dataset.orient = o;
    handle.setAttribute("aria-orientation", o === "horizontal" ? "vertical" : "horizontal");
    root.style.removeProperty("--a");
    const px = load();
    if (px) apply(px);
  }

  handle.addEventListener("pointerdown", (e) => {
    dragging = true;
    handle.setPointerCapture(e.pointerId);
    startPos = orient === "horizontal" ? e.clientX : e.clientY;
    startSize = paneA.getBoundingClientRect()[sizeProp()];
  });
  handle.addEventListener("pointermove", (e) => {
    if (!dragging) return;
    const pos = orient === "horizontal" ? e.clientX : e.clientY;
    const total = totalSize();
    const px = Math.max(min, Math.min(total - min - 8, startSize + (pos - startPos)));
    apply(px);
    handle.setAttribute("aria-valuenow", String(Math.round((px / total) * 100)));
  });
  handle.addEventListener("pointerup", (e) => {
    if (!dragging) return;
    dragging = false;
    handle.releasePointerCapture(e.pointerId);
    save(parseFloat(getComputedStyle(root).getPropertyValue("--a")) || paneA.getBoundingClientRect()[sizeProp()]);
  });
  handle.addEventListener("keydown", (e) => {
    const step = 24;
    const horiz = orient === "horizontal";
    const delta = (horiz && e.key === "ArrowLeft") || (!horiz && e.key === "ArrowUp") ? -step
      : (horiz && e.key === "ArrowRight") || (!horiz && e.key === "ArrowDown") ? step : 0;
    if (!delta) return;
    e.preventDefault();
    const total = totalSize();
    const cur = paneA.getBoundingClientRect()[sizeProp()];
    const px = Math.max(min, Math.min(total - min - 8, cur + delta));
    apply(px);
    handle.setAttribute("aria-valuenow", String(Math.round((px / total) * 100)));
    save(px);
  });

  setOrient(orient);
  return { setOrient };
}
