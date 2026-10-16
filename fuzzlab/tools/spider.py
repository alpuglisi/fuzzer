import argparse
import contextlib
import copy
import functools
import logging
import sqlite3
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from fuzzlab.core import get_logger, sendpolicy
from fuzzlab.core.urls import (canonical_origin, document_key, in_origin_scope, origin_scope,
                               url_key)
from fuzzlab.tools import navguard, spa

# Configure logging for production-ready output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Optional JavaScript rendering. Playwright drives a real (headless) browser, so
# content and links produced by JavaScript become visible. If it is not
# installed the crawler falls back to the static requests engine.
try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

    class PlaywrightError(Exception):
        """Stand-in so ``except PlaywrightError`` is valid without Playwright."""


class StorageManager:
    """Handles all database interactions to keep the crawler modular."""
    def __init__(self, db_name="spider_results.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        """Creates the schema if it doesn't exist and upgrades older databases."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                status_code INTEGER,
                depth INTEGER,
                title TEXT,
                content TEXT,
                rendered INTEGER DEFAULT 0,
                source TEXT DEFAULT 'link'
            )
        ''')
        # Every form the crawler saw (forms phase 1): entries are stored with sensitive
        # values blanked (core.forms.form_record), one row per (action, method, controls).
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_forms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_url TEXT,
                action_url TEXT,
                method TEXT,
                enctype TEXT,
                entries TEXT,
                controls TEXT,
                selector INTEGER DEFAULT 0,
                options TEXT,
                sig TEXT UNIQUE
            )
        ''')
        # What each submitted selector form did (forms phase 2, FR-CRAWL-10), keyed by
        # `formnav.signature_key`: "navigation" or "settings".
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS selector_verdicts (
                sig TEXT PRIMARY KEY,
                verdict TEXT
            )
        ''')
        # The app's own fetch/XHR requests with a JSON or form body (forms phase 3,
        # FR-CRAWL-13), the contract lane J imports: body_json is the redacted body as
        # JSON text; source is 'passive', 'submit' or 'blocked' (CC-CRAWL-0036);
        # signature = method + canonical URL path + the body's sorted leaf paths
        # (CC-CRAWL-0037); headers_json = `redact_captured_headers` (allowlisted,
        # non-secret headers; a cookie or credential header's name only, never its
        # value).
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_url TEXT,
                method TEXT,
                url TEXT,
                content_type TEXT,
                body_json TEXT,
                source TEXT,
                signature TEXT UNIQUE,
                headers_json TEXT
            )
        ''')
        # What the crawl's SPA features did (FR-CRAWL-12/13): `LocalSpider.spa_counts`
        # plus `submit_stopped` (0/1), written at the end of each crawl so reports can
        # read them (PA-0110; lane S review).
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS crawl_stats (
                name TEXT PRIMARY KEY,
                value INTEGER
            )
        ''')
        # Forms a reveal made visible (forms phase 4, FR-CRAWL-16 G2e): the route they
        # are attributed to and their `spa.form_signature`, for a later opt-in. Never
        # values; the page URL passes `redact_url_identifiers`.
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS revealed_forms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_url TEXT,
                route TEXT,
                signature TEXT,
                submitted INTEGER DEFAULT 0,
                UNIQUE (route, signature)
            )
        ''')
        # Add columns that older result databases won't have.
        for table, col, decl in (
                ("discovered_pages", "title", "TEXT"),
                ("discovered_pages", "content", "TEXT"),
                ("discovered_pages", "rendered", "INTEGER DEFAULT 0"),
                ("discovered_pages", "source", "TEXT DEFAULT 'link'"),
                ("discovered_requests", "headers_json", "TEXT")):      # CC-CRAWL-0037
            try:
                self.cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError:
                pass  # column already exists
        self.conn.commit()
        # Visit keys (`spa.visit_key`) of the pages already stored: a page is "visited"
        # by key, so loopback aliases are one site and SPA routes distinct pages.
        self._keys = {spa.visit_key(u) for (u,) in
                      self.cursor.execute('SELECT url FROM discovered_pages')}

    def reset(self):
        """Clears previous results so a fresh crawl starts from an empty map."""
        self.cursor.execute('DELETE FROM discovered_pages')
        self.cursor.execute('DELETE FROM discovered_forms')
        self.cursor.execute('DELETE FROM selector_verdicts')
        self.cursor.execute('DELETE FROM discovered_requests')
        self.cursor.execute('DELETE FROM crawl_stats')
        self.cursor.execute('DELETE FROM revealed_forms')
        self.conn.commit()
        self._keys = set()

    def record_stats(self, counts):
        """Store the crawl's counts (``name -> int``), replacing earlier values of the
        same names (a resumed crawl records its own run's counts)."""
        self.cursor.executemany(
            "INSERT INTO crawl_stats (name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            [(str(k), int(v)) for k, v in counts.items()])
        self.conn.commit()

    def record_request(self, page_url, method, url, content_type, body, source,
                       headers=None):
        """Store one request the page made (FR-CRAWL-13), redacted here, at the write
        site, by the one boundary (PA-0100): both URLs by
        `core.redaction.redact_url_identifiers`, the body by
        `core.redaction.redact_captured_body` (64 KiB, depth 8, fail closed), the
        request's ``headers`` by `core.redaction.redact_captured_headers` (CC-CRAWL-0037:
        allowlisted non-secret headers; a cookie or credential header is named, its
        value never taken). ``content_type`` keeps its media type. The signature is the
        method, the canonical URL and the redacted body's sorted leaf paths
        (`_leaf_paths`), so two bodies of different nested shapes are two requests.
        Returns None when stored, else why not (``duplicate`` for a signature already
        stored)."""
        import json

        from fuzzlab.core.redaction import (redact_captured_body, redact_captured_headers,
                                            redact_url_identifiers)
        doc, why = redact_captured_body(body, content_type)
        if why is not None:
            return why
        # a probe marker an app replays never reaches a row (FR-CRAWL-17, A-S4)
        doc = json.loads(spa.scrub_markers(json.dumps(doc, ensure_ascii=False)))
        safe_url = spa.scrub_markers(redact_url_identifiers(url))
        method = (method or "").upper()
        sig = json.dumps([method, url_key(safe_url), _leaf_paths(doc)])
        media = (content_type or "").split(";", 1)[0].strip().lower()
        kept = spa.scrub_markers(json.dumps(redact_captured_headers(headers),
                                            ensure_ascii=False))
        try:
            self.cursor.execute('''
                INSERT INTO discovered_requests
                    (page_url, method, url, content_type, body_json, source, signature,
                     headers_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (spa.scrub_markers(redact_url_identifiers(page_url)), method, safe_url, media,
                  json.dumps(doc, ensure_ascii=False), source, sig, kept))
            self.conn.commit()
            return None
        except sqlite3.IntegrityError:
            return "duplicate"

    def record_revealed_form(self, page_url, route, signature, submitted=False):
        """File a form a reveal made visible (FR-CRAWL-16, G2e): its route and signature;
        the page URL redacted (`core.redaction.redact_url_identifiers`). A later
        submission of the same form marks it ``submitted``. Returns True when new."""
        from fuzzlab.core.redaction import redact_url_identifiers
        # a probe marker never reaches a row; the dedup key is the stored one (B-N3)
        route, signature = spa.scrub_markers(route), spa.scrub_markers(signature)
        row = self.cursor.execute("SELECT id FROM revealed_forms WHERE route = ? AND "
                                  "signature = ?", (route, signature)).fetchone()
        if row is not None:
            if submitted:
                self.cursor.execute("UPDATE revealed_forms SET submitted = 1 WHERE id = ?",
                                    (row[0],))
                self.conn.commit()
            return False
        self.cursor.execute(
            "INSERT INTO revealed_forms (page_url, route, signature, submitted) "
            "VALUES (?, ?, ?, ?)",
            (spa.scrub_markers(redact_url_identifiers(page_url)), route, signature,
             int(bool(submitted))))
        self.conn.commit()
        return True

    def record_verdict(self, sig, verdict):
        """File what a submitted selector form did (``settings`` wins over
        ``navigation`` for the same signature)."""
        self.cursor.execute(
            "INSERT INTO selector_verdicts (sig, verdict) VALUES (?, ?) "
            "ON CONFLICT(sig) DO UPDATE SET verdict = CASE WHEN excluded.verdict = "
            "'settings' THEN 'settings' ELSE selector_verdicts.verdict END",
            (sig, verdict))
        self.conn.commit()

    def record_form(self, record):
        """Store a form record (already redacted by ``core.forms.form_record``; the
        page and action URLs pass ``redact_url``). Returns False if already present."""
        import json

        from fuzzlab.core.redaction import redact_url
        sig = json.dumps([record["action_url"], record["method"],
                          sorted(n for n, _k in record["controls"])])
        try:
            self.cursor.execute('''
                INSERT INTO discovered_forms
                    (page_url, action_url, method, enctype, entries, controls, selector,
                     options, sig)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', tuple(spa.scrub_markers(v) for v in (      # FR-CRAWL-17 (A-S4)
                redact_url(record["page_url"]), redact_url(record["action_url"]),
                record["method"], record["enctype"], json.dumps(record["entries"]),
                json.dumps(record["controls"]), int(record["selector"]),
                json.dumps(record["options"]), sig)))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def count(self):
        self.cursor.execute('SELECT COUNT(*) FROM discovered_pages')
        return self.cursor.fetchone()[0]

    def mark_visited(self, url, status_code, depth, title=None, content=None,
                     rendered=0, source='link'):
        """Records a URL (and any parsed content). Returns False if already present
        (by visit key: an alias spelling of a stored page is present). A probe marker
        (FR-CRAWL-17) in the URL, title or text is replaced (`spa.scrub_markers`): an app
        may replay one it persisted, and no row ever carries one (review A-S4)."""
        url, title, content = (spa.scrub_markers(v) for v in (url, title, content))
        key = spa.visit_key(url)
        if key in self._keys:
            return False
        try:
            self.cursor.execute('''
                INSERT INTO discovered_pages (url, status_code, depth, title, content, rendered, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (url, status_code, depth, title, content, int(rendered), source))
            self.conn.commit()
            self._keys.add(key)
            return True
        except sqlite3.IntegrityError:
            # URL already exists in the unique column
            return False

    def set_source(self, url, source):
        """Re-file a stored page's ``source`` (a query seed that blocked a write,
        FR-CRAWL-17). Returns True when a row changed."""
        cur = self.cursor.execute("UPDATE discovered_pages SET source = ? WHERE url = ?",
                                  (source, spa.scrub_markers(url)))
        self.conn.commit()
        return cur.rowcount > 0

    def is_visited(self, url):
        """Whether a page with this URL's visit key (`spa.visit_key`: canonical origin,
        path, query and SPA-route fragment) has already been processed."""
        return spa.visit_key(url) in self._keys

    def close(self):
        self.conn.close()


#: At most this many leaf paths make a captured request's signature.
MAX_SIGNATURE_PATHS = 256


def _leaf_paths(doc) -> list:
    """The sorted leaf paths of a redacted body (CC-CRAWL-0037): each path is the list
    of object keys down to a value that is not a non-empty container; an array's items
    share one ``"[]"`` step, so a list's length never makes a new request. A form body
    (a flat object) gives its names, as the top-level keys did. The first
    `MAX_SIGNATURE_PATHS` in sorted order."""
    out, stack = set(), [((), doc)]
    while stack:                      # bounded by the capture's 64 KiB / depth-8 cap
        path, node = stack.pop()
        if isinstance(node, dict) and node:
            stack.extend((path + (str(k),), v) for k, v in node.items())
        elif isinstance(node, list) and node:
            stack.extend((path + ("[]",), v) for v in node)
        elif path:
            out.add(path)
    # sorted before the cut, so key order never changes the signature (review N1)
    return [list(p) for p in sorted(out)[:MAX_SIGNATURE_PATHS]]


def _storage_rotated(value) -> bool:
    """A changed localStorage value that is a rotation, not a loss (reviewer B-S3): a
    non-empty, identifier-like value (`core.redaction.looks_like_identifier`). Cleared,
    empty, ``"null"`` and ``"undefined"`` (what ``localStorage.setItem(k, null)`` and
    friends leave) are a loss."""
    from fuzzlab.core.redaction import looks_like_identifier
    if value is None or str(value).strip().lower() in ("", "null", "undefined"):
        return False
    return looks_like_identifier(str(value))


def _nav_key(url):
    """A navigation's exact target for the reveal window's own-reload exemption (review
    A-S2): `core.urls.document_key` -- canonical origin, path and query, never only the
    path, so a redirect or a navigation to ``?action=x`` on the same path is not the
    window's own reload. The fragment is dropped: a reload never sends one."""
    return document_key(url)


def _route_key(url):
    """The bare route a seed or probe URL is a query of (FR-CRAWL-17, P1): a hash
    route's URL without its fragment's query (``/#/track?id=x`` -> ``/#/track``), else
    the URL without its query and fragment (history mode). A loadable URL."""
    head, sep, _frag = (url or "").partition("#")
    frag = spa.spa_fragment(url)
    if sep and frag is not None:
        return head + "#" + frag.split("?", 1)[0]
    return head.split("?", 1)[0]


def _is_bare_route(url):
    """Is ``url`` a route with no query of its own (B1)? A hash route: its fragment has
    no ``?``; otherwise the URL has no query. Only such a load is a route's baseline: a
    crawled ``#/poster?msg=hi`` link's POST is caused by its query, never the shell's."""
    frag = spa.spa_fragment(url)
    if frag is not None:
        return "?" not in frag
    return not urlparse(url or "").query


def _carries(tokens, *texts):
    """Does any of ``texts`` (a URL, a body, a WebSocket message; ``bytes`` decoded)
    carry one of ``tokens`` -- the seed's filler or the probe's markers (B2)? A URL is
    also read percent-decoded."""
    from urllib.parse import unquote_plus
    for text in texts:
        if text is None:
            continue
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8", "replace")
        text = str(text)
        for form in (text, unquote_plus(text)):
            if any(t and t in form for t in tokens):
                return True
    return False


def _write_key(method, url):
    """A write's identity for the baseline (P1(b)): its method (``WS`` for a WebSocket
    message) and its URL's path."""
    return ((method or "").upper(), urlparse(url or "").path or "/")


#: `discovered_requests.source` of a write the window refused and the crawl recorded,
#: unsent (CC-CRAWL-0036).
BLOCKED_SOURCE = "blocked"

#: Request types that stay open by design (an event stream; a WebSocket handshake).
_BACKGROUND_TYPES = frozenset({"eventsource", "websocket"})


def _background_request(request) -> bool:
    """A request a settle does not wait for (CC-CRAWL-0035): a realtime transport
    (`spa.is_transport_url`: socket.io / engine.io polling) or a request of a type that
    stays open by design. Judged on the URL and type alone, so the count goes up and
    down for the same requests. Unreadable: counted (waited for)."""
    try:
        return spa.is_transport_url(request.url) or \
            (request.resource_type or "") in _BACKGROUND_TYPES
    except Exception:  # noqa: BLE001 - fail towards waiting
        return False


#: ``names => {name: localStorage value}`` (FR-CRAWL-14's session check).
_LOCAL_STORAGE_JS = ("names => Object.fromEntries(names.map(n => "
                     "[n, window.localStorage.getItem(n)]))")


class SessionWithheld(RuntimeError):
    """A navigation met a document on another origin than the authenticated session's
    (FR-SESS-20): it is not crawled, and nothing is extracted from it."""


def _parse_html(html):
    """``(title, text, links)`` of an HTML document, as the static engine reads it."""
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.string.strip() if soup.title and soup.title.string else None
    return title, soup.get_text(" ", strip=True), \
        [a['href'] for a in soup.find_all('a', href=True)]


class LocalSpider:
    """Crawls a local site, optionally rendering JavaScript with a headless browser."""

    def __init__(self, start_url, max_depth=3, db_name="spider_results.db",
                 engine="auto", timeout_ms=10000, resume=False,
                 session_manager=None, identity=None, selector_forms=None,
                 spa_routes=True, submit_spa_forms=None, reveal=True, spa_query=True):
        self.start_url = start_url
        self.max_depth = max_depth
        self.storage = StorageManager(db_name)
        self.timeout_ms = timeout_ms
        self.resume = resume
        # Optional authentication for the Playwright engine: inject the session
        # (cookies / bearer header) into the browser context so JS-rendered pages
        # are crawled authenticated (Option A, browser path).
        self._session_manager = session_manager
        self._identity = identity
        # The login is discovered from the start URL itself, never its bare origin: the
        # app may live under a path (/bWAPP/), BUG-0113.
        self._auth_base_url = start_url
        # Link-following scope: the start URL's own host (see _in_scope); for a
        # loopback start, its exact origin (BUG-0123). The browser and every API request
        # use the same predicate.
        self._scope_host = self._norm_host(start_url)
        self._scope_origins = origin_scope(start_url)
        #: out-of-scope requests the browser aborted, by host (BUG-0123)
        self.skipped_out_of_scope: dict[str, int] = {}

        # A crawl normally rebuilds the whole map. Without this, a second run
        # against an existing database finds every URL already "visited" and
        # exits having crawled nothing. Pass resume=True to keep prior rows.
        if resume:
            logging.info(f"Resuming: {self.storage.count()} page(s) already in {db_name} will be skipped.")
        else:
            self.storage.reset()

        # Using a Session enables connection pooling for the static engine.
        # Set a full, internally-consistent set of browser headers
        # (BUG-0059/BUG-0060): `requests`' own defaults (`User-Agent:
        # python-requests/x.y`, `Accept: */*`, no `Accept-Language`) are
        # trivially fingerprintable, and several real external targets serve a
        # stripped-down/interstitial page (200 OK, no <a href> tags) or an
        # outright 403 to a request whose headers don't hang together as a
        # real browser's would -- a UA fix alone does not clear a WAF that
        # also checks Accept/Accept-Language/Sec-Fetch-* for the mismatch a
        # spoofed-UA-only client still shows. The local lab never surfaced
        # this since it doesn't discriminate by headers.
        from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_BROWSER_HEADERS)

        # Resolve which engine to use.
        if engine == "auto":
            engine = "playwright" if _PLAYWRIGHT_AVAILABLE else "requests"
        if engine == "playwright" and not _PLAYWRIGHT_AVAILABLE:
            logging.warning(
                "Playwright is not installed; falling back to the static 'requests' engine "
                "(dynamic content will NOT be seen). Install it with: "
                "pip install playwright && playwright install chromium"
            )
            engine = "requests"
        self.engine = engine
        logging.info(f"Crawler engine: {self.engine}")

        # Playwright handles (created lazily in crawl()).
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        # URLs requested by JavaScript (fetch/XHR) during the current navigation.
        self._xhr_urls = []
        # NFR-CRAWL-safe (BUG-0111): destructive links are never queued, fetched or
        # followed through a redirect; the start URL is the operator's own input.
        self._allow = frozenset({url_key(start_url)})
        self.skipped_destructive: dict[str, str] = {}
        # Selector-form navigation (FR-CRAWL-8): None = off (default); else the set of
        # select names the operator named (POST forms need a name; GET ones are allowed
        # whenever the feature is on).
        self._selector_forms = None if selector_forms is None else frozenset(selector_forms)
        self._enumerated: set = set()
        self._auth_headers: dict = {}
        #: where the session's headers may go (FR-CRAWL-14; set with the session)
        self._header_scope = self._in_scope
        #: where the context's cookies may go (FR-SESS-20: the session's origins; set
        #: with the session, None for an unauthenticated crawl)
        self._cookie_scope = None
        #: in-scope requests sent without the session: another origin (FR-SESS-20)
        self.session_out_of_origin = 0
        #: in-scope pages (documents, WebSockets) never loaded because they are on
        #: another origin than the session's, with the reason (FR-SESS-20, R1)
        self.skipped_other_origin: dict[str, str] = {}
        #: the navigation targets (``url_key``) whose own document or redirect landing
        #: the route withheld during the current page navigation (FR-SESS-20, T1)
        self._withheld_targets: set = set()
        #: the cookie-less request contexts the guards made (R2), disposed at the end
        self._isolated_requests: list = []
        #: how many such contexts were created (review round 2, T6)
        self.isolated_contexts_created = 0
        #: the in-scope localStorage entries the crawl adopted, ``{origin: {name:
        #: value}}``, checked after each authenticated submission (FR-CRAWL-14)
        self._adopted_storage: dict = {}
        self._last_final_url = None
        self._last_html = None
        # --- single-page apps (forms phase 3) ---
        # FR-CRAWL-12: routes from already-loaded same-origin scripts, hash routes as
        # distinct pages; default on in the Playwright engine (--no-spa-routes).
        self._spa_on = self.engine == "playwright" and bool(spa_routes)
        # FR-CRAWL-13: None = off (default); an empty set = every eligible route; else
        # only the routes named (normalised, `spa.normalise_route`).
        self._submit_routes = (None if submit_spa_forms is None else
                               frozenset(spa.normalise_route(r) for r in submit_spa_forms
                                         if spa.normalise_route(r)))
        if self._submit_routes is not None and not self._spa_on:
            logging.warning("--submit-spa-forms needs the Playwright engine with SPA routes "
                            "on; no SPA form will be submitted")
        self._authenticated = bool(session_manager and identity)
        self._injected_cookies: list = []
        self._app_base = self._start_dir(start_url)
        self._scripts_seen: set = set()
        self._page_scripts = 0
        self._pending_routes: list = []
        self._route_names: set = set()     # routes taken from scripts
        self._route_keys: set = set()      # their page URLs, by visit key
        self._doc_url = start_url
        self._last_doc = (200, "text/html")
        self._last_base = None
        self._current_url = start_url
        self._capture_source = "passive"
        self._capture_page = None
        # the one browser context a named-route submission is clicking in, or None
        self._delete_ok_for = None
        self._submitted_sigs: set = set()
        self._inflight: dict = {}
        #: Why SPA form submission stopped early (session lost), or None (FR-CRAWL-13).
        self.spa_submit_stopped = None
        #: What the SPA features did, reported at the end of the crawl (PA-0110: each
        #: count is of an effect that happened, e.g. a route page actually loaded).
        self.spa_counts = dict.fromkeys((
            "routes_found", "routes_visited", "routes_skipped_destructive",
            "routes_skipped_parameterised", "scripts_scanned", "scripts_too_large",
            "scripts_over_page_cap", "transport_urls_skipped", "requests_captured",
            "requests_not_recorded", "requests_blocked_recorded", "deletes_blocked",
            "forms_submitted", "forms_submitted_enter",
            "forms_refused", "forms_not_submittable", "forms_not_found_anonymous",
            "submissions_over_cap", "clicks_dispatched", "forms_label_changed",
            # forms phase 4 (FR-CRAWL-15/16; persisted in crawl_stats, PA-0110)
            "reveals_clicked", "reveals_refused", "reveals_over_cap",
            "reveal_writes_blocked", "reveal_ws_dropped", "reveal_navigations_captured",
            "revealed_links", "revealed_forms", "session_losses_after_reveal",
            "g1_controls_filled", "g1_forms_unsatisfiable",
            # forms phase 5 (FR-CRAWL-17; persisted in crawl_stats, PA-0110)
            "spa_query_pairs", "spa_query_unpaired", "spa_query_probe_loads",
            "spa_query_kept", "spa_query_refused", "spa_query_writes_blocked",
            "spa_query_marker_in_path", "spa_query_step_cap", "spa_query_seeded",
            "spa_query_seeded_fragment", "spa_query_write_seeds",
            "spa_query_session_losses", "spa_query_unclean_windows",
            "spa_query_baseline_writes"), 0)
        # --- forms phase 5: route query parameters (FR-CRAWL-17) ---
        #: On with SPA routes (it reads the same scripts); ``spa_query=False`` turns it off.
        self._query_on = self._spa_on and bool(spa_query)
        #: route -> names read from this page's scripts, seeded by `_queue_routes`
        self._pending_pairs: dict = {}
        #: every (route, name) pair and unpaired name the scripts gave (counted once)
        self._query_pairs_seen: set = set()
        self._query_unpaired: dict = {}
        #: visit keys of seeds already queued; route URL -> names seeded on it
        self._seed_keys: set = set()
        self._seeded_names: dict = {}
        #: scanned routes a probe may load (route -> (URL, depth)), and those probed
        self._probe_routes: dict = {}
        self._probed: set = set()
        self._names_over_cap: set = set()
        #: the probe load in progress (its markers and the requests it made), or None
        self._probe = None
        #: navigations a seed's window aborted, queued through the normal gates
        self._query_navs: list = []
        #: P1(b): bare route (`_route_key`) -> the writes (`_write_key`) its own loads
        #: made outside any window; a seed's write that is one of them is not counted
        self._write_baseline: dict = {}
        #: the writes of the load in progress, while `_goto_and_parse` records them
        self._load_writes: set = set()
        self._recording = False
        #: P4 (B-N1): did the last `_goto_and_parse` navigation commit?
        self._load_committed = False
        #: why seeds, probes or names were refused, by reason (crawl_stats keys
        #: ``spa_query_refused[<reason>]``)
        self.spa_query_refused: dict = {}
        #: why seed and probe loads stopped for the crawl (a session loss), or None
        self.spa_query_stopped = None
        # --- forms phase 4: the reveal window (W1-W4) and reveals (FR-CRAWL-16) ---
        #: Reveal navigation: on by default in the Playwright engine (--no-reveal); a
        #: reveal can only read (the window), like following a link.
        self._reveal_on = self.engine == "playwright" and bool(reveal)
        #: The open reveal window (W1), or None: ``{"context", "lifted_for", "own_nav",
        #: "aborted", "navs", "restore_aborted", "pages"}``.
        self._win = None
        #: Why reveals stopped for the whole crawl (a second session loss), or None.
        self.reveals_stopped = None
        self._reveal_stopped_routes: set = set()
        self._reveal_seen: set = set()
        self._card_counts: dict = {}
        self._reveal_losses = 0
        self._revealed_link_keys: set = set()
        self._browser_session = None
        self._adopted_original: dict = {}
        self._g1_attempts = 0
        self._rendered_ok = False
        #: set by the window's lift: a vetted final click was attempted (B-M1)
        self._click_attempted = False

    @staticmethod
    def _start_dir(url):
        """The start URL's directory: the app root for history-mode routes (the base
        URL keeps its path, PA-0113)."""
        head = url.split("#", 1)[0].split("?", 1)[0]
        return head if head.endswith("/") else head.rsplit("/", 1)[0] + "/"

    def _crawl_url(self, url):
        """``url`` as the crawler queues it: its fragment dropped, unless it names a SPA
        route and SPA routes are on (FR-CRAWL-12); a kept fragment's query passes the
        redaction boundary (`core.redaction.redact_spa_fragment`), since it is stored."""
        from fuzzlab.core.redaction import redact_spa_fragment
        return redact_spa_fragment(spa.crawl_url(url, self._spa_on))

    def _destructive(self, url):
        """The deny-list reason for ``url`` (None for the start URL), recorded once. A SPA
        route's fragment is checked too (``/#/logout``), which the browser's route guard
        never sees: a hash navigation sends no request (FR-CRAWL-12)."""
        if url_key(url) in self._allow and spa.spa_fragment(url) is None:
            return None
        reason = sendpolicy.destructive(spa.route_destructive_reason(url))
        if reason is not None and url not in self.skipped_destructive:
            self.skipped_destructive[url] = reason
            logging.info(f"skipped destructive link {url} ({reason!r})")
        return reason

    # ----- browser lifecycle (Playwright engine only) -----
    def _start_browser(self):
        self._pw = sync_playwright().start()
        # --no-sandbox / --disable-dev-shm-usage keep Chromium happy in
        # containers and when running as root.
        # Scope-confined launch (BUG-0123): no proxy, nothing resolvable outside the
        # crawl scope (the start origin; for an external start, its host on any port,
        # BUG-0050), no background networking (see browser_launch_args).
        from fuzzlab.tools.navguard import browser_launch_args
        if self._scope_host in self._LOOPBACK:
            args = browser_launch_args([self.start_url])
        else:
            args = browser_launch_args([], any_port_hosts=[self._scope_host,
                                                           f"www.{self._scope_host}"])
        # the one launch configuration, the operator's binary included (BUG-0126)
        from fuzzlab.tools.navguard import chromium_launch_kwargs
        self._browser = self._pw.chromium.launch(**chromium_launch_kwargs(args))
        # FR-CRAWL-14: the session is ensured BEFORE the crawl context opens (a browser
        # login, FR-SESS-19, runs and closes its own context on its own thread); the
        # context adopts its storage_state (in-scope origins only), and its headers are
        # added by the guarded route only (never set_extra_http_headers).
        session = None
        if self._session_manager and self._identity:
            from fuzzlab.tools import browserauth
            session = browserauth.browser_session(
                self._session_manager, self._identity, self._auth_base_url,
                in_scope=self._in_scope, scope_urls=[self.start_url])
            self._auth_headers = dict(session.headers)
            self._header_scope = session.header_scope
            self._cookie_scope = session.cookie_scope
            self._adopted_storage = dict(session.local_storage)
            # what a re-adoption after a session loss restores (W4): the values as
            # adopted, never a rotated one
            self._browser_session = session
            self._adopted_original = copy.deepcopy(session.local_storage)
        # service workers would fetch outside page.route (BUG-0111)
        from fuzzlab.tools import browserauth
        context = self._browser.new_context(service_workers="block",
                                            **browserauth.context_options(session))
        context.add_init_script(spa.LISTEN_INIT_JS)            # CC-CRAWL-0038
        # guard the context, not the page, so popups are confined too (BUG-0123)
        self._guard(context, scripts=True, session=session is not None)
        self._context = context
        self._page = context.new_page()
        self._track(self._page)
        if session is not None:
            from fuzzlab.tools import browserauth
            browserauth.apply_to_context(context, session.cookies)
            # the session's credential cookies (`session.manager.credential_cookie`),
            # jar ones included when they copy the token or look like an identifier
            # (BUG-0132, reviewer B); an ambient jar cookie is the app's to change
            self._injected_cookies = list(session.checked_cookies)
            logging.info(f"Crawler authenticated as {self._identity} "
                         f"({len(session.cookies)} cookie(s), "
                         f"{sum(map(len, self._adopted_storage.values()))} localStorage "
                         f"entr(ies))")
        # Record fetch()/XMLHttpRequest targets. These endpoints are where a
        # JavaScript-rendered page actually gets its data, and they never appear
        # as <a href> anywhere, so link-following alone can never reach them.
        self._page.on("request", self._on_request)
        self._page.on("requestfailed", self._on_request_failed)      # FR-CRAWL-17, Y1
        self._page.on("requestfinished", self._on_request_finished)  # FR-CRAWL-17, M8

    def _guard(self, context, *, scripts, session=False):
        """The one guard every context this crawl opens gets (BUG-0123, FR-CRAWL-12/13):
        scope, the destructive rule, the DELETE rule and the passive observer (which
        reads script bodies only in the crawl's own context). ``session``: the crawl's
        own authenticated context, whose route adds the session's headers to in-scope
        requests on the session's origins (FR-CRAWL-14); for an in-scope request on any
        other origin it aborts documents and WebSockets and fetches the rest through a
        cookie-less request context (FR-SESS-20, BUG-0134: an external crawl's scope is
        its host on every port, and the jar is port-agnostic); an unauthenticated
        context gets none of this."""
        from fuzzlab.tools.navguard import guard_page
        guard_page(context, allow=self._allow,
                   on_abort=self._note_guard_abort,
                   in_scope=self._in_scope, on_out_of_scope=self._note_out_of_scope,
                   method_refusal=functools.partial(self._method_refusal,
                                                    context=context),
                   observe=functools.partial(self._observe,
                                             scripts=scripts and self._spa_on),
                   headers=(self._auth_headers or None) if session else None,
                   header_scope=self._header_scope if session else None,
                   cookie_scope=self._cookie_scope if session else None,
                   on_session_withheld=self._note_session_withheld if session else None,
                   isolated_request=self._isolated_request if session else None,
                   # the reveal window (W2, W3): every context this crawl opens
                   window=functools.partial(self._window_refusal, context=context),
                   ws_hold=functools.partial(self._ws_hold, context),
                   on_ws_drop=self._note_ws_drop, on_ws_send=self._note_ws_send,
                   # CC-CRAWL-0036: what the window refused is recorded, never sent
                   on_window_refused=self._note_window_blocked)

    def _note_guard_abort(self, url, reason):
        """The guard aborted ``url`` (destructive, a refused method or body): recorded;
        while the reveal window is open it also counts as something the window
        aborted (W4's live probe). A probe load's URL (FR-CRAWL-17) is never recorded:
        it is blocked evidence of that probe only (review B-S1, A-M1)."""
        if self._probe is not None:
            self._probe["blocked"].add(url)
        else:
            self.skipped_destructive.setdefault(url, reason)
        if self._win is not None:
            self._win["aborted"] += 1
            if self._win.get("query"):
                self._win.setdefault("blocked", set()).add(url)

    # ----- the reveal window (forms phase 4: W1-W3) -----
    def _window_refusal(self, method, url, navigation, context=None):
        """W2: while the window is open, a request (from any context of this crawl) is
        aborted unless `spa.window_request_refusal` lets it through -- or it comes from
        the context whose vetted final submission lifted the window (W1), or it is the
        window's own reload of its route (GET, that route's URL, from that context).
        A refused GET/HEAD navigation's target is kept, to be queued through the normal
        gates; a refused non-GET navigation (an auto-submitted form) is a blocked write,
        never a page (CC-CRAWL-0029)."""
        win = self._win
        if win is None:
            return None
        if win["lifted_for"] is not None and context is win["lifted_for"]:
            return None
        if navigation and method in ("GET", "HEAD") and context is win["context"] \
                and _nav_key(url) in win["own_nav"]:
            return None
        why = spa.window_request_refusal(method, url, navigation)
        if why is None:
            return None
        win["aborted"] += 1
        # P2 (review B-S2): in a query window a refused GET navigation's target (a
        # redirect hop included) passes the window's GET word rules before it is
        # queued; a target they refuse (a transaction or account GET) is a blocked
        # write, never queued
        word_nav = bool(win.get("query")) and navigation and \
            method in ("GET", "HEAD") and \
            spa.window_request_refusal(method, url, False) is not None
        if win.get("query"):
            # FR-CRAWL-17 (review A-M1): a seed records whether it blocked a write; a
            # probe's blocked requests are never evidence; a blocked URL is never queued
            # from the load's request list (it would be fetched outside the window)
            win.setdefault("blocked", set()).add(url)
            if self._probe is not None:
                self._probe["blocked"].add(url)
            # a write (review round 2, U1): every refused non-GET/HEAD, a navigation (an
            # auto-submitted form) included, and every non-navigation GET the window's
            # word rules refused (a transaction or account GET)
            if method not in ("GET", "HEAD") or not navigation or word_nav:
                self._count_query_write(win, method, url)
        if navigation and method in ("GET", "HEAD") and not word_nav:
            win["navs"].append(url)
        else:
            # one rule for both windows (CC-CRAWL-0029): a refused non-GET navigation (an
            # auto-submitted form) is a blocked write, never a page -- its target is not
            # queued as a GET. A seed or probe load's window (FR-CRAWL-17, Q4) counts its
            # own
            self.spa_counts["spa_query_writes_blocked" if win.get("query")
                            else "reveal_writes_blocked"] += 1
        return why

    def _ws_hold(self, context):
        """W3: hold (drop) a page-to-server WebSocket message while the window is open,
        unless the window was lifted for ``context``'s vetted submission."""
        win = self._win
        return win is not None and not (win["lifted_for"] is not None
                                        and context is win["lifted_for"])

    def _note_ws_drop(self, url, message=None):
        self.spa_counts["reveal_ws_dropped"] += 1
        if self._win is not None:
            self._win["aborted"] += 1
            if self._win.get("query"):
                # a held page-to-server WebSocket message is a write (U1); its text is
                # read for the load's query values (B2)
                self._count_query_write(self._win, "WS", url, message)

    def _note_ws_send(self, url):
        """P1(b): a page-to-server WebSocket message forwarded outside any window; one
        sent while a page loads (`_recording`) joins that route's baseline."""
        if self._recording:
            self._load_writes.add(_write_key("WS", url))

    def _count_query_write(self, win, method, url, text=None):
        """A write in a query window (U1), unless the bare route's own loads made the
        same one outside any window (P1(b): the app shell's start-up or periodic writes,
        Juice Shop's socket.io polling POST and WebSocket pings): that one is blocked
        all the same, counted ``spa_query_baseline_writes``, and does not demote the
        seed.

        A realtime transport's **control** packet -- an engine.io ping, pong, upgrade,
        noop or probe, or a bare socket.io connect/disconnect, sent on a transport
        WebSocket (`spa.is_transport_url`, `spa.engineio_control`) -- is background
        traffic wherever it is seen (CC-CRAWL-0034): whether the bare route's load
        happened to send one is timing, so it is baseline even when the recorded load
        saw none. Blocked all the same. A socket.io event (``42[...]``), a polling POST
        (its body is not seen here) and any write carrying the load's values (B2) are
        judged as before (CC-CRAWL-0039, review M4)."""
        if _carries(win.get("taint", ()), url, text) or url in win.get("tainted", ()):
            # B2 (review A-S1 = B-S1): a write carrying this load's own query values
            # always counts, a baseline endpoint's included
            win["writes"] = win.get("writes", 0) + 1
            return
        if _write_key(method, url) in win.get("baseline", ()) or \
                ((method or "").upper() == "WS" and spa.is_transport_url(url)
                 and spa.engineio_control(text)):
            self.spa_counts["spa_query_baseline_writes"] += 1
            held = win.setdefault("baselined", {})
            held[url] = held.get(url, 0) + 1
            return
        win["writes"] = win.get("writes", 0) + 1

    def _note_tainted(self, win, url):
        """B2: the page's request to ``url`` carried this load's query values (seen by
        the ``request`` event, with its body). A write already set aside as a baseline
        one is counted after all, whichever event came first."""
        win.setdefault("tainted", set()).add(url)
        held = win.get("baselined", {}).pop(url, 0)
        if held:
            win["writes"] = win.get("writes", 0) + held

    @contextlib.contextmanager
    def _window(self, page, context, page_url, *, query=None):
        """The reveal window (W1): opened before the first reveal click or G1
        interaction; on exit the route is closed inside it -- ``Escape``, popups opened
        in it closed, the route reloaded (GET; `_restore`) -- and it is lifted only after
        a final quiet period (`_quiesce`: nothing in flight, then a round trip that
        flushes pending events). Re-entrant: a G1 inside a reveal uses the open window.
        If the close fails, every page the window opened is closed and the route's page
        is sent to ``about:blank`` (their timers die) before the window is lifted.

        ``query`` (FR-CRAWL-17, Q4): a seed (`spa.SEED_SOURCE`) or probe
        (`spa.PROBE_SOURCE`) load of ``page_url``. The window opens with ``own_nav`` set
        to that URL alone (`_goto_and_parse` clears it once the load has settled), and on
        exit the page **leaves** for ``about:blank`` inside the window (`_leave`) instead
        of `_restore`'s reload, which would replay the load's own on-load code."""
        if self._win is not None:
            yield self._win
            return
        win = {"context": context, "lifted_for": None, "own_nav": frozenset(),
               "aborted": 0, "navs": [], "restore_aborted": 0,
               "pages": list(getattr(context, "pages", []) or []), "query": query}
        if query:
            win["own_nav"] = frozenset({_nav_key(page_url)})
            # P1(b): what the bare route's own loads wrote outside any window
            win["baseline"] = frozenset(self._write_baseline.get(_route_key(page_url), ()))
            if self._authenticated:
                # U3 (review B2-M2): a check that never completes is a loss
                win["session"] = (False, "the session check did not complete")
        self._win = win
        try:
            yield win
        finally:
            try:
                win["lifted_for"] = None                  # lifted for one click only
                if query:
                    self._leave(page, page_url, win)
                else:
                    self._restore(page, page_url, win)
                self._quiesce(page)
                if query:
                    self._recheck_query_session(win)
                    win["closed"] = True             # U2: the window closed cleanly
            except PlaywrightError as exc:
                # M5: a probe's URL carries its markers, never logged (scrubbed)
                logging.info(spa.scrub_markers(
                    f"the reveal window could not close {page_url} cleanly "
                    f"({str(exc).splitlines()[0][:80]}); leaving the page"))
                # every page the window opened is closed, and the route's page left,
                # before the window is lifted: their timers die with them (review A-S1)
                self._close_window_pages(win, page)
                with contextlib.suppress(PlaywrightError):
                    navguard.navigate(page, "about:blank", timeout_ms=self.timeout_ms,
                                      wait_until="load")
                if query:
                    # Y3 (review B3-S3): the session re-check runs on this path too
                    self._recheck_query_session(win)
            finally:
                self._win = None
                if query == spa.SEED_SOURCE:
                    self._query_navs.extend(win["navs"])     # queued, normal gates

    def _restore(self, page, page_url, win):
        """Close what a reveal opened, inside the window (W1, G2c): ``Escape`` (never a
        dialog's own Cancel/Close button), close popups opened in the window, then
        reload the route (a GET navigation the window lets through for this context and
        this URL only) and let it settle. A dialog's timers die with the reload."""
        page.keyboard.press("Escape")
        page.wait_for_timeout(100)
        self._close_window_pages(win, page)
        before = win["aborted"]
        win["own_nav"] = frozenset({_nav_key(page_url)})
        try:
            if spa.visit_key(page.url) != spa.visit_key(page_url):
                navguard.navigate(page, page_url, timeout_ms=self.timeout_ms)
            if not navguard.reload(page, timeout_ms=self.timeout_ms).reached:
                # the route's reload did not complete (a refused script navigation
                # stopped it): the page leaves, so nothing of that stopped document
                # runs on (BUG-0138 review B-N1)
                navguard.navigate(page, "about:blank", timeout_ms=self.timeout_ms,
                                  wait_until="load")
            self._settle(page)
        finally:
            win["own_nav"] = frozenset()
            win["restore_aborted"] += win["aborted"] - before

    def _leave(self, page, page_url, win):
        """The exit of a seed or probe window (FR-CRAWL-17, Q4): a seed's same-document
        route change (``location.hash`` set on load) is kept as a navigation to queue;
        popups opened in the window are closed; the page leaves for ``about:blank``
        inside the window, so the load's timers die and nothing it scheduled runs after
        the lift. What the window aborted while leaving is counted with the rest
        (``spa_query_writes_blocked``)."""
        win["own_nav"] = frozenset()
        url = page.url or ""
        # M6 (BUG-0136 review B-S3): the page shows this load only when its navigation
        # was this load's (`_doc_url`) and it is a document of the app -- not
        # ``about:blank`` after a failed load (X1), nor an error page
        committed = self._load_committed and self._doc_url == page_url and \
            url.lower().startswith(("http://", "https://"))
        if self._authenticated:
            # S10 (review B-S4): the client-side session check (no network), on the
            # load's own page, before it leaves; a loss stops seed and probe loads. Any
            # failure of the check itself is a loss (U3); the page still leaves. M7: a
            # load that did not commit left no page of the app to read localStorage
            # from, so the cookie half and the server's verdict decide instead.
            try:
                if committed:
                    win["session"] = self._client_session_intact()
                else:
                    ok, why = self._cookies_intact()
                    win["session"] = self._live_session_intact() if ok else (ok, why)
            except Exception as exc:  # noqa: BLE001 - fail closed: recorded as a loss
                win["session"] = (False, f"the session check failed "
                                         f"({type(exc).__name__})")
        if win.get("query") == spa.SEED_SOURCE and committed and \
                spa.visit_key(url) != spa.visit_key(page_url):
            win["navs"].append(url)
        self._close_window_pages(win, page)
        navguard.navigate(page, "about:blank", timeout_ms=self.timeout_ms,
                          wait_until="load")

    def _recheck_query_session(self, win):
        """After a seed or probe window's quiet period (U4, review B2-S1/S2), in an
        authenticated crawl: the cookie half of the session check again -- a response
        that landed while the page left may have cleared a credential cookie -- and,
        when the window blocked a write, the server's own verdict (`verify_live`, as W4
        does after an abort). A failure of either check is a loss."""
        if not self._authenticated or not win.get("session", (False, None))[0]:
            return
        try:
            ok, why = self._cookies_intact()
            if ok and win.get("writes"):
                ok, why = self._live_session_intact()
        except Exception as exc:  # noqa: BLE001 - fail closed: recorded as a loss
            ok, why = False, f"the session re-check failed ({type(exc).__name__})"
        if not ok:
            win["session"] = (False, why)

    @staticmethod
    def _close_window_pages(win, page):
        """Close every page opened while the window was open (popups), errors
        suppressed."""
        for extra in list(getattr(win["context"], "pages", []) or []):
            if extra not in win["pages"] and extra is not page:
                with contextlib.suppress(PlaywrightError):
                    extra.close()

    def _quiesce(self, page):
        """The final quiet period before the window is lifted (W1): settle, flush the
        driver's pending events with a round trip, and settle again (bounded) while a
        request is still in flight."""
        self._settle(page)
        for _ in range(2):
            page.evaluate("() => 0")
            if self._inflight.get(id(page), 0) == 0:
                return
            self._settle(page)

    def _lift_for(self, context):
        """``click_vetted``'s ``before_click``: lift the window for ``context``'s one
        vetted final submission (W1)."""
        def lift():
            self._click_attempted = True
            if self._win is not None:
                self._win["lifted_for"] = context
        return lift

    def _track(self, page):
        """Count a page's requests in flight, so a settle waits for the app's own XHRs
        (a hash-route change or a click leaves the page's load state as it was).

        Realtime transport requests are not counted (`_background_request`,
        CC-CRAWL-0035): a socket.io long-poll or an event stream stays open by design,
        so counting it held every settle to its budget."""
        key = id(page)
        self._inflight[key] = 0

        def up(request):
            if not _background_request(request):
                self._inflight[key] = self._inflight.get(key, 0) + 1

        def down(request):
            if not _background_request(request):
                self._inflight[key] = max(0, self._inflight.get(key, 0) - 1)
        page.on("request", up)
        page.on("requestfinished", down)
        page.on("requestfailed", down)

    def _settle(self, page, budget_ms=None):
        """Let ``page``'s requests finish: three quiet 100 ms polls in a row, bounded."""
        budget = min(self.timeout_ms, 5000) if budget_ms is None else budget_ms
        deadline = time.monotonic() + budget / 1000
        quiet = 0
        while time.monotonic() < deadline and quiet < 3:
            page.wait_for_timeout(100)
            quiet = quiet + 1 if self._inflight.get(id(page), 0) == 0 else 0

    def _method_refusal(self, method, url, context=None):
        """FR-CRAWL-12 (reviewer A6): the crawl never deletes. A browser-initiated DELETE
        is aborted unless it comes from a submission on a route the operator named with
        ``--submit-spa-forms``, **from the context doing that click** (``context`` is the
        context whose guard asks; the crawl context's background requests during an
        unauthenticated context's click are still refused, lane S review), and **once per
        click** (a button deletes one thing; a background poller in the clicking context
        gets at most that one); each abort is counted."""
        if method != "DELETE":
            return None
        if self._delete_ok_for is not None and context is self._delete_ok_for:
            self._delete_ok_for = None                   # single use
            return None
        self.spa_counts["deletes_blocked"] += 1
        return "browser-initiated DELETE"

    def _on_request(self, request):
        try:
            if self._recording and self._win is None:
                # P1(b): what this load would have written inside a query window
                method = (request.method or "").upper()
                navigation = request.is_navigation_request()
                if (method not in ("GET", "HEAD") or not navigation) and \
                        spa.window_request_refusal(method, request.url,
                                                   navigation) is not None:
                    self._load_writes.add(_write_key(method, request.url))
            win = self._win
            if win is not None and win.get("taint"):
                body = request.post_data_buffer
                if _carries(win["taint"], request.url, body):
                    self._note_tainted(win, request.url)
            if self._probe is not None:
                # FR-CRAWL-17 (Q5): a probe load's requests -- aborted ones included,
                # this event comes before the route -- are correlated in memory only
                body = request.post_data_buffer or b""
                self._probe["requests"].append(
                    (request.url, body[:65536].decode("utf-8", "replace")))
                return                         # blocked ones are marked at the read
            if request.resource_type in ("xhr", "fetch"):
                self._xhr_urls.append(request.url)
                win = self._win
                if win is not None and win.get("query"):
                    # M8: in flight until it finishes or fails (Y1's late-failure race)
                    flight = win.setdefault("inflight", {})
                    flight[request.url] = flight.get(request.url, 0) + 1
        except Exception:
            pass  # never let instrumentation break a crawl

    def _on_request_finished(self, request):
        """M8: a query load's request is no longer in flight."""
        try:
            flight = (self._win or {}).get("inflight")
            if flight and flight.get(request.url):
                flight[request.url] -= 1
                if not flight[request.url]:
                    del flight[request.url]
        except Exception:
            pass  # never let instrumentation break a crawl

    def _on_request_failed(self, request):
        """FR-CRAWL-17 (Y1, review A3-S1 / B3-S1): while a seed or probe window is open,
        every request of the page that failed is blocked for that window -- among them a
        request whose redirect **hop** the window refused (the original request fails
        when its hop is aborted, and only the original is in the load's request list), so
        it is never queued and fetched later outside the window, nor evidence."""
        try:
            win = self._win
            if win is not None and win.get("query"):
                win.setdefault("blocked", set()).add(request.url)
                if self._probe is not None:
                    self._probe["blocked"].add(request.url)
            self._on_request_finished(request)
        except Exception:
            pass  # never let instrumentation break a crawl

    # ----- passive observation (forms phase 3) -----
    def _observe(self, request, response, *, scripts):
        """Called by the guard for each request it sent (FR-CRAWL-12/13): a same-origin
        script body is scanned for routes (crawl context only); a fetch/XHR request with a
        body is captured. Nothing is requested here: both come from what the browser
        already loaded. A probe load (FR-CRAWL-17) is never observed: it records
        nothing."""
        if self._probe is not None:
            return
        rtype = request.resource_type
        if rtype == "script":
            if scripts:
                self._note_script(request.url, response)
            return
        if rtype not in ("xhr", "fetch"):
            return
        method = request.method.upper()
        if method in ("GET", "HEAD", "OPTIONS"):
            return
        if spa.is_transport_url(request.url):
            self.spa_counts["transport_urls_skipped"] += 1
            return
        body = request.post_data_buffer
        if not body:
            return
        # the media type of Content-Type and the allowlisted non-secret headers are kept
        # (`redact_captured_headers`, CC-CRAWL-0037); a cookie or credential header never
        content_type = (request.headers or {}).get("content-type", "")
        why = self.storage.record_request(self._capture_page or self._current_url, method,
                                          request.url, content_type, body,
                                          self._capture_source, headers=request.headers)
        if why is None:
            self.spa_counts["requests_captured"] += 1
        elif why != "duplicate":
            self.spa_counts["requests_not_recorded"] += 1
            logging.info(f"captured request {method} {request.url.split('?', 1)[0]} not "
                         f"recorded ({why})")

    def _note_window_blocked(self, request):
        """A write the reveal window refused before it was sent
        (CC-CRAWL-0036, survey option 3): recorded as a discovered request with source
        `BLOCKED_SOURCE` -- method, URL, body and media type through the one capture
        boundary (`StorageManager.record_request`, PA-0100) -- and never sent. The
        import's rules decide whether it becomes a point, as for a captured one
        (FR-AUD-22). A navigation write (an auto-submitted form, a picker POST) is kept
        too. Not kept: a GET/HEAD/OPTIONS (a read; a GET navigation's target is queued
        as before), a transport URL, a body-less write, and anything a seed or probe
        load's window refused (CC-CRAWL-0039: a query load's write is never replayed,
        FR-CRAWL-17 -- it is caused by our own query value, and M6 or the fuzzer would
        send it outside any window; a probe records nothing)."""
        if self._probe is not None or (self._win or {}).get("query"):
            return
        method = (request.method or "").upper()
        if method in ("GET", "HEAD", "OPTIONS") or spa.is_transport_url(request.url):
            return
        body = request.post_data_buffer
        if not body:
            return
        content_type = (request.headers or {}).get("content-type", "")
        why = self.storage.record_request(self._capture_page or self._current_url, method,
                                          request.url, content_type, body, BLOCKED_SOURCE,
                                          headers=request.headers)
        if why is None:
            self.spa_counts["requests_blocked_recorded"] += 1
        elif why != "duplicate":
            self.spa_counts["requests_not_recorded"] += 1
            logging.info(spa.scrub_markers(
                f"blocked request {method} {request.url.split('?', 1)[0]} not recorded "
                f"({why})"))

    def _note_script(self, url, response):
        """Scan one already-loaded script for route declarations, if it is same-origin
        with the page, under the size cap, and within the per-page script cap."""
        if response.status != 200:
            return
        if canonical_origin(url) != canonical_origin(self._doc_url):
            return                                    # cross-origin scripts are not read
        key = url.split("#", 1)[0]
        if key in self._scripts_seen:
            return
        self._scripts_seen.add(key)
        if self._page_scripts >= spa.MAX_SCRIPTS_PER_PAGE:
            self.spa_counts["scripts_over_page_cap"] += 1
            return
        self._page_scripts += 1
        declared = (response.headers or {}).get("content-length")
        if declared and declared.isdigit() and int(declared) > spa.MAX_SCRIPT_BYTES:
            self.spa_counts["scripts_too_large"] += 1
            return
        body = response.body()
        # one scan of the body for routes and query parameters (FR-CRAWL-17, Q1)
        found = spa.scan_script(body.decode("utf-8", "replace")) \
            if len(body) <= spa.MAX_SCRIPT_BYTES else None
        if found is None:
            self.spa_counts["scripts_too_large"] += 1
            return
        routes, query = found
        self.spa_counts["scripts_scanned"] += 1
        self._pending_routes.extend(routes)
        if self._query_on:
            self._note_query_scan(query)

    def _stop_browser(self):
        try:
            if self._context is not None:
                from fuzzlab.tools.navguard import release
                release(self._context)
            for ctx in self._isolated_requests:          # R2's cookie-less contexts
                with contextlib.suppress(Exception):
                    ctx.dispose()
            if self._browser:
                self._browser.close()
        finally:
            if self._pw:
                self._pw.stop()

    #: Loopback aliases treated as one host, so the lab can link between
    #: `localhost` and `127.0.0.1` (and IPv6 loopback) without being dropped.
    _LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})

    @staticmethod
    def _norm_host(url):
        """Hostname, lowercased, with a leading ``www.`` stripped (apex and
        ``www`` count as the same host). Uses hostname, not netloc, so a port
        such as ``:8080`` never affects scope."""
        host = (urlparse(url).hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        return host

    def _in_scope(self, url):
        """Whether a discovered link is in scope to follow.

        Scope is the **start URL's own host** — the single target the operator
        pointed the crawler at. This both keeps the crawler from escaping to the
        open web (third-party domains, CDNs, social links are never followed —
        the safety intent of the former localhost-only guard) and lets it
        actually crawl whatever authorized host it was started on, loopback lab
        or otherwise (previously it silently dropped every non-loopback link, so
        a real target yielded zero followed links). ``www.`` is normalised on both
        sides. A **loopback** start is scoped to its exact origin (BUG-0123): loopback
        aliases on the same port are one origin, another port is another service.
        This one predicate gates the link queue, redirects, the browser's every
        request (``guard_page``) and the API-request client.
        """
        if self._scope_host in self._LOOPBACK:
            # A loopback start is one service: its exact origin (scheme, host, port),
            # aliases folded by canonical_origin. Another loopback port is another
            # service the operator did not name (BUG-0123).
            return in_origin_scope(url, self._scope_origins)
        host = self._norm_host(url)
        if not host:
            return False
        return host == self._scope_host

    def _note_out_of_scope(self, url):
        if self._probe is not None:
            self._probe["blocked"].add(url)          # FR-CRAWL-17: never evidence
        host = urlparse(url).hostname or "?"
        self.skipped_out_of_scope[host] = self.skipped_out_of_scope.get(host, 0) + 1

    #: Why an in-scope page on another origin than the session's is not crawled.
    OTHER_ORIGIN_REASON = ("another origin than the session's: crawl that origin "
                           "separately, or pass --auth-origin if it is this app's "
                           "(FR-SESS-20)")

    def _note_session_withheld(self, url, kind="request", source=None):
        """An in-scope request went without the session (another origin, FR-SESS-20). A
        document, landing, frame or WebSocket there is never loaded (R1): recorded as
        skipped, with its kind (T6). Only a page navigation whose **own** target or
        redirect landing was withheld (``source`` is that target) extracts nothing (T1):
        a script-initiated navigation away, aborted with ERR_ABORTED, leaves the page
        where it was, and it is extracted normally."""
        self.session_out_of_origin += 1
        if self._probe is not None:
            # FR-CRAWL-17 (M1): a probe's URL carries markers: blocked evidence of that
            # probe only, never recorded as skipped nor logged
            self._probe["blocked"].add(url)
            return
        if kind in ("document", "landing", "frame", "websocket"):
            if kind in ("document", "landing"):
                self._withheld_targets.add(url_key(source or url))
            if url not in self.skipped_other_origin:
                self.skipped_other_origin[url] = f"{kind}: {self.OTHER_ORIGIN_REASON}"
                logging.info(f"skipped {url} ({kind}): {self.OTHER_ORIGIN_REASON}")

    def _isolated_request(self):
        """A cookie-less, storage-less request context for the guard's withheld fetches
        (FR-SESS-20, R2); disposed when the browser stops."""
        ctx = self._pw.request.new_context()
        self._isolated_requests.append(ctx)
        self.isolated_contexts_created += 1
        return ctx

    def _other_origin(self, url):
        """Is ``url`` outside the authenticated session's origins (FR-SESS-20)?"""
        return self._cookie_scope is not None and self._in_scope(url) and \
            not self._cookie_scope(url)

    # ----- fetchers -----
    def _fetch_static(self, url):
        """No JavaScript. Parses the raw HTML with BeautifulSoup. Redirects are
        followed by hand, each hop in scope and not destructive (BUG-0111)."""
        from fuzzlab.tools.navguard import get_checked
        resp = get_checked(self.session, url, self.timeout_ms / 1000,
                           lambda nxt: self._in_scope(nxt) and not self._destructive(nxt))
        ct = resp.headers.get('Content-Type', '')
        title, text, links = None, None, []
        self._last_final_url = getattr(resp, "url", None) or url
        self._last_html = resp.text if 'text/html' in ct else None
        if 'text/html' in ct:
            title, text, links = _parse_html(resp.text)
        return resp.status_code, ct, title, text, links, []

    def _fetch_rendered(self, url, fallback=True):
        """Renders with headless Chromium, then reads links and text from the live DOM.

        Chromium refuses to navigate to some responses (downloads,
        application/octet-stream). Those URLs still belong in the map, so the
        crawler falls back to a plain request rather than dropping them.
        """
        self._xhr_urls = []   # collected by _on_request during this navigation
        self._rendered_ok = False
        self._withheld_targets = set()
        try:
            result = self._goto_recording(url)
        except Exception as e:
            # BUG-0136 review (X1): a failed load ends the previous document. A refused
            # navigation is aborted with ERR_ABORTED, which leaves the page shown before
            # it alive; its timers and fetches would otherwise run on and be sent and
            # captured under the URLs crawled next
            with contextlib.suppress(PlaywrightError):
                navguard.navigate(self._page, "about:blank", timeout_ms=self.timeout_ms,
                                  wait_until="load")
            if self._navigation_withheld(url):
                # this navigation's own target or its redirect landing is on another
                # origin than the session's (R1, T1): nothing is extracted, and no
                # static fallback (it would file that origin's page under this URL)
                raise SessionWithheld(url) from None
            if not fallback:
                # FR-CRAWL-17 (M4): a seed's load failed inside its window; a static
                # request would send it again outside the window, so it fails instead
                raise
            logging.info(f"Browser could not render {url} ({str(e).splitlines()[0][:80]}); "
                         f"falling back to a static request")
            return self._fetch_static(url)
        if self._navigation_withheld(url):
            raise SessionWithheld(url)            # committed off the session's origins
        return result

    def _navigation_withheld(self, url):
        """Did this page navigation meet another origin than the session's (FR-SESS-20,
        T1)? Its own target or redirect landing was withheld by the route, or the main
        frame committed on an **in-scope** origin outside the session's. A
        script-initiated navigation away that the route aborted is neither: the page
        stays (ERR_ABORTED, BUG-0136), and is extracted. An out-of-scope committed URL
        is BUG-0123's scope abort, already counted under its own reason
        (`skipped_out_of_scope`), never FR-SESS-20's (review round 3, V2). After a
        failed `goto` the page has already been sent to ``about:blank`` (BUG-0136
        review, X1), so there only the withheld targets decide."""
        if self._cookie_scope is None:
            return False
        if url_key(url) in self._withheld_targets:
            return True
        try:
            committed = self._page.url if self._page is not None else ""
        except Exception:  # noqa: BLE001 - a closed page: nothing committed here
            return False
        return bool(committed) and self._other_origin(committed)

    def _goto_recording(self, url):
        """`_goto_and_parse`; outside any window, the writes a load of a **bare** route
        makes (what a query window would have counted) join that route's baseline
        (P1(b)); a load of a URL with its own query never does (B1)."""
        self._load_writes = set()
        self._recording = self._win is None and _is_bare_route(url)
        try:
            return self._goto_and_parse(url)
        finally:
            if self._recording:
                self._recording = False
                self._write_baseline.setdefault(_route_key(url), set()).update(
                    self._load_writes)

    def _goto_and_parse(self, url):
        self._last_final_url, self._last_html, self._last_base = url, None, None
        self._load_committed = False                    # P4 (B-N1): set once it commits
        self._doc_url, self._page_scripts, self._pending_routes = url, 0, []
        # BUG-0138: the commit, then a bounded load (navguard.navigate): a refused own
        # target still raises; a load a refused script navigation superseded is not
        # waited out
        nav = navguard.navigate(self._page, url, timeout_ms=self.timeout_ms)
        response = nav.response
        same_document = response is None and spa.spa_fragment(url) is not None
        if same_document:
            # a hash-route change in the loaded app: no new document, no response; the
            # document's own status stands, and the app's XHRs are waited for
            status, ct = self._last_doc
        else:
            status = response.status if response else 0
            ct = (response.headers or {}).get('content-type', '') if response else ''
            if response:
                self._last_doc = (status, ct)

        title, text, links = None, None, []
        own = True                     # a non-HTML response: the page shows it (merge)
        if 'text/html' in ct or ct == '':
            # Let JavaScript-driven fetch()/render settle (best effort), unless the load
            # never completed (its loading stopped: nothing more will settle)
            if nav.reached:
                navguard.wait_for_state(self._page, "networkidle", self.timeout_ms)
            if same_document:
                self._settle(self._page)
            if self._win is not None and self._win.get("query"):
                self._win["own_nav"] = frozenset()   # the load's own navigation only (Q4)
            # BUG-0138 review (Q2): a load that did not complete either stopped (a
            # refused script navigation superseded it), merely outlasted the wait, or
            # was replaced by another document a script navigation committed
            own = nav.reached or navguard.shows_own_document(self._page, url, response)
            if own:
                title = self._page.title()
                self._last_final_url = self._page.url
                self._last_html = self._page.content()
                if self._spa_on:
                    self._last_base = self._page.evaluate(
                        "() => document.querySelector('base') ? document.baseURI : null")
                # Links and text come from the RENDERED DOM, so JS-injected nav links
                # and JS-built content are included.
                links = self._page.eval_on_selector_all('a[href]',
                                                        'els => els.map(e => e.href)')
                try:
                    # read, never waited for: a document whose loading stopped in its
                    # head has no body, and `inner_text('body')` would wait 30 s for one
                    text = self._page.evaluate(
                        "() => document.body ? document.body.innerText : null")
                except Exception:
                    text = None
            if not nav.reached and response is not None:
                # BUG-0138: what the browser received for this navigation, read as the
                # static engine reads a page -- never a second request
                html = nav.html
                if html is not None:
                    got_title, got_text, got_links = _parse_html(html)
                    if not own:
                        # another document replaced this one: this URL's own response
                        # alone, never the other document's title, links or URL
                        title, text, links = got_title, got_text, got_links
                        self._last_final_url, self._last_html = url, html
                    elif nav.superseded:
                        # its parsing stopped: the response holds the document; the
                        # DOM's links (JS-built ones) are kept with it
                        title, text = title or got_title, got_text
                        links = list(dict.fromkeys(list(links) + got_links))
                        self._last_html = html
                    elif not text:
                        # merely slow: the DOM stands (JS-rendered text included); the
                        # response fills an empty text only
                        text = got_text
            elif not own:
                self._last_final_url = url              # nothing of the other document
            # the browser shows this page, fully loaded (reveals)
            self._rendered_ok = nav.reached
        # P4 (review B-N1): the navigation committed (a document, or a same-document
        # hash change), recorded after the navigation returned, never before it -- and
        # only while the page shows this load's own document (BUG-0138 merge)
        self._load_committed = (response is not None or same_document) and own
        return status, ct, title, text, links, list(dict.fromkeys(self._xhr_urls))

    # ----- landing URLs, forms, selector navigation (forms phase 1) -----
    def _after_fetch(self, url, status, depth, title, content):
        """Record where a redirect landed and every form on the page; enumerate allowed
        selector forms. Returns more ``(url, depth, source)`` to queue."""
        from fuzzlab.core.redaction import redact_url
        more = []
        final = self._last_final_url
        landing = self._crawl_url(final) if final else None
        # a seed (FR-CRAWL-17) runs in its window: its landing is queued by `_leave`, and
        # it neither reveals nor submits (the bare route's visit does)
        seed = self._win is not None and bool(self._win.get("query"))
        if (landing and not seed and spa.visit_key(landing) != spa.visit_key(url)
                and self._in_scope(landing) and not self._destructive(landing)):
            # the landing URL keeps its query (xss_eval.php?date=Date()), redacted
            self.storage.mark_visited(redact_url(landing), status, depth,
                                      title, content, source='redirect')
        if self._spa_on and self.engine == "playwright":
            more += self._queue_routes(final or url, depth)
            if (self._submit_routes is not None and self._last_html is not None
                    and self._is_spa_page(url) and not seed):
                self._submit_spa_forms(final or url)
        if self._reveal_on and self._last_html is not None and self._rendered_ok \
                and not seed:
            # G2 (FR-CRAWL-16): menus, dialogs and drawers, inside the reveal window
            more += self._reveal_page(final or url, depth)
            if self._spa_on:
                more += self._queue_routes(final or url, depth)  # scripts a reveal loaded
        if not self._last_html:
            return more
        from fuzzlab.core.forms import form_record
        page = final or url
        for form in BeautifulSoup(self._last_html, 'html.parser').find_all('form'):
            record = form_record(form, page)
            if seed:
                # FR-CRAWL-17 (P1 follow-up): a seed's forms go with the seed -- stored
                # only once its window closed cleanly with no write (fail closed: a form
                # its query rendered and auto-submitted is that blocked write), and never
                # enumerated (a seed neither reveals nor submits)
                self._win.setdefault("forms", []).append(record)
                continue
            self.storage.record_form(record)
            if self._selector_forms is None or not record["selector"] or depth >= self.max_depth:
                continue
            from fuzzlab.tools import formnav
            sig = formnav.signature(record)
            if sig in self._enumerated:
                continue
            self._enumerated.add(sig)
            why = formnav.refusal(record, self._selector_forms, True, self._in_scope)
            if why:
                logging.info(f"selector form on {page} not submitted: {why}")
                continue
            key = formnav.signature_key(record)
            for target in formnav.enumerate_form(
                    record, self._isolated_submit, self._in_scope,
                    on_verdict=lambda v, k=key: self.storage.record_verdict(k, v)):
                if not self._destructive(target) and not self.storage.is_visited(target):
                    more.append((target, depth + 1, 'form'))
        return more

    # ----- SPA routes (forms phase 3, FR-CRAWL-12) -----
    def _is_spa_page(self, url):
        """A SPA route page: a route fragment, or a history-mode route found in a
        script."""
        return spa.spa_fragment(url) is not None or spa.visit_key(url) in self._route_keys

    def _queue_routes(self, page_url, depth):
        """Turn the routes the page's scripts declared into pages to crawl: hash mode
        when the page or its links use ``#/`` (or ``#!/``), else history mode under the
        page's ``<base>`` or the start URL's directory. Parameterised, wildcard and
        destructive routes are skipped and counted."""
        routes, self._pending_routes = self._pending_routes, []
        pairs, self._pending_pairs = self._pending_pairs, {}
        if not routes and not pairs:
            return []
        frag = spa.spa_fragment(page_url) or ""
        hrefs = []
        try:
            hrefs = self._page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')
        except PlaywrightError:
            pass
        link_frags = [spa.spa_fragment(h) for h in hrefs]
        hash_mode = bool(frag) or any(f is not None for f in link_frags)
        hashbang = frag.startswith("!/") or any(f and f.startswith("!/") for f in link_frags)
        base = self._last_base or self._app_base
        more = []
        for path in routes:
            kind, reason = spa.classify_route(path)
            if kind in spa.NOT_ROUTES:                       # not counted as found
                continue
            name = spa.normalise_route(path)
            if name in self._route_names:
                continue
            self._route_names.add(name)
            self.spa_counts["routes_found"] += 1
            if kind == spa.ROUTE_PARAM:
                self.spa_counts["routes_skipped_parameterised"] += 1
                logging.info(f"SPA route {name!r} skipped: parameterised or wildcard")
                continue
            if kind == spa.ROUTE_DESTRUCTIVE:
                self.spa_counts["routes_skipped_destructive"] += 1
                logging.info(f"SPA route {name!r} skipped: destructive ({reason!r})")
                continue
            target = spa.route_url(page_url, path, hash_mode=hash_mode, hashbang=hashbang,
                                   base=base)
            self._route_keys.add(spa.visit_key(target))
            if self._query_on:
                self._probe_routes.setdefault(name, (target, depth + 1))   # Q5
            if depth >= self.max_depth:
                continue
            if (self._in_scope(target) and not self._destructive(target)
                    and not self.storage.is_visited(target)):
                more.append((target, depth + 1, 'spa-route'))
        # FR-CRAWL-17 (Q3): each paired route's seed, queued after the bare routes (B8)
        for path, names in pairs.items():
            kind, _reason = spa.classify_route(path)
            if kind != spa.ROUTE_OK:
                self._refuse_query({spa.ROUTE_PARAM: "parameterised route",
                                    spa.ROUTE_DESTRUCTIVE: "destructive route"}.get(
                                        kind, "not a route"))
                continue
            if depth >= self.max_depth:
                continue
            target = spa.route_url(page_url, path, hash_mode=hash_mode, hashbang=hashbang,
                                   base=base)
            more += self._queue_seed(target, names, depth + 1)
        return more

    # ----- route query parameters (forms phase 5, FR-CRAWL-17) -----
    def _note_query_scan(self, scan):
        """Take one script's `spa.QueryScan`: its pairs wait for `_queue_routes` (which
        knows the page's routing mode), its unpaired names for the probe; each pair and
        name is counted once per crawl, refusals by reason."""
        for route, names in scan.pairs.items():
            got = self._pending_pairs.setdefault(route, [])
            for name in names:
                key = (spa.normalise_route(route), name)
                if key not in self._query_pairs_seen:
                    self._query_pairs_seen.add(key)
                    self.spa_counts["spa_query_pairs"] += 1
                if name not in got:
                    got.append(name)
        for name in scan.unpaired:
            if name not in self._query_unpaired:
                self._query_unpaired[name] = None
                self.spa_counts["spa_query_unpaired"] += 1
        for reason, n in scan.refused.items():
            self._refuse_query(reason, n)
        if scan.budget_hit:
            self.spa_counts["spa_query_step_cap"] += 1

    def _refuse_query(self, reason, n=1):
        self.spa_query_refused[reason] = self.spa_query_refused.get(reason, 0) + n
        self.spa_counts["spa_query_refused"] += n

    def _query_gate(self, url):
        """Why a seed or probe URL is never loaded, as a counted reason class, or None:
        `spa.query_url_refusal` (the destructive rule, then the window's own rule as a
        GET, A-M1) and scope."""
        why = spa.query_url_refusal(url)
        if why is not None:
            logging.info(f"SPA query URL {url.split('?', 1)[0]} not loaded: {why}")
            return "destructive URL" if why.startswith("destructive") else \
                "write-window refusal"
        if not self._in_scope(url):
            return "out of scope"
        return None

    def _queue_seed(self, route_url, names, depth):
        """One seed for ``route_url``: its names not yet seeded there, each set to the
        filler (``/`` when redirect-ish), through `_query_gate` and the visit key (Q3).
        Returns the queue entries (at most one)."""
        done = self._seeded_names.setdefault(spa.visit_key(route_url), set())
        names = [n for n in names if n not in done]
        if not names:
            return []
        done.update(names)
        url = spa.seed_url(route_url, names)
        why = self._query_gate(url)
        if why is not None:
            self._refuse_query(why)
            return []
        key = spa.visit_key(url)
        if key in self._seed_keys or self.storage.is_visited(url):
            return []
        self._seed_keys.add(key)
        return [(url, depth, spa.SEED_SOURCE)]

    def _plan_probes(self):
        """When the queue drains (the bare routes are visited): one probe load per
        scanned route the crawl rendered and has not probed, at most
        `spa.MAX_QUERY_PROBE_ROUTES` per crawl (Q5). Nothing without unpaired names."""
        if not self._query_on or not self._query_unpaired or self._page is None \
                or self.spa_query_stopped:
            return []
        out = []
        for name, (url, depth) in self._probe_routes.items():
            if name in self._probed or not self.storage.is_visited(url):
                continue
            self._probed.add(name)
            if len(self._probed) > spa.MAX_QUERY_PROBE_ROUTES:
                self._refuse_query("probe route cap")
                continue
            out.append((url, depth, spa.PROBE_SOURCE))
        return out

    def _mint_probe(self, route_url):
        """The probe load for ``route_url`` with **fresh** markers (Q5, B2): every
        unpaired name not yet seeded there, at most `spa.MAX_UNPAIRED_NAMES`, all in one
        load, each with its own marker (``/`` for a redirect-ish name, B6), through the
        seed's gate. None when there is nothing to probe or the URL is refused."""
        done = self._seeded_names.get(spa.visit_key(route_url), set())
        names = [n for n in self._query_unpaired if n not in done]
        if len(names) > spa.MAX_UNPAIRED_NAMES:
            over = [n for n in names[spa.MAX_UNPAIRED_NAMES:]
                    if n not in self._names_over_cap]
            self._names_over_cap.update(over)
            if over:
                self._refuse_query("probe name cap", len(over))     # once per name
            names = names[:spa.MAX_UNPAIRED_NAMES]
        if not names:
            return None
        markers = spa.mint_markers(len(names))
        values = [spa.query_value(n, m) for n, m in zip(names, markers)]
        url = spa.query_url(route_url, list(zip(names, values)))
        why = self._query_gate(url)
        if why is not None:
            self._refuse_query(why)
            return None
        return {"url": url, "route_url": route_url, "names": names, "requests": [],
                "blocked": set(),
                "markers": {v: n for n, v in zip(names, values) if v != "/"}}

    def _finish_probe(self, probe, depth):
        """Read what a probe load showed, inside its window, and seed what it kept
        (Q5): the rendered DOM's strings (`spa.OBSERVE_JS`) and the load's own requests,
        attributed by `spa.observed_names` to this load's markers only. Nothing is
        recorded: the correlation stays in memory. Returns the kept pairs' seed."""
        try:
            texts = self._page.evaluate(spa.OBSERVE_JS, spa.MARKER_PREFIX)
        except PlaywrightError as exc:
            logging.info(f"probe of {probe['route_url']} could not be read "
                          f"({str(exc).splitlines()[0][:80]})")
            texts = []
        requests = [(u, b, u in probe["blocked"]) for u, b in probe["requests"]]
        frag = spa.spa_fragment(probe["url"])
        kept, in_path = spa.observed_names(
            texts, requests, probe["markers"], probe["names"],
            doc_path=urlparse(probe["url"]).path or "/",
            route="#" + frag.split("?", 1)[0] if frag is not None else None)
        self.spa_counts["spa_query_marker_in_path"] += in_path
        self.spa_counts["spa_query_kept"] += len(kept)
        names = [n for n in probe["names"] if n in kept]
        logging.info(f"SPA query probe of {probe['route_url']}: kept "
                     f"{', '.join(names) or 'none'} of {len(probe['names'])} name(s)")
        return self._queue_seed(probe["route_url"], names, depth) if names else []

    def _after_query_window(self, win, url, visited=True):
        """After a seed or probe window (FR-CRAWL-17). A seed is stored with source
        `spa.WRITE_SEED_SOURCE`, which the importer never turns into points, and is
        promoted to `spa.SEED_SOURCE` only here, after its window closed cleanly with no
        write (U2, fail closed: anything that stops the crawl before this keeps it a
        write seed). A seed that blocked a write stays one -- an M6 load of it would send
        that write unguarded (review A-M1; counted ``spa_query_write_seeds``). In an
        authenticated crawl, the window's session verdict (S10, U3, U4): on a loss, seed
        and probe loads stop for the crawl, and the session is re-adopted once on the
        start page; a re-adoption that does not hold stops reveals and submissions too
        (as W4)."""
        if win.get("query") and not win.get("closed"):
            self.spa_counts["spa_query_unclean_windows"] += 1     # Y2 (review B3-S2)
        if win.get("query") == spa.SEED_SOURCE:
            if visited and win.get("closed") and not win.get("writes"):
                self.storage.set_source(url, spa.SEED_SOURCE)
                for record in win.get("forms", ()):     # promoted: its forms with it
                    self.storage.record_form(record)
            else:
                # a write, an unclean close, or a failed visit (filed by the loop's
                # failure path): kept as a page, never a point (B3-N2: all counted)
                self.spa_counts["spa_query_write_seeds"] += 1
                logging.info(f"SPA query seed {url} blocked a write (or its window did "
                             f"not close cleanly, or its visit failed): kept as a page, "
                             f"never a point")
        ok, why = win.get("session", (not self._authenticated, "no session check"))
        if ok:
            return
        self.spa_counts["spa_query_session_losses"] += 1
        self.spa_query_stopped = f"the session was lost after a query load ({why})"
        logging.warning(f"SPA query loads stopped: {self.spa_query_stopped}")
        try:
            navguard.navigate(self._page, self.start_url, timeout_ms=self.timeout_ms)
            ok, again = self._readopt_session()
        except Exception as exc:  # noqa: BLE001 - fail closed: re-adoption did not hold
            ok, again = False, f"re-adoption failed ({type(exc).__name__})"
        if not ok:
            stop = f"the session could not be re-adopted after a query load ({again})"
            self.reveals_stopped = self.reveals_stopped or stop
            self.spa_submit_stopped = self.spa_submit_stopped or stop
            logging.warning(f"reveals and submissions stopped: {stop}")

    def _take_query_navs(self, depth):
        """The navigations a seed's window aborted or its load made (``location.hash``),
        through the normal queue gates (scope, destructive, visited, depth)."""
        navs, self._query_navs = self._query_navs, []
        more = []
        if depth >= self.max_depth:
            return more
        for href in navs:
            link = self._crawl_url(href)
            if (self._in_scope(link) and not self._destructive(link)
                    and not self.storage.is_visited(link)):
                more.append((link, depth + 1, "redirect"))
        return more

    # ----- SPA form submission (forms phase 3, FR-CRAWL-13) -----
    def _submit_spa_forms(self, page_url):
        """Fill and click, once per form signature, each eligible form on this SPA route.
        The gate is `spa.form_refusal`. A form with a password input is submitted only in
        a fresh unauthenticated context; in an authenticated crawl, any form is submitted
        in the crawl's own context only when its route was named. After each submission
        in an authenticated context the session is re-checked; on loss, submitting stops
        and is reported. At most `spa.MAX_SUBMISSIONS` per crawl."""
        if self.spa_submit_stopped:
            return
        route = spa.route_of(page_url, self._last_base or self._app_base)
        named = self._submit_routes or None
        try:
            forms = self._page.evaluate(spa.FORMS_JS, 20)
        except PlaywrightError as exc:
            logging.info(f"could not read the forms on {page_url} ({exc})")
            return
        stale = False
        for form in forms:
            sig = spa.form_signature(form)
            if sig in self._submitted_sigs:
                continue
            self._submitted_sigs.add(sig)
            why = spa.form_refusal(form, route, named=named)
            if why:
                self.spa_counts["forms_refused"] += 1
                logging.info(f"SPA form on {page_url} not submitted: {why}")
                continue
            if self.spa_counts["forms_submitted"] >= spa.MAX_SUBMISSIONS:
                self.spa_counts["submissions_over_cap"] += 1
                logging.info(f"SPA form on {page_url} not submitted: the crawl's "
                             f"{spa.MAX_SUBMISSIONS}-submission cap is reached")
                continue
            # the route was named (form_refusal refuses an unnamed one when routes are)
            explicit = named is not None
            anonymous = spa.has_password(form) or (self._authenticated and not explicit)
            if anonymous:
                self._submit_anonymously(page_url, sig, explicit)
                continue
            if stale:
                # an earlier submission (or G1's reload, W1) re-rendered the page: the
                # form is found again by its signature (its marks are gone)
                form = self._refind_form(self._page, sig)
                if form is None:
                    logging.info(f"SPA form on {page_url} no longer rendered: not "
                                 f"submitted")
                    continue
            stale = True
            if self._fill_and_click(self._page, self._context, form, page_url,
                                    explicit) and \
                    self._authenticated:
                intact, why = self._session_intact()
                if not intact:
                    self.spa_submit_stopped = (f"the crawl's session was lost after "
                                               f"submitting a form on {route!r} ({why})")
                    logging.warning(f"SPA form submission stopped: "
                                    f"{self.spa_submit_stopped}")
                    return

    def _fill_and_click(self, page, context, form, page_url, explicit):
        """Fill ``form``'s typed controls with our fillers and click its button once.
        Returns True when the click happened (counted). A DELETE it causes is allowed
        only on a named route (``explicit``) and only from ``context``.

        On a named route (``explicit``) this is constraint-aware (G1, FR-CRAWL-15) and
        runs entirely inside the reveal window (W1): the fill, every G1 interaction and
        the checks happen with the window's write block on; only the vetted final click
        lifts it, for that click (`spa.click_vetted`'s ``before_click``); the route is
        then closed and reloaded inside the window again."""
        if not explicit:
            return self._fill_and_click_now(page, context, form, page_url, explicit,
                                            g1=False)
        with self._window(page, context, page_url):
            return self._fill_and_click_now(page, context, form, page_url, explicit,
                                            g1=True)

    def _fill_and_click_now(self, page, context, form, page_url, explicit, *, g1):
        # CC-CRAWL-0038: a button-less container is submitted by Enter in its text
        # control, only inside the window (a named route, G1): with no button there is
        # no label to vet, so the route and control gates are all it has
        enter = form.get("submit_by") == "enter" and not form.get("button_id")
        if enter and not g1:
            self.spa_counts["forms_not_submittable"] += 1
            logging.info(f"SPA form on {page_url} not submittable (a button-less form is "
                         f"submitted by Enter only on a route named with "
                         f"--submit-spa-forms)")
            return False
        for (name, kind), cid in zip(form["controls"], form["ids"]):
            if not spa.fillable(kind) or (kind != "password"
                                          and spa.sensitive_control(name)):
                continue
            try:
                page.fill(f'[data-fuzzlab-id="{cid}"]', spa.filler(kind),
                          timeout=self.timeout_ms)
            except PlaywrightError:
                pass                                    # e.g. a range or read-only input
        button = form.get("enter_id") if enter else form.get("button_id")
        selector = f'[data-fuzzlab-id="{button}"]'
        if g1:
            try:
                why = self._g1(page, form)
            except PlaywrightError as exc:
                why = f"constraint-aware filling failed ({str(exc).splitlines()[0][:80]})"
            if why is not None:
                self.spa_counts["forms_not_submittable"] += 1
                logging.info(f"SPA form on {page_url} not submittable: {why}")
                return False
        try:
            if not button or not page.is_enabled(selector, timeout=self.timeout_ms):
                self.spa_counts["forms_not_submittable"] += 1
                why = "no enabled button"
                if g1 and button and not enter:
                    still = self._g1_invalid_names(page, form)
                    why = (f"invalid after {self._g1_attempts} attempts: "
                           f"{', '.join(still) or '(no control reports invalid)'}")
                    self.spa_counts["g1_forms_unsatisfiable"] += 1
                logging.info(f"SPA form on {page_url} not submittable ({why})")
                return False
        except PlaywrightError:
            self.spa_counts["forms_not_submittable"] += 1
            return False
        self._capture_source, self._capture_page = "submit", page_url
        self._delete_ok_for = context if explicit else None
        try:
            if enter:
                how = self._press_enter(page, selector, form, self._lift_for(context))
            else:
                how = self._click_vetted(page, selector, [
                    form.get("button") or "", form.get("button_aria") or "",
                    form.get("button_icons") or ""],
                    before_click=self._lift_for(context) if g1 else None)
            if how is None:
                logging.info(f"SPA form on {page_url} not clicked: its button's labels "
                             f"changed after the gate vetted them")
                return False
            self.spa_counts["forms_submitted"] += 1
            if enter:
                self.spa_counts["forms_submitted_enter"] += 1
            logging.info(f"submitted the SPA form {form.get('button')!r} on {page_url}"
                         + (" (Enter in its text control)" if enter else "")
                         + (" (click dispatched: the button was covered)"
                            if how == "dispatched" else ""))
            self._settle(page)
            return True
        except PlaywrightError as exc:
            self.spa_counts["forms_not_submittable"] += 1
            logging.info(f"SPA form on {page_url} could not be clicked "
                         f"({str(exc).splitlines()[0][:80]})")
            return False
        finally:
            self._capture_source, self._capture_page = "passive", None
            self._delete_ok_for = None
            if g1 and self._win is not None:
                # the lift covers exactly this one click and its settle (review B-M1):
                # whatever follows in the window -- a click that raised included --
                # runs with the write block and the WebSocket hold on again
                self._win["lifted_for"] = None

    # ----- G1: constraint-aware filling (forms phase 4, FR-CRAWL-15) -----
    def _g1_invalid_names(self, page, form):
        names = dict(zip(form["ids"], (n for n, _k in form["controls"])))
        infos = page.evaluate(spa.G1_READ_JS, list(form["ids"]))
        return [names.get(i["id"]) or i["id"] for i in infos
                if not i.get("missing") and i.get("invalid")]

    def _g1(self, page, form):
        """Make each invalid control valid with ladder values (G1a), inside the window.
        Returns None, or why the form is not submittable: a sensitive or credential-like
        control that is invalid (G1b; never filled), an object-selector or identifier
        select / radio, or an option failing the label gate (G1c), a required checkbox
        whose label fails the gate (G1d). Attempts are counted in ``_g1_attempts``
        (at most `spa.G1_MAX_ATTEMPTS` per control)."""
        self._g1_attempts = 0
        names = dict(zip(form["ids"], (n for n, _k in form["controls"])))
        infos = page.evaluate(spa.G1_READ_JS, list(form["ids"]))
        done_groups = set()
        for info in infos:
            if info.get("missing") or not info.get("invalid"):
                continue
            name = names.get(info["id"]) or info["id"]
            sel = f'[data-fuzzlab-id="{info["id"]}"]'
            kind = info.get("kind") or "text"
            if kind in ("hidden", "submit", "button", "reset", "image", "file"):
                continue
            if kind == "password":
                continue                                # the filler only (G1b)
            hit = spa.g1_sensitive(info.get("names") or [name])
            if hit:
                return f"a sensitive or credential control is invalid ({hit!r}): never filled"
            if kind == "checkbox":
                why = spa.checkbox_refusal(info.get("label"))
                if why:
                    return f"required checkbox {info.get('label')!r}: {why}"
                self._g1_attempts += 1
                page.eval_on_selector(sel, "el => el.click()")
            elif kind == "radio":
                if info.get("group") in done_groups:
                    continue
                done_groups.add(info.get("group"))
                why = self._g1_radio(page, info, infos)
                if why:
                    return why
            elif kind == "select":
                why = (self._g1_custom_select(page, sel, info)
                       if info.get("tag") == "custom-select"
                       else self._g1_native_select(page, sel, info))
                if why:
                    return why
            else:
                self._g1_ladder(page, sel, info)
            self._settle(page, budget_ms=1000)
            if not page.eval_on_selector(sel, spa.G1_INVALID_JS):
                self.spa_counts["g1_controls_filled"] += 1
                logging.info(f"G1: control {name!r} ({kind}) made valid")
            else:
                logging.info(f"G1: control {name!r} ({kind}) still invalid")
        return None

    def _g1_ladder(self, page, sel, info):
        """Try ladder values (`spa.g1_candidates`; a pattern's candidates must pass the
        page's own RegExp first, in a bounded worker) until the control is valid."""
        cands = spa.g1_candidates(info)
        if info.get("pattern") and info.get("kind") not in ("number", "range"):
            verdicts = page.evaluate(spa.PATTERN_TEST_JS, {
                "pattern": info["pattern"], "candidates": cands,
                "timeout": spa.G1_PATTERN_TIMEOUT_MS})
            cands = [c for c, ok in zip(cands, verdicts or []) if ok]
        for value in cands[:spa.G1_MAX_ATTEMPTS]:
            self._g1_attempts += 1
            if info.get("kind") == "range":
                page.eval_on_selector(sel, spa.G1_SET_JS, value)
            else:
                page.fill(sel, value, timeout=self.timeout_ms)
            if not page.eval_on_selector(sel, spa.G1_INVALID_JS):
                return

    @staticmethod
    def _g1_label(info):
        return info.get("label") or next(iter(info.get("names") or []), info["id"])

    def _g1_native_select(self, page, sel, info):
        options = [(v, t) for v, t, disabled in info.get("options") or [] if not disabled]
        chosen = next(((v, t) for v, t in options if v and t), None)
        why = spa.select_refusal(info.get("names") or [], options,
                                 chosen[1] if chosen else "")
        if why or chosen is None:
            return f"select {self._g1_label(info)!r}: {why or 'no option'}"
        self._g1_attempts += 1
        page.select_option(sel, value=chosen[0], timeout=self.timeout_ms)
        return None

    def _g1_custom_select(self, page, sel, info):
        """A mat-select (role=combobox): its names are judged before it is opened; it is
        opened by a click, its options read and judged, and the first non-empty one
        chosen by a click (the option click is not a submission; G1c)."""
        why = spa.select_refusal(info.get("names") or [], [], "")
        if why:
            return f"select {self._g1_label(info)!r}: {why}"
        page.click(sel, timeout=self.timeout_ms)
        self._settle(page, budget_ms=1000)
        opts = [o for o in page.evaluate(spa.G1_OPTIONS_JS) if not o.get("disabled")]
        chosen = next((o for o in opts if o.get("text")), None)
        why = spa.select_refusal(info.get("names") or [],
                                 [(o.get("value"), o.get("text")) for o in opts],
                                 chosen["text"] if chosen else "")
        if why or chosen is None:
            page.keyboard.press("Escape")
            return f"select {self._g1_label(info)!r}: {why or 'no option'}"
        self._g1_attempts += 1
        page.click(f'[data-fuzzlab-opt="{chosen["id"]}"]', timeout=self.timeout_ms)
        return None

    def _g1_radio(self, page, info, infos):
        group = [i for i in infos if i.get("kind") == "radio" and not i.get("missing")
                 and i.get("group") == info.get("group")]
        if any(i.get("checked") for i in group):
            return None
        options = [(i.get("value") or "", i.get("label") or "") for i in group]
        chosen = next((i for i in group if not spa.checkbox_refusal(i.get("label"))), None)
        why = spa.select_refusal([info.get("group") or ""] + (info.get("names") or []),
                                 options, chosen.get("label") if chosen else "")
        if why or chosen is None:
            return (f"radio group {info.get('group')!r}: "
                    f"{why or 'no option passes the label gate'}")
        self._g1_attempts += 1
        page.eval_on_selector(f'[data-fuzzlab-id="{chosen["id"]}"]', "el => el.click()")
        return None

    def _click_vetted(self, page, selector, vetted, before_click=None):
        """Click the button the gate already vetted, exactly once: `spa.click_vetted`
        (the one implementation, shared with the session manager's browser login),
        counting ``clicks_dispatched`` and ``forms_label_changed`` here. Returns
        ``"clicked"``, ``"dispatched"`` or None (labels changed)."""
        return spa.click_vetted(page, selector, vetted, timeout_ms=self.timeout_ms,
                                counts=self.spa_counts, before_click=before_click)

    def _press_enter(self, page, selector, form, before_press):
        """CC-CRAWL-0038: press Enter in a button-less form's text control. The control
        must still carry the name the gate judged (`spa.form_refusal`) and be enabled;
        then ``before_press`` lifts the window for this one press (W1). Returns
        ``"pressed"``, or None when the control changed."""
        name = next((n for (n, _k), cid in zip(form["controls"], form["ids"])
                     if f'[data-fuzzlab-id="{cid}"]' == selector), None)
        now = page.eval_on_selector(selector, spa.CONTROL_NAME_JS)
        if name is None or now != name or not page.is_enabled(selector,
                                                               timeout=self.timeout_ms):
            return None
        before_press()
        page.press(selector, "Enter", timeout=self.timeout_ms)
        return "pressed"

    def _refind_form(self, page, sig):
        """The rendered form with signature ``sig`` (marked afresh), or None."""
        try:
            return next((f for f in page.evaluate(spa.FORMS_JS, 20)
                         if spa.form_signature(f) == sig), None)
        except PlaywrightError:
            return None

    def _submit_anonymously(self, page_url, sig, explicit):
        """Load the route in a fresh unauthenticated context (same browser, so the same
        launch arguments; the same guard and scope) and submit the form with this
        signature there. The context is closed afterwards."""
        from fuzzlab.tools.navguard import release
        context = self._browser.new_context(service_workers="block")
        context.add_init_script(spa.LISTEN_INIT_JS)            # CC-CRAWL-0038: same forms
        self._guard(context, scripts=False)
        try:
            page = context.new_page()
            self._track(page)
            navguard.navigate(page, page_url, timeout_ms=self.timeout_ms)
            self._settle(page)
            forms = page.evaluate(spa.FORMS_JS, 20)
            match = next((f for f in forms if spa.form_signature(f) == sig), None)
            if match is None:
                self.spa_counts["forms_not_found_anonymous"] += 1
                logging.info(f"SPA form on {page_url} not found in an unauthenticated "
                             f"context: not submitted")
                return
            self._fill_and_click(page, context, match, page_url, explicit)
        except PlaywrightError as exc:
            self.spa_counts["forms_not_submittable"] += 1
            logging.info(f"unauthenticated submission on {page_url} failed "
                         f"({str(exc).splitlines()[0][:80]})")
        finally:
            release(context)
            context.close()

    def _session_intact(self):
        """Is the crawl's own session still there after a submission (Revision 1)? Each
        cookie we injected must still hold its value in the crawl's context, each
        localStorage entry the crawl adopted from a browser login must still hold its
        value (read with ``page.evaluate`` on a page of its origin, FR-CRAWL-14), and the
        session manager must still find the session live (`verify_live`; a browser
        login's protected probe). A localStorage entry changed to another non-empty,
        identifier-like value is a token rotation: re-adopted, not a loss. Returns ``(ok, why)``; anything that cannot be
        verified is a loss (fail closed)."""
        ok, why = self._client_session_intact()
        if not ok:
            return ok, why
        return self._live_session_intact()

    def _client_session_intact(self):
        """The client-side half of `_session_intact` (no network; W4): each injected
        credential cookie and each adopted localStorage entry still holds its value (a
        rotation re-adopted: of a localStorage entry, or of a credential cookie the app's
        JS set -- a login-response cookie must keep its value). Returns ``(ok, why)``;
        fail closed."""
        ok, why = self._cookies_intact()
        if not ok:
            return ok, why
        for origin, entries in self._adopted_storage.items():
            page = next((p for p in self._context.pages
                         if canonical_origin(p.url) == canonical_origin(origin)), None)
            if page is None:
                return False, f"the localStorage of {origin} cannot be read (no page)"
            try:
                now = page.evaluate(_LOCAL_STORAGE_JS, sorted(entries))
            except PlaywrightError as exc:
                return False, f"localStorage could not be read ({type(exc).__name__})"
            for name, value in entries.items():
                current = now.get(name)
                if current == value:
                    continue
                if _storage_rotated(current):
                    # the app rotated its token (reviewer B-S3): re-adopted; the server
                    # still has to accept the session (`verify_live` below)
                    entries[name] = current
                    continue
                return False, f"localStorage entry {name!r} was cleared or invalidated"
        return True, None

    def _cookies_intact(self):
        """The cookie half of `_client_session_intact` (no page needed): each injected
        credential cookie still holds its value in the crawl's context, a rotation of a
        cookie the app's JS set re-adopted. Returns ``(ok, why)``."""
        jar = {c["name"]: c["value"] for c in self._context.cookies()}
        rotating = getattr(self._browser_session, "rotating_cookies", frozenset())
        for i, (name, value) in enumerate(self._injected_cookies):
            current = jar.get(name)
            if current == value:
                continue
            if name in rotating and _storage_rotated(current):
                # a credential cookie the app's JS set and rotated (reviewer B, BUG-0132):
                # re-adopted, as a rotated localStorage token is; `verify_live` decides
                self._injected_cookies[i] = (name, current)
                continue
            return False, f"cookie {name!r} was changed or cleared"
        return True, None

    def _live_session_intact(self):
        """The server half of `_session_intact`: the session manager's `verify_live` (a
        browser login's protected probe). Fail closed."""
        verify = getattr(self._session_manager, "verify_live", None)
        if verify is not None:
            host = urlparse(self._auth_base_url).hostname or ""
            try:
                if not verify(host, self._identity, self._auth_base_url):
                    return False, "the server no longer accepts the session"
            except Exception as exc:  # noqa: BLE001 - unverifiable counts as lost
                return False, f"the session could not be verified ({type(exc).__name__})"
        return True, None

    # ----- G2: reveal navigation (forms phase 4, FR-CRAWL-16) -----
    def _reveal_page(self, page_url, depth):
        """Click this page's reveal candidates (`spa.REVEAL_JS`), each once per (route,
        label signature), each inside its own reveal window. Bounded: per page, per
        crawl, cards per structural signature. Returns more ``(url, depth, source)``."""
        if self.reveals_stopped or self._page is None:
            return []
        route = spa.route_of(page_url, self._last_base or self._app_base)
        if route in self._reveal_stopped_routes:
            return []
        try:
            cands = self._page.evaluate(spa.REVEAL_JS, spa.MAX_REVEAL_CANDIDATES)
        except PlaywrightError as exc:
            logging.info(f"could not read the reveal candidates on {page_url} ({exc})")
            return []
        more, here = [], 0
        for cand in cands:
            if self.reveals_stopped or route in self._reveal_stopped_routes:
                break
            key = spa.reveal_key(route, cand)
            if key in self._reveal_seen:
                continue
            self._reveal_seen.add(key)
            why = spa.reveal_refusal(cand.get("labels")) or (
                "a card text too long to judge whole" if cand.get("long") else None)
            if why:
                self.spa_counts["reveals_refused"] += 1
                logging.info(f"reveal on {page_url} refused: {why}")
                continue
            card = (route, cand.get("sig")) if cand.get("kind") == "card" else None
            if card and self._card_counts.get(card, 0) >= spa.MAX_CARDS_PER_SIGNATURE:
                self.spa_counts["reveals_over_cap"] += 1
                continue
            if here >= spa.MAX_REVEALS_PER_PAGE or \
                    self.spa_counts["reveals_clicked"] >= spa.MAX_REVEALS:
                self.spa_counts["reveals_over_cap"] += 1
                continue
            if card:
                self._card_counts[card] = self._card_counts.get(card, 0) + 1
            here += 1
            try:
                more += self._reveal_one(page_url, route, cand, depth)
            except PlaywrightError as exc:
                logging.info(f"reveal on {page_url} failed "
                             f"({str(exc).splitlines()[0][:80]})")
        return more

    def _find_candidate(self, page, cand, route):
        """The candidate with ``cand``'s key on the page now (marked afresh), or None."""
        key = spa.reveal_key(route, cand)
        return next((c for c in page.evaluate(spa.REVEAL_JS, spa.MAX_REVEAL_CANDIDATES)
                     if spa.reveal_key(route, c) == key), None)

    def _reveal_click(self, page, cand, route):
        """Click one vetted candidate, in the open window: an announcer through
        `spa.click_vetted` (labels re-read, covered-only dispatch); a card by its own
        ``el.click()`` after its labels are re-read (never a coordinate click, B6).
        Returns True when clicked."""
        found = self._find_candidate(page, cand, route)
        if found is None:
            return False
        sel = f'[data-fuzzlab-reveal="{found["id"]}"]'
        if found.get("kind") == "card":
            if list(page.eval_on_selector(sel, spa.CARD_LABELS_JS)) != \
                    list(found.get("labels") or []):
                return False
            page.eval_on_selector(sel, "el => el.click()")
            return True
        return spa.click_vetted(page, sel, found.get("labels") or [],
                                timeout_ms=self.timeout_ms, counts={}) is not None

    def _hrefs(self, page):
        return page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')

    def _revealed(self, page, before_links, url_before, win):
        """What a reveal made reachable: new ``a[href]`` targets, a changed page URL (a
        same-document route change), and navigations the window aborted (W2)."""
        found = [h for h in self._hrefs(page) if h not in before_links]
        if page.url.lower().startswith(("http://", "https://")) and \
                spa.visit_key(page.url) != spa.visit_key(url_before):
            found.append(page.url)
            self.spa_counts["reveal_navigations_captured"] += 1
        navs, win["navs"] = win["navs"], []
        self.spa_counts["reveal_navigations_captured"] += len(navs)
        return found + navs

    def _reveal_one(self, page_url, route, cand, depth):
        """One reveal (G2), inside one window (W1): click, settle, collect links, routes
        and forms; click the revealed menu items that pass the label gate (each after a
        reload and a re-click, inside the window; G2b); a revealed form is filed (G2e)
        and submitted only on a named route. The window closes with Escape and a reload
        (G2c). Afterwards the session is checked (W4). Returns more to queue."""
        page, context = self._page, self._context
        found = []
        with self._window(page, context, page_url) as win:
            before_links = set(self._hrefs(page))
            url_before = page.url
            before_forms = {spa.form_signature(f) for f in page.evaluate(spa.FORMS_JS, 20)}
            if not self._reveal_click(page, cand, route):
                logging.info(f"reveal on {page_url} not clicked: the candidate changed")
                return []
            self.spa_counts["reveals_clicked"] += 1
            self._settle(page)
            found += self._revealed(page, before_links, url_before, win)
            new_forms = [f for f in page.evaluate(spa.FORMS_JS, 20)
                         if spa.form_signature(f) not in before_forms]
            self._record_revealed_forms(page, page_url, route, new_forms)
            submitted = self._submit_revealed(page, context, page_url, route, new_forms)
            items = [] if submitted else page.evaluate(spa.MENU_ITEMS_JS)
            todo = []
            for item in items:
                if item.get("href") or item.get("disabled"):
                    continue                     # a link item: queued as a link
                why = spa.reveal_refusal(item.get("labels"))
                if why:
                    self.spa_counts["reveals_refused"] += 1
                    logging.info(f"revealed menu item on {page_url} not clicked: {why}")
                    continue
                todo.append(item)
            for i, item in enumerate(todo[:spa.MAX_MENU_ITEMS]):
                if i:
                    self._restore(page, page_url, win)
                    if not self._reveal_click(page, cand, route):
                        break
                    self._settle(page)
                    url_before = page.url
                match = next((m for m in page.evaluate(spa.MENU_ITEMS_JS)
                              if m.get("labels") == item.get("labels")), None)
                if match is None:
                    continue
                if spa.click_vetted(page, f'[data-fuzzlab-item="{match["id"]}"]',
                                    match.get("labels") or [], timeout_ms=self.timeout_ms,
                                    counts={}) is None:
                    continue
                self._settle(page)
                found += self._revealed(page, before_links, url_before, win)
        more = self._queue_revealed(page_url, found, depth)
        if win["restore_aborted"]:
            # the close ran with the window's write block on: a clean reload (a page
            # visit, as the crawl makes) so the next reveal sees the app's normal state
            with contextlib.suppress(PlaywrightError):
                navguard.reload(page, timeout_ms=self.timeout_ms)
                self._settle(page)
        self._reveal_session_check(win["aborted"], route)
        return more

    def _record_revealed_forms(self, page, page_url, route, forms):
        """File the forms a reveal showed (G2e): ``revealed_forms`` (route, signature),
        and each real ``<form>`` through the existing phase 1/2 record (`form_record`:
        its own action and method, never relocated, BUG-0115)."""
        from fuzzlab.core.forms import form_record
        for f in forms:
            if self.storage.record_revealed_form(page_url, route, spa.form_signature(f)):
                self.spa_counts["revealed_forms"] += 1
        if forms:
            for form in BeautifulSoup(page.content(), 'html.parser').find_all('form'):
                self.storage.record_form(form_record(form, page_url))

    def _submit_revealed(self, page, context, page_url, route, forms):
        """Submit a revealed form only as a named route's form is (FR-CRAWL-13 + G1): the
        route named, the gate passed, no password, in the crawl's own context. Inside
        the open window (its vetted click lifts it, for that click only). Returns True
        after the first click **attempt** -- a click that raised included: nothing more
        (no other form, no menu item) is done in that reveal (review B-M1)."""
        if not self._submit_routes or self.spa_submit_stopped or not self._spa_on:
            return False
        named = self._submit_routes
        for form in forms:
            sig = spa.form_signature(form)
            if sig in self._submitted_sigs:
                continue
            self._submitted_sigs.add(sig)
            why = (spa.form_refusal(form, route, named=named)
                   or ("a password form (submitted only unauthenticated; not from a "
                       "reveal)" if spa.has_password(form) else None))
            if why:
                self.spa_counts["forms_refused"] += 1
                logging.info(f"revealed SPA form on {page_url} not submitted: {why}")
                continue
            if self.spa_counts["forms_submitted"] >= spa.MAX_SUBMISSIONS:
                self.spa_counts["submissions_over_cap"] += 1
                continue
            self._click_attempted = False
            clicked = self._fill_and_click(page, context, form, page_url, True)
            if not clicked and self._click_attempted:
                # one click attempt per reveal, even one that raised (review B-M1)
                logging.info(f"revealed SPA form on {page_url}: its click failed; no "
                             f"further form or menu item in this reveal")
                return True
            if clicked:
                self.storage.record_revealed_form(page_url, route, sig, submitted=True)
                if self._authenticated:
                    intact, why = self._session_intact()
                    if not intact:
                        self.spa_submit_stopped = (f"the crawl's session was lost after "
                                                   f"submitting a revealed form on "
                                                   f"{route!r} ({why})")
                        logging.warning(f"SPA form submission stopped: "
                                        f"{self.spa_submit_stopped}")
                return True
        return False

    def _queue_revealed(self, page_url, found, depth):
        """Revealed targets through the normal queue gates: scope, the destructive rule
        (a logout link or route is refused), not visited, the depth bound."""
        more = []
        if depth >= self.max_depth:
            return more
        for href in found:
            link = self._crawl_url(urljoin(page_url, href))
            if not (self._in_scope(link) and not self._destructive(link)):
                continue
            key = spa.visit_key(link)
            if key not in self._revealed_link_keys:
                self._revealed_link_keys.add(key)
                self.spa_counts["revealed_links"] += 1
            if not self.storage.is_visited(link):
                more.append((link, depth + 1, 'reveal'))
        return more

    # ----- W4: the session after a reveal -----
    def _reveal_session_check(self, aborted, route):
        """W4 (authenticated crawls): after every reveal, the client-side session check
        (cookies and adopted localStorage, no network), plus `verify_live` when the
        window aborted anything. On a loss: reveals stop on this route, the adopted
        browser state is re-adopted once and the crawl goes on; a second loss (or a
        re-adoption that does not hold) stops reveals for the crawl. Reported."""
        if not self._authenticated:
            return
        ok, why = self._client_session_intact()
        if ok and aborted:
            ok, why = self._live_session_intact()
        if ok:
            return
        self.spa_counts["session_losses_after_reveal"] += 1
        self._reveal_losses += 1
        self._reveal_stopped_routes.add(route)
        if self._reveal_losses >= 2:
            self.reveals_stopped = (f"the session was lost again after a reveal on "
                                    f"{route!r} ({why})")
            logging.warning(f"reveals stopped: {self.reveals_stopped}")
            return
        logging.warning(f"the session was lost after a reveal on {route!r} ({why}); "
                        f"reveals stop on that route and the browser state is "
                        f"re-adopted")
        ok, again = self._readopt_session()
        if not ok:
            self.reveals_stopped = (f"the session could not be re-adopted after a reveal "
                                    f"on {route!r} ({again})")
            self.spa_submit_stopped = self.spa_submit_stopped or self.reveals_stopped
            logging.warning(f"reveals stopped: {self.reveals_stopped}")

    def _readopt_session(self):
        """Re-adopt the session the crawl started with (W4): its cookies and its
        browser login's cookies, and the adopted localStorage entries **as adopted**
        (never a rotated value), then reload the page so the app reads them. Returns the
        client-side check's ``(ok, why)``, then `verify_live`'s when the session manager
        has one (review A-N1)."""
        from fuzzlab.tools import browserauth
        sess, ctx = self._browser_session, self._context
        try:
            if sess is not None:
                state_cookies = (sess.storage_state or {}).get("cookies") or []
                if state_cookies:
                    ctx.add_cookies(state_cookies)
                browserauth.apply_to_context(ctx, sess.cookies)
                self._injected_cookies = list(sess.checked_cookies)   # as adopted
            for origin, entries in self._adopted_original.items():
                page = next((p for p in ctx.pages
                             if canonical_origin(p.url) == canonical_origin(origin)), None)
                if page is None:
                    return False, f"no page of {origin} to restore its localStorage"
                page.evaluate("pairs => pairs.forEach(([k, v]) => "
                              "window.localStorage.setItem(k, v))", sorted(entries.items()))
            self._adopted_storage = copy.deepcopy(self._adopted_original)
            navguard.reload(self._page, timeout_ms=self.timeout_ms)
            self._settle(self._page)
        except PlaywrightError as exc:
            return False, f"re-adoption failed ({type(exc).__name__})"
        ok, why = self._client_session_intact()
        if ok:
            ok, why = self._live_session_intact()    # the server too (review A-N1)
        return ok, why

    def _isolated_submit(self, method, action_url, entries):
        """Submit a selector form without following redirects, through a client that
        starts with a copy of the crawler's cookies and never writes a response cookie
        back (reviewers A2/B-M1). Returns ``(status, headers)``."""
        from urllib.parse import urlencode
        pairs = list(entries)
        from fuzzlab.tools.navguard import checked_api_request
        checked_api_request(self._in_scope, action_url)          # BUG-0123
        if self.engine == "playwright" and self._pw is not None:
            # one scope-checked request, no redirects: the session's headers only when
            # the action is on the session's origins over its transport (FR-CRAWL-14)
            headers = self._auth_headers if self._auth_headers and \
                self._header_scope(action_url) else None
            storage = self._page.context.storage_state()
            if self._cookie_scope is not None and not self._cookie_scope(action_url):
                # another origin than the session's: none of the jar's port-agnostic
                # cookies go with it (FR-SESS-20, BUG-0134)
                storage = {**storage, "cookies": []}
                self._note_session_withheld(action_url, "request")
            ctx = self._pw.request.new_context(storage_state=storage,
                                               extra_http_headers=headers)
            try:
                if method == "POST":
                    resp = ctx.fetch(action_url, method="POST", data=urlencode(pairs),
                                     headers={"Content-Type":
                                              "application/x-www-form-urlencoded"},
                                     max_redirects=0, timeout=self.timeout_ms)
                else:   # a GET form replaces the action's query with its entries
                    resp = ctx.fetch(action_url.split("?")[0] + "?" + urlencode(pairs),
                                     method="GET", max_redirects=0,
                                     timeout=self.timeout_ms)
                return resp.status, dict(resp.headers)
            finally:
                ctx.dispose()
        iso = requests.Session()
        iso.headers.update(self.session.headers)
        iso.cookies.update(self.session.cookies.copy())
        if method == "POST":
            r = iso.post(action_url, data=pairs, allow_redirects=False,
                         timeout=self.timeout_ms / 1000)
        else:
            r = iso.get(action_url.split("?")[0], params=pairs, allow_redirects=False,
                        timeout=self.timeout_ms / 1000)
        return r.status_code, dict(r.headers)

    def _queue_xhr(self, current_url, href):
        """An XHR/fetch URL as a page to crawl, or None: socket.io / engine.io transport
        URLs are not pages (counted); an identifier-like query value is blanked, as a
        stored request's is (`core.redaction.redact_url_identifiers`)."""
        from fuzzlab.core.redaction import redact_url_identifiers
        link = urljoin(current_url, href).split('#')[0]
        if spa.is_transport_url(link):
            self.spa_counts["transport_urls_skipped"] += 1
            return None
        return redact_url_identifiers(link)

    def spa_summary(self):
        """The crawl summary's SPA lines (FR-CRAWL-12/13): routes visited and skipped,
        requests captured, DELETEs blocked, forms submitted and refused, and why
        submitting stopped. Empty when none of it happened."""
        c = self.spa_counts
        lines = []
        if c["routes_found"] or c["routes_visited"]:
            lines.append(f"SPA routes: {c['routes_visited']} visited, "
                         f"{c['routes_skipped_destructive']} skipped as destructive, "
                         f"{c['routes_skipped_parameterised']} skipped as parameterised "
                         f"({c['routes_found']} found in {c['scripts_scanned']} script(s)).")
        if c["scripts_too_large"] or c["scripts_over_page_cap"]:
            lines.append(f"Scripts not scanned for routes: {c['scripts_too_large']} over "
                         f"{spa.MAX_SCRIPT_BYTES} bytes, {c['scripts_over_page_cap']} over "
                         f"the {spa.MAX_SCRIPTS_PER_PAGE}-per-page cap.")
        if c["requests_captured"] or c["requests_not_recorded"]:
            lines.append(f"Captured {c['requests_captured']} request(s) of the app "
                         f"(redacted); {c['requests_not_recorded']} not recorded.")
        if c["requests_blocked_recorded"]:
            lines.append(f"Recorded {c['requests_blocked_recorded']} write(s) the window "
                         f"blocked (redacted, never sent).")
        if c["transport_urls_skipped"]:
            lines.append(f"Skipped {c['transport_urls_skipped']} socket.io/engine.io "
                         f"transport URL(s).")
        if c["deletes_blocked"]:
            lines.append(f"Blocked {c['deletes_blocked']} browser-initiated DELETE "
                         f"request(s) (NFR-CRAWL-safe).")
        if self._submit_routes is not None:
            lines.append(f"SPA forms: {c['forms_submitted']} submitted (cap "
                         f"{spa.MAX_SUBMISSIONS}), {c['forms_refused']} refused, "
                         f"{c['forms_not_submittable']} not submittable, "
                         f"{c['forms_not_found_anonymous']} not found unauthenticated, "
                         f"{c['clicks_dispatched']} click(s) dispatched past an overlay, "
                         f"{c['submissions_over_cap']} over the cap.")
        if self.spa_submit_stopped:
            lines.append(f"SPA form submission stopped: {self.spa_submit_stopped}.")
        if c["g1_controls_filled"] or c["g1_forms_unsatisfiable"]:
            lines.append(f"Constraint-aware filling: {c['g1_controls_filled']} control(s) "
                         f"made valid, {c['g1_forms_unsatisfiable']} form(s) still "
                         f"invalid.")
        if c["reveals_clicked"] or c["reveals_refused"] or c["reveals_over_cap"]:
            lines.append(f"Reveals: {c['reveals_clicked']} clicked, "
                         f"{c['reveals_refused']} refused, {c['reveals_over_cap']} over "
                         f"the caps; {c['revealed_links']} link(s) and "
                         f"{c['revealed_forms']} form(s) revealed, "
                         f"{c['reveal_navigations_captured']} navigation(s) captured.")
        if c["reveal_writes_blocked"] or c["reveal_ws_dropped"]:
            lines.append(f"The reveal window blocked {c['reveal_writes_blocked']} "
                         f"request(s) and dropped {c['reveal_ws_dropped']} WebSocket "
                         f"message(s).")
        if c["revealed_forms"]:
            lines.append("Revealed forms are recorded (spider table revealed_forms: "
                         "route and signature); they are submitted only on a route "
                         "named with --submit-spa-forms.")
        if c["session_losses_after_reveal"]:
            lines.append(f"The session was lost {c['session_losses_after_reveal']} "
                         f"time(s) after a reveal.")
        if self.reveals_stopped:
            lines.append(f"Reveals stopped: {self.reveals_stopped}.")
        if c["spa_query_pairs"] or c["spa_query_unpaired"] or c["spa_query_refused"]:
            hist = c["spa_query_seeded"] - c["spa_query_seeded_fragment"]
            lines.append(f"SPA query parameters (FR-CRAWL-17): {c['spa_query_pairs']} "
                         f"(route, name) pair(s) and {c['spa_query_unpaired']} unpaired "
                         f"name(s) read from scripts; {c['spa_query_probe_loads']} probe "
                         f"load(s) kept {c['spa_query_kept']} name(s); "
                         f"{c['spa_query_seeded']} seed page(s) visited: "
                         f"{c['spa_query_seeded_fragment']} hash route(s) (fragment "
                         f"points, confirmable only with --browser) and {hist} history "
                         f"route(s) (query points, confirmable without a browser).")
        if self.spa_query_refused:
            why = ", ".join(f"{k} x{v}" for k, v in sorted(self.spa_query_refused.items()))
            lines.append(f"SPA query parameters refused: {why}.")
        if c["spa_query_writes_blocked"] or c["spa_query_marker_in_path"] or \
                c["spa_query_step_cap"] or c["spa_query_write_seeds"] or \
                c["spa_query_unclean_windows"]:
            lines.append(f"SPA query loads: {c['spa_query_writes_blocked']} request(s) "
                         f"blocked by their window; {c['spa_query_write_seeds']} seed(s) "
                         f"kept as pages, never points (a write, an unclean close or a "
                         f"failed visit); "
                         f"{c['spa_query_marker_in_path']} marker(s) or filler(s) seen in "
                         f"a request path (no point); the step budget stopped "
                         f"{c['spa_query_step_cap']} script scan(s); "
                         f"{c['spa_query_unclean_windows']} window(s) did not close "
                         f"cleanly.")
        if self.spa_query_stopped:
            lines.append(f"SPA query loads stopped: {self.spa_query_stopped}.")
        return lines

    def crawl(self):
        queue = [(self._crawl_url(self.start_url), 0, 'link')]
        logging.info(f"Starting crawl at {self.start_url} (max_depth={self.max_depth})")

        if self.engine == "playwright":
            self._start_browser()

        crawled = 0
        try:
            while queue or self._query_on:
                if not queue:
                    # FR-CRAWL-17 (Q5): the bare routes are visited; probe them
                    queue.extend(self._plan_probes())
                    if not queue:
                        break
                current_url, depth, source = queue.pop(0)
                probe = None
                if source in (spa.SEED_SOURCE, spa.PROBE_SOURCE) and self.spa_query_stopped:
                    self._refuse_query("session lost")     # S10: no more query loads
                    continue
                if source == spa.PROBE_SOURCE:
                    if self._other_origin(current_url):
                        # M2: the route itself is off the session's origins: never
                        # loaded, recorded under the route's own URL (no markers)
                        self._note_session_withheld(current_url, "document")
                        continue
                    # fresh markers for this load only (B2, PA-0090)
                    probe = self._mint_probe(current_url)
                    if probe is None:
                        continue
                    current_url = probe["url"]

                if depth > self.max_depth or self.storage.is_visited(current_url):
                    continue
                if self._other_origin(current_url):
                    # FR-SESS-20 (R1): never loaded in the authenticated crawl
                    self._note_session_withheld(current_url, "document")
                    continue

                # a seed or probe load runs inside its window (FR-CRAWL-17, Q4)
                window = contextlib.ExitStack()
                win, visited, bare_refused = None, False, False
                try:
                    self._current_url = current_url
                    if source in (spa.SEED_SOURCE, spa.PROBE_SOURCE):
                        # a query load starts from a fresh document (M7): the page
                        # before it is left first, outside the window, as any crawl
                        # navigation leaves it, so none of its timers or requests is
                        # counted as the load's own (a write, an XHR)
                        with contextlib.suppress(PlaywrightError):
                            navguard.navigate(self._page, "about:blank",
                                              timeout_ms=self.timeout_ms,
                                              wait_until="load")
                        if spa.spa_fragment(current_url) is not None:
                            # P1(a): a hash route's load is the bare route's, fresh and
                            # settled OUTSIDE the window (the shell's start-up writes
                            # are sent there, and recorded as its baseline), then the
                            # same-document hash change into the seed or probe inside it
                            # (its captures are filed under the bare route, never the
                            # seed or the probe)
                            self._current_url = _route_key(current_url)
                            self._rendered_ok = False
                            self._goto_recording(self._current_url)
                            self._current_url = current_url
                            if not self._rendered_ok:
                                # S3 (BUG-0138 merge): the bare route did not load (its
                                # loading stopped -- a refused script navigation -- or
                                # never completed): no stable document to change the hash
                                # of, so the window is never entered; refused, counted
                                self._refuse_query("bare route did not load")
                                bare_refused = True
                                continue
                        win = window.enter_context(self._window(
                            self._page, self._context, current_url, query=source))
                        self._probe = probe
                        # B2: what this load's query carries -- the probe's markers, or
                        # the seed's text filler (a redirect-ish name's ``/`` is not)
                        win["taint"] = frozenset(probe["markers"]) if probe is not None \
                            else frozenset({spa.query_filler()})
                    if probe is not None:
                        # rendered only: a probe never falls back to a static request
                        self._xhr_urls = []
                        status, ct, title, text, raw_links, xhr_links = \
                            self._goto_and_parse(current_url)
                    elif self.engine == "playwright":
                        status, ct, title, text, raw_links, xhr_links = self._fetch_rendered(
                            current_url, fallback=source != spa.SEED_SOURCE)
                    else:
                        status, ct, title, text, raw_links, xhr_links = self._fetch_static(current_url)
                    if probe is not None:
                        # FR-CRAWL-17 (A-M3, B3): a probe load records nothing -- no page,
                        # no link, no XHR URL, no form -- only what it kept is seeded
                        self.spa_counts["spa_query_probe_loads"] += 1
                        queue.extend(self._finish_probe(probe, depth))
                        continue

                    content = (text or "")[:8000]
                    self.storage.mark_visited(
                        current_url, status, depth, title, content,
                        rendered=1 if self.engine == "playwright" else 0,
                        # U2 (fail closed): a seed is filed as a write seed (never a
                        # point) until its window closes cleanly with no write
                        source=(spa.WRITE_SEED_SOURCE if source == spa.SEED_SOURCE
                                else source),
                    )
                    visited = True
                    crawled += 1
                    if source == spa.SEED_SOURCE and self._last_html is not None:
                        self.spa_counts["spa_query_seeded"] += 1       # rendered (PA-0110)
                        if spa.spa_fragment(current_url) is not None:
                            self.spa_counts["spa_query_seeded_fragment"] += 1
                        # Q6: the filler in a GET path segment gives no point (counted)
                        self.spa_counts["spa_query_marker_in_path"] += sum(
                            spa.filler_in_path(h) for h in xhr_links)
                    elif self._spa_on and self._is_spa_page(current_url) \
                            and self._last_html is not None:
                        self.spa_counts["routes_visited"] += 1     # rendered (PA-0110)
                    queue.extend(self._after_fetch(current_url, status, depth, title,
                                                   content))
                    logging.info(
                        f"[{status}] depth {depth}: {current_url}"
                        + (f" — {len(raw_links)} link(s)" if raw_links else "")
                        + (f", {len(xhr_links)} XHR endpoint(s)" if xhr_links else "")
                    )

                    if depth < self.max_depth:
                        if 'text/html' in ct or ct == '':
                            for href in raw_links:
                                absolute_link = self._crawl_url(urljoin(current_url, href))
                                if (self._in_scope(absolute_link)
                                        and not self._destructive(absolute_link)
                                        and not self.storage.is_visited(absolute_link)):
                                    queue.append((absolute_link, depth + 1, 'link'))
                        # XHR/fetch targets are queued whatever the page's own
                        # content type, so JSON APIs behind rendered pages land
                        # in the map and get audited like any other URL.
                        for href in xhr_links:
                            if win is not None and (href in win.get("blocked", ())
                                                    or href in win.get("inflight", ())):
                                continue          # FR-CRAWL-17: blocked (or still in
                                #                   flight, M8) in the window
                            absolute_link = self._queue_xhr(current_url, href)
                            if absolute_link and (self._in_scope(absolute_link)
                                    and not self._destructive(absolute_link)
                                    and not self.storage.is_visited(absolute_link)):
                                queue.append((absolute_link, depth + 1, 'xhr'))

                except SessionWithheld:
                    # landed on another origin than the session's (FR-SESS-20, R1):
                    # visited, nothing extracted. A probe records nothing; a seed is
                    # filed as a write seed, never a point (M3)
                    if probe is None:
                        self.storage.mark_visited(
                            current_url, 0, depth,
                            source=(spa.WRITE_SEED_SOURCE if source == spa.SEED_SOURCE
                                    else source))
                    visited = False
                except Exception as e:
                    # M5: a probe's URL (and the error quoting it) carries its
                    # markers: scrubbed before it is logged
                    logging.error(spa.scrub_markers(f"Failed to process {current_url}: {e}"))
                    if probe is None:                    # a probe records nothing
                        self.storage.mark_visited(
                            current_url, 0, depth,
                            source=(spa.WRITE_SEED_SOURCE if source == spa.SEED_SOURCE
                                    else source))
                    visited = False
                finally:
                    try:
                        window.close()
                    finally:
                        self._probe = None
                    queue.extend(self._take_query_navs(depth))
                    if win is not None:
                        self._after_query_window(win, current_url, visited)
                    elif source == spa.SEED_SOURCE and not bare_refused:
                        # its bare route's load (P1(a)) failed before the window
                        # opened: a failed visit, kept as a page (B3-N2: counted)
                        self.spa_counts["spa_query_write_seeds"] += 1

        except KeyboardInterrupt:
            logging.info("Crawl interrupted by user.")
        finally:
            if self.engine == "playwright":
                self._stop_browser()
            if crawled == 0:
                logging.warning(
                    "Crawled 0 new pages. "
                    + ("Every queued URL was already in the database (resume mode); "
                       "drop --resume to rebuild the map from scratch."
                       if self.resume else
                       f"Check that {self.start_url} is reachable.")
                )
            else:
                logging.info(f"Crawled {crawled} page(s).")
            if self.skipped_destructive:
                logging.info(f"Skipped {len(self.skipped_destructive)} destructive "
                             f"URL(s) (NFR-CRAWL-safe).")
            if self.skipped_out_of_scope:
                hosts = ", ".join(f"{h} x{n}" for h, n in
                                  sorted(self.skipped_out_of_scope.items()))
                logging.info(f"Blocked {sum(self.skipped_out_of_scope.values())} "
                             f"out-of-scope browser request(s): {hosts} (BUG-0123).")
            if self.session_out_of_origin:
                logging.info(f"Sent {self.session_out_of_origin} in-scope request(s) "
                             f"without the session: another origin than the session's "
                             f"(session_out_of_origin, FR-SESS-20).")
            if self.isolated_contexts_created:
                logging.info(f"Made {self.isolated_contexts_created} cookie-less request "
                             f"context(s) for other-origin requests (FR-SESS-20).")
            if self.skipped_other_origin:
                logging.info(f"Skipped {len(self.skipped_other_origin)} in-scope page(s) "
                             f"on another origin: {self.OTHER_ORIGIN_REASON}.")
            for line in self.spa_summary():
                logging.info(line)
            self.storage.record_stats({**self.spa_counts,
                                       **{f"spa_query_refused[{k}]": v
                                          for k, v in self.spa_query_refused.items()},
                                       "submit_stopped": int(bool(self.spa_submit_stopped)),
                                       "reveals_stopped": int(bool(self.reveals_stopped)),
                                       "spa_query_stopped":
                                           int(bool(self.spa_query_stopped))})
            self.storage.close()
            logging.info("Crawl finished. Data saved to SQLite database.")


def build_parser():
    p = argparse.ArgumentParser(
        prog="fuzzlab crawl",
        description="Local crawler with optional JavaScript rendering (headless Chromium)."
    )
    p.add_argument("--start", default="http://localhost", help="Start URL (default: http://localhost)")
    p.add_argument("--max-depth", type=int, default=4, help="Maximum crawl depth (default: 4)")
    p.add_argument("--db", default="spider_results.db", help="SQLite output database")
    p.add_argument(
        "--engine", choices=["auto", "playwright", "requests"], default="auto",
        help="auto (default): use Playwright if installed, else static requests. "
             "playwright: render JavaScript. requests: static HTML only.",
    )
    p.add_argument("--timeout", type=int, default=10000, help="Per-page timeout in ms (default: 10000)")
    p.add_argument(
        "--resume", action="store_true",
        help="Keep results already in the database and skip those URLs. "
             "By default each run clears the table and re-crawls.",
    )
    p.add_argument("--store", default=None,
                   help="Also consolidate results into the unified fuzzlab store at this path.")
    p.add_argument("--identity", default=None,
                   help="Crawl authenticated as this identity via the session manager "
                        "(needs saved credentials; Playwright engine). Omit to crawl anonymously.")
    from fuzzlab.session.manager import AUTH_ORIGIN_HELP
    p.add_argument("--auth-origin", action="append", default=[], metavar="ORIGIN",
                   help=AUTH_ORIGIN_HELP)
    p.add_argument("--follow-selector-forms", nargs="?", const="", default=None,
                   metavar="SELECT[,SELECT...]",
                   help="Navigate through menu-like forms (one <select> and a button). "
                        "Alone: GET forms only. With names: also submit POST forms whose "
                        "<select> has one of these names (e.g. 'bug'). Off by default: "
                        "a submission can change state, so POST pickers are submitted "
                        "only when named, never settings-like ones (FR-CRAWL-8).")
    p.add_argument("--no-spa-routes", action="store_true",
                   help="Do not read single-page-app routes from the page's own scripts "
                        "nor crawl hash routes (#/x) as pages. On by default in the "
                        "Playwright engine: it is navigation, like link following "
                        "(FR-CRAWL-12).")
    p.add_argument("--submit-spa-forms", nargs="*", default=None, metavar="ROUTE",
                   help="Fill and submit SPA forms once each, with filler values, so the "
                        "app sends its real requests (captured, redacted). Alone: every "
                        "eligible route (in an authenticated crawl, only in a fresh "
                        "unauthenticated context). With routes (e.g. 'login search'): "
                        "only those. Off by default: a submission changes lab state. "
                        "Destructive, settings, transaction, credential-change, 2FA and "
                        "file-upload forms are never submitted (FR-CRAWL-13).")
    p.add_argument("--no-reveal", action="store_true",
                   help="Do not open menus, dialogs and drawers to find the links and "
                        "forms behind them. On by default in the Playwright engine: "
                        "inside a reveal window that lets only safe GETs through (no "
                        "write, no navigation, no WebSocket message), so a reveal can "
                        "only read (FR-CRAWL-16).")
    p.add_argument("--no-spa-query", action="store_true",
                   help="Do not crawl single-page-app routes with the query parameters "
                        "their scripts read (seeds, and the observation probe for names "
                        "read without a route). On with SPA routes in the Playwright "
                        "engine: every such load runs inside the reveal window, which "
                        "lets only safe GETs through (FR-CRAWL-17).")
    sendpolicy.add_arguments(p)              # D71: lab-only off-switches for three rules
    from fuzzlab.cli_dryrun import add_dry_run_flag
    add_dry_run_flag(p)
    return p


def spa_route_names(values):
    """``--submit-spa-forms`` values as route names: split on commas and whitespace (a
    web-form value arrives as one string); None when the flag is absent."""
    if values is None:
        return None
    return [r for v in values for r in v.replace(",", " ").split() if r]


def spider_kwargs(args, session_manager=None) -> dict:
    """The `LocalSpider` keywords the CLI's ``args`` select (one place, so every flag is
    wired and testable; review B-N1)."""
    return dict(
        max_depth=args.max_depth,
        db_name=args.db,
        engine=args.engine,
        timeout_ms=args.timeout,
        resume=args.resume,
        session_manager=session_manager,
        identity=args.identity,
        selector_forms=(None if args.follow_selector_forms is None else
                        [n.strip() for n in args.follow_selector_forms.split(",")
                         if n.strip()]),
        spa_routes=not args.no_spa_routes,
        submit_spa_forms=spa_route_names(args.submit_spa_forms),
        reveal=not args.no_reveal,
        spa_query=not args.no_spa_query,
    )


def session_manager_for(args):
    """The CLI's session manager, or None without ``--identity``: one place, so
    ``--auth-origin`` provably reaches it (merge review)."""
    if not args.identity:
        return None
    from fuzzlab.tools.authhttp import make_session_manager
    return make_session_manager(args.start, store_path=args.store,
                                auth_origins=args.auth_origin)


def parse_args(argv=None):
    p = build_parser()
    args = p.parse_args(argv)
    sendpolicy.apply(args)                   # D71, before any side effect
    if args.auth_origin:                 # a usage error before any side effect (R5)
        from fuzzlab.session.manager import parse_auth_origins
        from fuzzlab.tools.authhttp import scope_hosts_for
        try:
            args.auth_origin = parse_auth_origins(args.auth_origin,
                                                  scope_hosts_for(args.start))
        except ValueError as exc:
            p.error(str(exc))
    return args


if __name__ == "__main__":
    args = parse_args()
    if args.dry_run:
        from fuzzlab.cli_dryrun import report
        report("crawl", args)
        raise SystemExit(0)
    get_logger("crawler").info("crawler starting",
                               extra={"start": args.start, "engine": args.engine,
                                      "identity": args.identity})
    spider = LocalSpider(args.start, **spider_kwargs(args, session_manager_for(args)))
    spider.crawl()
    if args.store:
        from fuzzlab.core.config import load_config
        from fuzzlab.core.store import Store
        from fuzzlab.tools import store_adapter
        with Store(args.store) as store:
            run_id = store.start_run("crawler", load_config().hash())
            counts = store_adapter.import_spider(args.db, store, run_id)
        get_logger("crawler").info("consolidated into store", extra=counts)
