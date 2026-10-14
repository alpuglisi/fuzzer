import argparse
import functools
import logging
import sqlite3
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from fuzzlab.core import get_logger
from fuzzlab.core.urls import canonical_origin, in_origin_scope, origin_scope, url_key
from fuzzlab.tools import spa

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
        # JSON text; source is 'passive' or 'submit'; signature = method + canonical URL
        # path + sorted top-level keys. Request headers and cookies are never stored.
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_url TEXT,
                method TEXT,
                url TEXT,
                content_type TEXT,
                body_json TEXT,
                source TEXT,
                signature TEXT UNIQUE
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
        # Add columns that older result databases won't have.
        for col, decl in (("title", "TEXT"), ("content", "TEXT"),
                          ("rendered", "INTEGER DEFAULT 0"), ("source", "TEXT DEFAULT 'link'")):
            try:
                self.cursor.execute(f"ALTER TABLE discovered_pages ADD COLUMN {col} {decl}")
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

    def record_request(self, page_url, method, url, content_type, body, source):
        """Store one request the page made (FR-CRAWL-13), redacted here, at the write
        site, by the one boundary (PA-0100): both URLs by
        `core.redaction.redact_url_identifiers`, the body by
        `core.redaction.redact_captured_body` (64 KiB, depth 8, fail closed). Only the
        media type of the request's own Content-Type is kept; no other header and no
        cookie is ever taken. Returns None when stored, else why not (``duplicate`` for
        a signature already stored)."""
        import json

        from fuzzlab.core.redaction import redact_captured_body, redact_url_identifiers
        doc, why = redact_captured_body(body, content_type)
        if why is not None:
            return why
        safe_url = redact_url_identifiers(url)
        method = (method or "").upper()
        keys = sorted(str(k) for k in doc) if isinstance(doc, dict) else []
        sig = json.dumps([method, url_key(safe_url), keys])
        media = (content_type or "").split(";", 1)[0].strip().lower()
        try:
            self.cursor.execute('''
                INSERT INTO discovered_requests
                    (page_url, method, url, content_type, body_json, source, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (redact_url_identifiers(page_url), method, safe_url, media,
                  json.dumps(doc, ensure_ascii=False), source, sig))
            self.conn.commit()
            return None
        except sqlite3.IntegrityError:
            return "duplicate"

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
            ''', (redact_url(record["page_url"]), redact_url(record["action_url"]),
                  record["method"], record["enctype"], json.dumps(record["entries"]),
                  json.dumps(record["controls"]), int(record["selector"]),
                  json.dumps(record["options"]), sig))
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
        (by visit key: an alias spelling of a stored page is present)."""
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

    def is_visited(self, url):
        """Whether a page with this URL's visit key (`spa.visit_key`: canonical origin,
        path, query and SPA-route fragment) has already been processed."""
        return spa.visit_key(url) in self._keys

    def close(self):
        self.conn.close()


def _storage_rotated(value) -> bool:
    """A changed localStorage value that is a rotation, not a loss (reviewer B-S3): a
    non-empty, identifier-like value (`core.redaction.looks_like_identifier`). Cleared,
    empty, ``"null"`` and ``"undefined"`` (what ``localStorage.setItem(k, null)`` and
    friends leave) are a loss."""
    from fuzzlab.core.redaction import looks_like_identifier
    if value is None or str(value).strip().lower() in ("", "null", "undefined"):
        return False
    return looks_like_identifier(str(value))


#: ``names => {name: localStorage value}`` (FR-CRAWL-14's session check).
_LOCAL_STORAGE_JS = ("names => Object.fromEntries(names.map(n => "
                     "[n, window.localStorage.getItem(n)]))")


class LocalSpider:
    """Crawls a local site, optionally rendering JavaScript with a headless browser."""

    def __init__(self, start_url, max_depth=3, db_name="spider_results.db",
                 engine="auto", timeout_ms=10000, resume=False,
                 session_manager=None, identity=None, selector_forms=None,
                 spa_routes=True, submit_spa_forms=None):
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
            "requests_not_recorded", "deletes_blocked", "forms_submitted",
            "forms_refused", "forms_not_submittable", "forms_not_found_anonymous",
            "submissions_over_cap", "clicks_dispatched", "forms_label_changed"), 0)

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
        reason = spa.route_destructive_reason(url)
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
            self._adopted_storage = dict(session.local_storage)
        # service workers would fetch outside page.route (BUG-0111)
        context = self._browser.new_context(
            service_workers="block",
            **({"storage_state": session.storage_state}
               if session is not None and session.storage_state else {}))
        # guard the context, not the page, so popups are confined too (BUG-0123)
        self._guard(context, scripts=True, session=session is not None)
        self._context = context
        self._page = context.new_page()
        self._track(self._page)
        if session is not None:
            from fuzzlab.tools import browserauth
            browserauth.apply_to_context(context, session.cookies)
            self._injected_cookies = [(c["name"], c["value"]) for c in session.cookies]
            logging.info(f"Crawler authenticated as {self._identity} "
                         f"({len(session.cookies)} cookie(s), "
                         f"{sum(map(len, self._adopted_storage.values()))} localStorage "
                         f"entr(ies))")
        # Record fetch()/XMLHttpRequest targets. These endpoints are where a
        # JavaScript-rendered page actually gets its data, and they never appear
        # as <a href> anywhere, so link-following alone can never reach them.
        self._page.on("request", self._on_request)

    def _guard(self, context, *, scripts, session=False):
        """The one guard every context this crawl opens gets (BUG-0123, FR-CRAWL-12/13):
        scope, the destructive rule, the DELETE rule and the passive observer (which
        reads script bodies only in the crawl's own context). ``session``: the crawl's
        own authenticated context, whose route adds the session's headers to in-scope
        requests on the session's host (FR-CRAWL-14); an unauthenticated context gets
        none."""
        from fuzzlab.tools.navguard import guard_page
        guard_page(context, allow=self._allow,
                   on_abort=lambda url, reason: self.skipped_destructive.setdefault(url, reason),
                   in_scope=self._in_scope, on_out_of_scope=self._note_out_of_scope,
                   method_refusal=functools.partial(self._method_refusal,
                                                    context=context),
                   observe=functools.partial(self._observe,
                                             scripts=scripts and self._spa_on),
                   headers=(self._auth_headers or None) if session else None,
                   header_scope=self._header_scope if session else None)

    def _track(self, page):
        """Count a page's requests in flight, so a settle waits for the app's own XHRs
        (a hash-route change or a click leaves the page's load state as it was)."""
        key = id(page)
        self._inflight[key] = 0

        def up(_request):
            self._inflight[key] = self._inflight.get(key, 0) + 1

        def down(_request):
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
            if request.resource_type in ("xhr", "fetch"):
                self._xhr_urls.append(request.url)
        except Exception:
            pass  # never let instrumentation break a crawl

    # ----- passive observation (forms phase 3) -----
    def _observe(self, request, response, *, scripts):
        """Called by the guard for each request it sent (FR-CRAWL-12/13): a same-origin
        script body is scanned for routes (crawl context only); a fetch/XHR request with a
        body is captured. Nothing is requested here: both come from what the browser
        already loaded."""
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
        # the request's own Content-Type is the one header read; none is stored
        content_type = (request.headers or {}).get("content-type", "")
        why = self.storage.record_request(self._capture_page or self._current_url, method,
                                          request.url, content_type, body,
                                          self._capture_source)
        if why is None:
            self.spa_counts["requests_captured"] += 1
        elif why != "duplicate":
            self.spa_counts["requests_not_recorded"] += 1
            logging.info(f"captured request {method} {request.url.split('?', 1)[0]} not "
                         f"recorded ({why})")

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
        routes = spa.scan_routes(body.decode("utf-8", "replace")) \
            if len(body) <= spa.MAX_SCRIPT_BYTES else None
        if routes is None:
            self.spa_counts["scripts_too_large"] += 1
            return
        self.spa_counts["scripts_scanned"] += 1
        self._pending_routes.extend(routes)

    def _stop_browser(self):
        try:
            if self._context is not None:
                from fuzzlab.tools.navguard import release
                release(self._context)
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
        host = urlparse(url).hostname or "?"
        self.skipped_out_of_scope[host] = self.skipped_out_of_scope.get(host, 0) + 1

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
            soup = BeautifulSoup(resp.text, 'html.parser')
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
            text = soup.get_text(" ", strip=True)
            links = [a['href'] for a in soup.find_all('a', href=True)]
        return resp.status_code, ct, title, text, links, []

    def _fetch_rendered(self, url):
        """Renders with headless Chromium, then reads links and text from the live DOM.

        Chromium refuses to navigate to some responses (downloads,
        application/octet-stream). Those URLs still belong in the map, so the
        crawler falls back to a plain request rather than dropping them.
        """
        self._xhr_urls = []   # collected by _on_request during this navigation
        try:
            return self._goto_and_parse(url)
        except Exception as e:
            logging.info(f"Browser could not render {url} ({str(e).splitlines()[0][:80]}); "
                         f"falling back to a static request")
            return self._fetch_static(url)

    def _goto_and_parse(self, url):
        self._last_final_url, self._last_html, self._last_base = url, None, None
        self._doc_url, self._page_scripts, self._pending_routes = url, 0, []
        response = self._page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
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
        if 'text/html' in ct or ct == '':
            # Let JavaScript-driven fetch()/render settle (best effort).
            try:
                self._page.wait_for_load_state("networkidle", timeout=self.timeout_ms)
            except Exception:
                pass
            if same_document:
                self._settle(self._page)
            title = self._page.title()
            self._last_final_url = self._page.url
            self._last_html = self._page.content()
            if self._spa_on:
                self._last_base = self._page.evaluate(
                    "() => document.querySelector('base') ? document.baseURI : null")
            # Links and text come from the RENDERED DOM, so JS-injected nav links
            # and JS-built content are included.
            links = self._page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')
            try:
                text = self._page.inner_text('body')
            except Exception:
                text = None
        return status, ct, title, text, links, list(dict.fromkeys(self._xhr_urls))

    # ----- landing URLs, forms, selector navigation (forms phase 1) -----
    def _after_fetch(self, url, status, depth, title, content):
        """Record where a redirect landed and every form on the page; enumerate allowed
        selector forms. Returns more ``(url, depth, source)`` to queue."""
        from fuzzlab.core.redaction import redact_url
        more = []
        final = self._last_final_url
        landing = self._crawl_url(final) if final else None
        if (landing and spa.visit_key(landing) != spa.visit_key(url)
                and self._in_scope(landing) and not self._destructive(landing)):
            # the landing URL keeps its query (xss_eval.php?date=Date()), redacted
            self.storage.mark_visited(redact_url(landing), status, depth,
                                      title, content, source='redirect')
        if self._spa_on and self.engine == "playwright":
            more += self._queue_routes(final or url, depth)
            if (self._submit_routes is not None and self._last_html is not None
                    and self._is_spa_page(url)):
                self._submit_spa_forms(final or url)
        if not self._last_html:
            return more
        from fuzzlab.core.forms import form_record
        page = final or url
        for form in BeautifulSoup(self._last_html, 'html.parser').find_all('form'):
            record = form_record(form, page)
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
        if not routes:
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
            if depth >= self.max_depth:
                continue
            if (self._in_scope(target) and not self._destructive(target)
                    and not self.storage.is_visited(target)):
                more.append((target, depth + 1, 'spa-route'))
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
        only on a named route (``explicit``) and only from ``context``."""
        for (name, kind), cid in zip(form["controls"], form["ids"]):
            if not spa.fillable(kind) or (kind != "password"
                                          and spa.sensitive_control(name)):
                continue
            try:
                page.fill(f'[data-fuzzlab-id="{cid}"]', spa.filler(kind),
                          timeout=self.timeout_ms)
            except PlaywrightError:
                pass                                    # e.g. a range or read-only input
        button = form.get("button_id")
        selector = f'[data-fuzzlab-id="{button}"]'
        try:
            if not button or not page.is_enabled(selector, timeout=self.timeout_ms):
                self.spa_counts["forms_not_submittable"] += 1
                logging.info(f"SPA form on {page_url} not submittable (no enabled button)")
                return False
        except PlaywrightError:
            self.spa_counts["forms_not_submittable"] += 1
            return False
        self._capture_source, self._capture_page = "submit", page_url
        self._delete_ok_for = context if explicit else None
        try:
            how = self._click_vetted(page, selector, [
                form.get("button") or "", form.get("button_aria") or "",
                form.get("button_icons") or ""])
            if how is None:
                logging.info(f"SPA form on {page_url} not clicked: its button's labels "
                             f"changed after the gate vetted them")
                return False
            self.spa_counts["forms_submitted"] += 1
            logging.info(f"submitted the SPA form {form.get('button')!r} on {page_url}"
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

    def _click_vetted(self, page, selector, vetted):
        """Click the button the gate already vetted, exactly once: `spa.click_vetted`
        (the one implementation, shared with the session manager's browser login),
        counting ``clicks_dispatched`` and ``forms_label_changed`` here. Returns
        ``"clicked"``, ``"dispatched"`` or None (labels changed)."""
        return spa.click_vetted(page, selector, vetted, timeout_ms=self.timeout_ms,
                                counts=self.spa_counts)

    def _submit_anonymously(self, page_url, sig, explicit):
        """Load the route in a fresh unauthenticated context (same browser, so the same
        launch arguments; the same guard and scope) and submit the form with this
        signature there. The context is closed afterwards."""
        from fuzzlab.tools.navguard import release
        context = self._browser.new_context(service_workers="block")
        self._guard(context, scripts=False)
        try:
            page = context.new_page()
            self._track(page)
            page.goto(page_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
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
        jar = {c["name"]: c["value"] for c in self._context.cookies()}
        for name, value in self._injected_cookies:
            if jar.get(name) != value:
                return False, f"cookie {name!r} was changed or cleared"
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
        verify = getattr(self._session_manager, "verify_live", None)
        if verify is not None:
            host = urlparse(self._auth_base_url).hostname or ""
            try:
                if not verify(host, self._identity, self._auth_base_url):
                    return False, "the server no longer accepts the session"
            except Exception as exc:  # noqa: BLE001 - unverifiable counts as lost
                return False, f"the session could not be verified ({type(exc).__name__})"
        return True, None

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
            # the action is on the session's host over its transport (FR-CRAWL-14)
            headers = self._auth_headers if self._auth_headers and \
                self._header_scope(action_url) else None
            ctx = self._pw.request.new_context(
                storage_state=self._page.context.storage_state(),
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
        return lines

    def crawl(self):
        queue = [(self._crawl_url(self.start_url), 0, 'link')]
        logging.info(f"Starting crawl at {self.start_url} (max_depth={self.max_depth})")

        if self.engine == "playwright":
            self._start_browser()

        crawled = 0
        try:
            while queue:
                current_url, depth, source = queue.pop(0)

                if depth > self.max_depth or self.storage.is_visited(current_url):
                    continue

                try:
                    self._current_url = current_url
                    if self.engine == "playwright":
                        status, ct, title, text, raw_links, xhr_links = self._fetch_rendered(current_url)
                    else:
                        status, ct, title, text, raw_links, xhr_links = self._fetch_static(current_url)

                    content = (text or "")[:8000]
                    self.storage.mark_visited(
                        current_url, status, depth, title, content,
                        rendered=1 if self.engine == "playwright" else 0,
                        source=source,
                    )
                    crawled += 1
                    if self._spa_on and self._is_spa_page(current_url) \
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
                            absolute_link = self._queue_xhr(current_url, href)
                            if absolute_link and (self._in_scope(absolute_link)
                                    and not self._destructive(absolute_link)
                                    and not self.storage.is_visited(absolute_link)):
                                queue.append((absolute_link, depth + 1, 'xhr'))

                except Exception as e:
                    logging.error(f"Failed to process {current_url}: {e}")
                    self.storage.mark_visited(current_url, 0, depth, source=source)

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
            for line in self.spa_summary():
                logging.info(line)
            self.storage.record_stats({**self.spa_counts,
                                       "submit_stopped": int(bool(self.spa_submit_stopped))})
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
    from fuzzlab.cli_dryrun import add_dry_run_flag
    add_dry_run_flag(p)
    return p


def spa_route_names(values):
    """``--submit-spa-forms`` values as route names: split on commas and whitespace (a
    web-form value arrives as one string); None when the flag is absent."""
    if values is None:
        return None
    return [r for v in values for r in v.replace(",", " ").split() if r]


def parse_args():
    return build_parser().parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.dry_run:
        from fuzzlab.cli_dryrun import report
        report("crawl", args)
        raise SystemExit(0)
    get_logger("crawler").info("crawler starting",
                               extra={"start": args.start, "engine": args.engine,
                                      "identity": args.identity})
    session_manager = None
    if args.identity:
        from fuzzlab.tools.authhttp import make_session_manager
        session_manager = make_session_manager(args.start, store_path=args.store)
    spider = LocalSpider(
        args.start,
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
    )
    spider.crawl()
    if args.store:
        from fuzzlab.core.config import load_config
        from fuzzlab.core.store import Store
        from fuzzlab.tools import store_adapter
        with Store(args.store) as store:
            run_id = store.start_run("crawler", load_config().hash())
            counts = store_adapter.import_spider(args.db, store, run_id)
        get_logger("crawler").info("consolidated into store", extra=counts)
