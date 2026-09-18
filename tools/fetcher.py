import argparse
import logging
import os
import re
import sqlite3
from urllib.parse import urlparse, urljoin, parse_qsl

import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Optional JavaScript rendering. When Playwright is available the auditor can
# render a page in a headless browser and inspect the resulting DOM, so forms
# and inputs that are built by JavaScript are audited too. Without it, the
# auditor falls back to fetching the raw HTML.
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


# Query-string names that typically feed ORDER BY / LIMIT / WHERE clauses.
FILTER_PARAMS = {
    'sort', 'order', 'orderby', 'order_by', 'dir', 'direction', 'by',
    'limit', 'offset', 'page', 'per_page', 'perpage', 'start', 'count',
    'filter', 'category', 'cat', 'tag', 'type', 'status', 'view',
}

# Field types that carry no user-controlled value worth fuzzing.
SKIP_INPUT_TYPES = {'submit', 'button', 'reset', 'image'}

# Passive signatures of a database error surfacing in a response body.
SQL_ERROR_SIGNATURES = [
    (re.compile(r"You have an error in your SQL syntax", re.I), 'MySQL'),
    (re.compile(r"\bmysqli?_(?:query|fetch|num_rows|real_escape)", re.I), 'MySQL'),
    (re.compile(r"\bWarning:\s*mysql", re.I), 'MySQL'),
    (re.compile(r"\bunclosed quotation mark after the character string", re.I), 'MSSQL'),
    (re.compile(r"\bMicrosoft OLE DB Provider for (?:ODBC|SQL Server)", re.I), 'MSSQL'),
    (re.compile(r"\bPG::SyntaxError|\bpg_query\(\)|\bPostgreSQL query failed", re.I), 'PostgreSQL'),
    (re.compile(r"\bORA-\d{5}", re.I), 'Oracle'),
    (re.compile(r"\bSQLite3?::|\bsqlite3\.OperationalError|\bunrecognized token", re.I), 'SQLite'),
]

# fetch('...') / $.ajax({url: '...'}) / new XMLHttpRequest().open('GET','...')
AJAX_URL_PATTERNS = [
    re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""\.open\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""\burl\s*:\s*['"]([^'"]+)['"]""", re.I),
]


def load_urls(spider_db="spider_results.db"):
    """Extracts the mapped URLs from the spider's database.

    Returns a list of (url, source) where source is 'link' or 'xhr'. Older
    spider databases have no source column; those rows default to 'link'.
    """
    try:
        conn = sqlite3.connect(spider_db)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(discovered_pages)")
        has_source = any(row[1] == 'source' for row in cursor.fetchall())
        if has_source:
            cursor.execute("SELECT url, IFNULL(source, 'link') FROM discovered_pages ORDER BY depth ASC")
            rows = cursor.fetchall()
        else:
            cursor.execute("SELECT url FROM discovered_pages ORDER BY depth ASC")
            rows = [(row[0], 'link') for row in cursor.fetchall()]
        conn.close()
        return rows
    except sqlite3.Error as e:
        logging.error(f"Spider DB error: {e}")
        return []


def load_indicators(indicator_db="php_indicators.db"):
    """Extracts the audit rules from the indicators database."""
    try:
        conn = sqlite3.connect(indicator_db)
        cursor = conn.cursor()
        cursor.execute("SELECT indicator_type, category FROM indicators")
        indicators = cursor.fetchall()
        conn.close()
        return indicators
    except sqlite3.Error as e:
        logging.error(f"Indicator DB error: {e}")
        return []


def setup_results_db(db_name="audit_results.db", append=False):
    """Initializes the findings database.

    Findings are keyed on (category, transaction_type, target_identifier) so the
    same form or parameter reached from 40 pages is one row with an occurrence
    count, not 40 near-identical rows. Unless append=True the table is cleared,
    so re-running never inflates the results.
    """
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_url TEXT NOT NULL,
            category TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            target_identifier TEXT NOT NULL,
            html_context TEXT,
            occurrences INTEGER NOT NULL DEFAULT 1
        )
    ''')
    # Upgrade databases written by the previous version.
    try:
        cursor.execute("ALTER TABLE findings ADD COLUMN occurrences INTEGER NOT NULL DEFAULT 1")
    except sqlite3.OperationalError:
        pass

    if append:
        # Collapse any duplicates left by an older run so the unique index applies.
        cursor.execute('''
            UPDATE findings SET occurrences = (
                SELECT COUNT(*) FROM findings f2
                WHERE f2.category = findings.category
                  AND f2.transaction_type = findings.transaction_type
                  AND f2.target_identifier = findings.target_identifier
            )
        ''')
        cursor.execute('''
            DELETE FROM findings WHERE id NOT IN (
                SELECT MIN(id) FROM findings
                GROUP BY category, transaction_type, target_identifier
            )
        ''')
    else:
        cursor.execute('DELETE FROM findings')

    cursor.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_target
        ON findings (category, transaction_type, target_identifier)
    ''')
    conn.commit()
    return conn


def log_finding(cursor, url, category, trans_type, target, context=""):
    """Records a finding, or bumps its occurrence count if already seen."""
    cursor.execute('''
        INSERT INTO findings (page_url, category, transaction_type, target_identifier, html_context)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (category, transaction_type, target_identifier)
        DO UPDATE SET occurrences = occurrences + 1
    ''', (url, category, trans_type, target, context))
    return cursor.rowcount


class ContentFetcher:
    """Fetches page HTML, optionally rendering JavaScript with a headless browser.

    Use as a context manager so the browser is started once and reused:

        with ContentFetcher(engine="playwright") as fetcher:
            status, content_type, html = fetcher.fetch(url)
    """

    def __init__(self, engine="auto", timeout_ms=10000):
        self.timeout_ms = timeout_ms
        self.session = requests.Session()

        if engine == "auto":
            engine = "playwright" if _PLAYWRIGHT_AVAILABLE else "requests"
        if engine == "playwright" and not _PLAYWRIGHT_AVAILABLE:
            logging.warning(
                "Playwright is not installed; falling back to the static 'requests' engine "
                "(JavaScript-built forms/inputs will NOT be audited). Install with: "
                "pip install playwright && playwright install chromium"
            )
            engine = "requests"
        self.engine = engine

        self._pw = None
        self._browser = None
        self._page = None
        self._xhr_urls = []

    def __enter__(self):
        if self.engine == "playwright":
            self._pw = sync_playwright().start()
            launch_kwargs = {
                "headless": True,
                "args": ["--no-sandbox", "--disable-dev-shm-usage"],
            }
            exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
            if exe:
                launch_kwargs["executable_path"] = exe
            self._browser = self._pw.chromium.launch(**launch_kwargs)
            self._page = self._browser.new_page()
            self._page.on("request", self._on_request)
        logging.info(f"Auditor engine: {self.engine}")
        return self

    def _on_request(self, request):
        try:
            if request.resource_type in ("xhr", "fetch"):
                self._xhr_urls.append(request.url)
        except Exception:
            pass

    def __exit__(self, exc_type, exc, tb):
        if self.engine == "playwright":
            try:
                if self._browser:
                    self._browser.close()
            finally:
                if self._pw:
                    self._pw.stop()
        return False

    def fetch(self, url):
        """Returns (status_code, content_type, html, xhr_urls). html is the
        RENDERED DOM when the Playwright engine is active, otherwise the raw
        response body. xhr_urls are the fetch/XHR calls the page made while
        rendering (always empty for the static engine)."""
        if self.engine == "playwright":
            self._xhr_urls = []
            response = self._page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            status = response.status if response else 0
            ct = (response.headers or {}).get('content-type', '') if response else ''
            # Let JavaScript-driven DOM updates settle (best effort).
            try:
                self._page.wait_for_load_state("networkidle", timeout=self.timeout_ms)
            except Exception:
                pass
            html = self._page.content()
            return status, ct, html, list(dict.fromkeys(self._xhr_urls))

        resp = self.session.get(url, timeout=self.timeout_ms / 1000)
        return resp.status_code, resp.headers.get('Content-Type', ''), resp.text, []


def _form_target(page_url, form):
    """Resolves a form's action to a stable identifier for the fuzzer."""
    action = (form.get('action') or '').strip()
    if action in ('', '#'):
        # An empty action posts back to the page itself.
        return urlparse(page_url).path.lstrip('/') or 'index.php'
    return urlparse(urljoin(page_url, action)).path.lstrip('/')


def audit_page(url, source, fetcher, indicators, db_conn, unhandled):
    """Fetches the page (rendering JS if enabled) and applies checks to the DOM."""
    print(f"\n--- Auditing: {url} ---")
    cursor = db_conn.cursor()

    try:
        status, content_type, html, xhr_urls = fetcher.fetch(url)
        parsed_url = urlparse(url)
        path = parsed_url.path.lstrip('/') or 'index.php'
        params = parse_qsl(parsed_url.query, keep_blank_values=True)

        is_html = 'text/html' in content_type
        soup = BeautifulSoup(html, 'html.parser') if is_html else None

        for ind_type, category in indicators:

            # 1. URL Parameter Checks — one finding per parameter, scoped to the
            #    path, so the fuzzer gets a real parameter list.
            if ind_type == "Query Strings":
                for name, value in params:
                    target = f"{path}?{name}"
                    print(f"[!] Logged {ind_type}: {target}")
                    log_finding(cursor, url, category, ind_type, target,
                                f"example value: {value[:80]}")

            # 2. Sequential numeric parameters that likely map to primary keys.
            elif ind_type == "Predictable IDs":
                for name, value in params:
                    if value.isdigit():
                        target = f"{path}?{name}"
                        print(f"[!] Logged {ind_type}: {target}={value}")
                        log_finding(cursor, url, category, ind_type, target,
                                    f"numeric value: {value[:80]}")

            # 3. Form Action Checks
            elif ind_type == "Action Attributes":
                for form in (soup.find_all('form') if soup else []):
                    target = _form_target(url, form)
                    method = (form.get('method') or 'GET').upper()
                    print(f"[!] Logged {ind_type}: '{target}' via {method}")
                    log_finding(cursor, url, category, ind_type, target,
                                f"method={method} {str(form)[:150]}")

            # 4. Input Name Checks — every named field a user can submit, not
            #    just hidden ones. Scoped by form action so the shared header
            #    search box is one finding, not one per page.
            elif ind_type == "Input Names":
                for form in (soup.find_all('form') if soup else []):
                    action = _form_target(url, form)
                    for field in form.find_all(['input', 'textarea', 'select']):
                        # JavaScript-built forms often address their fields by id
                        # alone, with no name attribute. Those are still user
                        # input, so fall back to the id rather than skipping.
                        name = field.get('name') or field.get('id')
                        if not name:
                            continue
                        ftype = (field.get('type') or field.name).lower()
                        if ftype in SKIP_INPUT_TYPES:
                            continue
                        keyed_by = 'name' if field.get('name') else 'id'
                        target = f"{action}:{name}"
                        print(f"[!] Logged {ind_type}: field '{name}' ({ftype}, by {keyed_by}) -> {action}")
                        log_finding(cursor, url, category, ind_type, target,
                                    f"type={ftype} keyed_by={keyed_by} {str(field)[:150]}")
                # Fields sitting outside any <form> are still fuzzable via JS.
                for field in (soup.find_all(['input', 'textarea', 'select']) if soup else []):
                    if field.find_parent('form') is not None:
                        continue
                    name = field.get('name') or field.get('id')
                    if not name:
                        continue
                    ftype = (field.get('type') or field.name).lower()
                    if ftype in SKIP_INPUT_TYPES:
                        continue
                    target = f"{path}:{name}"
                    print(f"[!] Logged {ind_type}: unbound field '{name}' ({ftype})")
                    log_finding(cursor, url, category, ind_type, target,
                                f"type={ftype} (no enclosing form) {str(field)[:150]}")

            # 5. Background calls that query a database directly. Captured live
            #    from the browser when rendering, and by reading the scripts so
            #    the static engine finds them too.
            elif ind_type == "AJAX Live Search":
                endpoints = set()
                for endpoint in xhr_urls:
                    endpoints.add(urlparse(endpoint).path.lstrip('/') or endpoint)
                if soup:
                    for script in soup.find_all('script'):
                        body = script.string or script.get_text() or ''
                        for pattern in AJAX_URL_PATTERNS:
                            for hit in pattern.findall(body):
                                if hit.startswith(('http:', 'https:', '/')) or '.php' in hit:
                                    endpoints.add(urlparse(urljoin(url, hit)).path.lstrip('/'))
                if source == 'xhr':
                    endpoints.add(path)
                for endpoint in sorted(endpoints):
                    print(f"[!] Logged {ind_type}: {endpoint}")
                    log_finding(cursor, url, category, ind_type, endpoint,
                                f"called from {url}")

            # 6. Sort/paginate/filter parameters that reach ORDER BY or LIMIT.
            elif ind_type == "Filtered Views":
                for name, value in params:
                    if name.lower() in FILTER_PARAMS:
                        target = f"{path}?{name}"
                        print(f"[!] Logged {ind_type}: {target}")
                        log_finding(cursor, url, category, ind_type, target,
                                    f"filter/sort parameter, example: {value[:80]}")

            # 7. Database errors already visible in the response. Passive only —
            #    the auditor never sends payloads of its own.
            elif ind_type == "SQL Syntax Errors":
                for pattern, engine_name in SQL_ERROR_SIGNATURES:
                    match = pattern.search(html or '')
                    if match:
                        target = f"{path} [{engine_name}]"
                        print(f"[!] Logged {ind_type}: {engine_name} error text on {path}")
                        log_finding(cursor, url, category, ind_type, target,
                                    f"matched: {match.group(0)[:120]}")
                        break

            else:
                # No handler for this rule. Surface it once instead of silently
                # dropping it, so the rule store can't overstate coverage.
                unhandled.add(ind_type)

        db_conn.commit()

    except Exception as e:
        print(f"[-] Fetch failed for {url}: {e}")


def parse_args():
    p = argparse.ArgumentParser(
        description="Audit spidered pages for PHP transaction indicators, "
                    "optionally rendering JavaScript with a headless browser."
    )
    p.add_argument("--spider-db", default="spider_results.db", help="Spider results database")
    p.add_argument("--indicator-db", default="php_indicators.db", help="Indicator rules database")
    p.add_argument("--out", default="audit_results.db", help="Output findings database")
    p.add_argument(
        "--engine", choices=["auto", "playwright", "requests"], default="auto",
        help="auto (default): render JS with Playwright if installed, else static requests.",
    )
    p.add_argument("--timeout", type=int, default=10000, help="Per-page timeout in ms (default: 10000)")
    p.add_argument(
        "--append", action="store_true",
        help="Keep findings already in the output database. By default each run "
             "starts from an empty findings table.",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    targets = load_urls(args.spider_db)
    rules = load_indicators(args.indicator_db)

    if not targets or not rules:
        print("Missing required databases. Ensure spider and indicator DBs are populated.")
    else:
        print(f"Loaded {len(targets)} targets and {len(rules)} rules. Beginning audit...")

        unhandled = set()
        results_db = setup_results_db(args.out, append=args.append)
        with ContentFetcher(engine=args.engine, timeout_ms=args.timeout) as fetcher:
            for target, source in targets:
                audit_page(target, source, fetcher, rules, results_db, unhandled)

        if unhandled:
            print(f"\n[!] {len(unhandled)} indicator rule(s) have no handler and were "
                  f"skipped: {', '.join(sorted(unhandled))}")

        cur = results_db.cursor()
        cur.execute("SELECT COUNT(*), IFNULL(SUM(occurrences), 0) FROM findings")
        distinct, total = cur.fetchone()
        results_db.close()
        print(f"\nAudit complete. {distinct} distinct finding(s) from {total} observation(s). "
              f"Results saved to {args.out}.")
