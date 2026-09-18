import argparse
import logging
import os
import sqlite3
from urllib.parse import urlparse

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


def load_urls(spider_db="spider_results.db"):
    """Extracts the mapped URLs from the spider's database."""
    try:
        conn = sqlite3.connect(spider_db)
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM discovered_pages ORDER BY depth ASC")
        urls = [row[0] for row in cursor.fetchall()]
        conn.close()
        return urls
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


def setup_results_db(db_name="audit_results.db"):
    """Initializes the database to store discovered PHP transactions."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_url TEXT NOT NULL,
            category TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            target_identifier TEXT NOT NULL,
            html_context TEXT
        )
    ''')
    conn.commit()
    return conn


def log_finding(cursor, url, category, trans_type, target, context=""):
    """Inserts a specific finding into the database."""
    cursor.execute('''
        INSERT INTO findings (page_url, category, transaction_type, target_identifier, html_context)
        VALUES (?, ?, ?, ?, ?)
    ''', (url, category, trans_type, target, context))


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
        logging.info(f"Auditor engine: {self.engine}")
        return self

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
        """Returns (status_code, content_type, html). html is the RENDERED DOM
        when the Playwright engine is active, otherwise the raw response body."""
        if self.engine == "playwright":
            response = self._page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            status = response.status if response else 0
            ct = (response.headers or {}).get('content-type', '') if response else ''
            # Let JavaScript-driven DOM updates settle (best effort).
            try:
                self._page.wait_for_load_state("networkidle", timeout=self.timeout_ms)
            except Exception:
                pass
            html = self._page.content()
            return status, ct, html

        resp = self.session.get(url, timeout=self.timeout_ms / 1000)
        return resp.status_code, resp.headers.get('Content-Type', ''), resp.text


def audit_page(url, fetcher, indicators, db_conn):
    """Fetches the page (rendering JS if enabled) and applies checks to the DOM."""
    print(f"\n--- Auditing: {url} ---")
    cursor = db_conn.cursor()

    try:
        status, content_type, html = fetcher.fetch(url)
        parsed_url = urlparse(url)

        is_html = 'text/html' in content_type
        soup = BeautifulSoup(html, 'html.parser') if is_html else None

        for ind_type, category in indicators:

            # 1. URL Parameter Checks
            if ind_type == "Query Strings":
                if parsed_url.query:
                    print(f"[!] Logged {ind_type}: ?{parsed_url.query}")
                    log_finding(cursor, url, category, ind_type, parsed_url.query, "URL Parameter")

            # 2. Form Action Checks
            elif ind_type == "Action Attributes" and soup:
                for form in soup.find_all('form'):
                    action = form.get('action', 'Unknown')
                    method = form.get('method', 'GET').upper()
                    if '.php' in action or action in ['', '#', 'Unknown']:
                        print(f"[!] Logged {ind_type}: '{action}' via {method}")
                        log_finding(cursor, url, category, ind_type, action, str(form)[:150])

            # 3. Input Name Checks
            elif ind_type == "Input Names" and soup:
                for hidden in soup.find_all('input', type='hidden'):
                    name = hidden.get('name', 'Unknown')
                    val = hidden.get('value', '')
                    print(f"[!] Logged {ind_type}: field '{name}'")
                    log_finding(cursor, url, category, ind_type, name, str(hidden))

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
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    targets = load_urls(args.spider_db)
    rules = load_indicators(args.indicator_db)

    if not targets or not rules:
        print("Missing required databases. Ensure spider and indicator DBs are populated.")
    else:
        print(f"Loaded {len(targets)} targets and {len(rules)} rules. Beginning audit...")

        results_db = setup_results_db(args.out)
        with ContentFetcher(engine=args.engine, timeout_ms=args.timeout) as fetcher:
            for target in targets:
                audit_page(target, fetcher, rules, results_db)

        results_db.close()
        print("\nAudit complete. Results saved to audit_results.db.")
