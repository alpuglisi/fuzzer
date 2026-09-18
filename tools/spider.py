import argparse
import logging
import sqlite3
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# Configure logging for production-ready output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Optional JavaScript rendering. Playwright drives a real (headless) browser, so
# content and links produced by JavaScript become visible. If it is not
# installed the crawler falls back to the static requests engine.
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


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
                rendered INTEGER DEFAULT 0
            )
        ''')
        # Add columns that older result databases won't have.
        for col, decl in (("title", "TEXT"), ("content", "TEXT"), ("rendered", "INTEGER DEFAULT 0")):
            try:
                self.cursor.execute(f"ALTER TABLE discovered_pages ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError:
                pass  # column already exists
        self.conn.commit()

    def mark_visited(self, url, status_code, depth, title=None, content=None, rendered=0):
        """Records a URL (and any parsed content). Returns False if already present."""
        try:
            self.cursor.execute('''
                INSERT INTO discovered_pages (url, status_code, depth, title, content, rendered)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (url, status_code, depth, title, content, int(rendered)))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # URL already exists in the unique column
            return False

    def is_visited(self, url):
        """Checks if a URL has already been processed."""
        self.cursor.execute('SELECT 1 FROM discovered_pages WHERE url = ?', (url,))
        return self.cursor.fetchone() is not None

    def close(self):
        self.conn.close()


class LocalSpider:
    """Crawls a local site, optionally rendering JavaScript with a headless browser."""

    def __init__(self, start_url, max_depth=3, db_name="spider_results.db",
                 engine="auto", timeout_ms=10000):
        self.start_url = start_url
        self.max_depth = max_depth
        self.storage = StorageManager(db_name)
        self.timeout_ms = timeout_ms

        # Using a Session enables connection pooling for the static engine.
        self.session = requests.Session()

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
        self._page = None

    # ----- browser lifecycle (Playwright engine only) -----
    def _start_browser(self):
        import os
        self._pw = sync_playwright().start()
        # --no-sandbox / --disable-dev-shm-usage keep Chromium happy in
        # containers and when running as root.
        launch_kwargs = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        # Optional override: point at a specific Chromium binary (useful when the
        # managed browser version does not match, e.g. a pre-installed browser).
        exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if exe:
            launch_kwargs["executable_path"] = exe
        self._browser = self._pw.chromium.launch(**launch_kwargs)
        self._page = self._browser.new_page()

    def _stop_browser(self):
        try:
            if self._browser:
                self._browser.close()
        finally:
            if self._pw:
                self._pw.stop()

    def _is_local(self, url):
        """Ensures the crawler doesn't escape to the open web.

        Uses hostname (not netloc) so a port such as :8080 does not cause a
        local URL to be rejected.
        """
        return urlparse(url).hostname in ['localhost', '127.0.0.1']

    # ----- fetchers -----
    def _fetch_static(self, url):
        """No JavaScript. Parses the raw HTML with BeautifulSoup."""
        resp = self.session.get(url, timeout=self.timeout_ms / 1000)
        ct = resp.headers.get('Content-Type', '')
        title, text, links = None, None, []
        if 'text/html' in ct:
            soup = BeautifulSoup(resp.text, 'html.parser')
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
            text = soup.get_text(" ", strip=True)
            links = [a['href'] for a in soup.find_all('a', href=True)]
        return resp.status_code, ct, title, text, links

    def _fetch_rendered(self, url):
        """Renders with headless Chromium, then reads links and text from the live DOM."""
        response = self._page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        status = response.status if response else 0
        ct = (response.headers or {}).get('content-type', '') if response else ''

        title, text, links = None, None, []
        if 'text/html' in ct or ct == '':
            # Let JavaScript-driven fetch()/render settle (best effort).
            try:
                self._page.wait_for_load_state("networkidle", timeout=self.timeout_ms)
            except Exception:
                pass
            title = self._page.title()
            # Links and text come from the RENDERED DOM, so JS-injected nav links
            # and JS-built content are included.
            links = self._page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')
            try:
                text = self._page.inner_text('body')
            except Exception:
                text = None
        return status, ct, title, text, links

    def crawl(self):
        queue = [(self.start_url, 0)]
        logging.info(f"Starting crawl at {self.start_url} (max_depth={self.max_depth})")

        if self.engine == "playwright":
            self._start_browser()

        try:
            while queue:
                current_url, depth = queue.pop(0)

                if depth > self.max_depth or self.storage.is_visited(current_url):
                    continue

                try:
                    if self.engine == "playwright":
                        status, ct, title, text, raw_links = self._fetch_rendered(current_url)
                    else:
                        status, ct, title, text, raw_links = self._fetch_static(current_url)

                    content = (text or "")[:8000]
                    self.storage.mark_visited(
                        current_url, status, depth, title, content,
                        rendered=1 if self.engine == "playwright" else 0,
                    )
                    logging.info(
                        f"[{status}] depth {depth}: {current_url}"
                        + (f" — {len(raw_links)} link(s)" if raw_links else "")
                    )

                    if depth < self.max_depth and ('text/html' in ct or ct == ''):
                        for href in raw_links:
                            absolute_link = urljoin(current_url, href).split('#')[0]
                            if self._is_local(absolute_link) and not self.storage.is_visited(absolute_link):
                                queue.append((absolute_link, depth + 1))

                except Exception as e:
                    logging.error(f"Failed to process {current_url}: {e}")
                    self.storage.mark_visited(current_url, 0, depth)

        except KeyboardInterrupt:
            logging.info("Crawl interrupted by user.")
        finally:
            if self.engine == "playwright":
                self._stop_browser()
            self.storage.close()
            logging.info("Crawl finished. Data saved to SQLite database.")


def parse_args():
    p = argparse.ArgumentParser(
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
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    spider = LocalSpider(
        args.start,
        max_depth=args.max_depth,
        db_name=args.db,
        engine=args.engine,
        timeout_ms=args.timeout,
    )
    spider.crawl()
