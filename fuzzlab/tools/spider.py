import argparse
import logging
import sqlite3
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from fuzzlab.core import get_logger

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
                rendered INTEGER DEFAULT 0,
                source TEXT DEFAULT 'link'
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

    def reset(self):
        """Clears previous results so a fresh crawl starts from an empty map."""
        self.cursor.execute('DELETE FROM discovered_pages')
        self.conn.commit()

    def count(self):
        self.cursor.execute('SELECT COUNT(*) FROM discovered_pages')
        return self.cursor.fetchone()[0]

    def mark_visited(self, url, status_code, depth, title=None, content=None,
                     rendered=0, source='link'):
        """Records a URL (and any parsed content). Returns False if already present."""
        try:
            self.cursor.execute('''
                INSERT INTO discovered_pages (url, status_code, depth, title, content, rendered, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (url, status_code, depth, title, content, int(rendered), source))
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
                 engine="auto", timeout_ms=10000, resume=False):
        self.start_url = start_url
        self.max_depth = max_depth
        self.storage = StorageManager(db_name)
        self.timeout_ms = timeout_ms
        self.resume = resume

        # A crawl normally rebuilds the whole map. Without this, a second run
        # against an existing database finds every URL already "visited" and
        # exits having crawled nothing. Pass resume=True to keep prior rows.
        if resume:
            logging.info(f"Resuming: {self.storage.count()} page(s) already in {db_name} will be skipped.")
        else:
            self.storage.reset()

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
        # URLs requested by JavaScript (fetch/XHR) during the current navigation.
        self._xhr_urls = []

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
        # Record fetch()/XMLHttpRequest targets. These endpoints are where a
        # JavaScript-rendered page actually gets its data, and they never appear
        # as <a href> anywhere, so link-following alone can never reach them.
        self._page.on("request", self._on_request)

    def _on_request(self, request):
        try:
            if request.resource_type in ("xhr", "fetch"):
                self._xhr_urls.append(request.url)
        except Exception:
            pass  # never let instrumentation break a crawl

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
        return status, ct, title, text, links, list(dict.fromkeys(self._xhr_urls))

    def crawl(self):
        queue = [(self.start_url, 0, 'link')]
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
                    logging.info(
                        f"[{status}] depth {depth}: {current_url}"
                        + (f" — {len(raw_links)} link(s)" if raw_links else "")
                        + (f", {len(xhr_links)} XHR endpoint(s)" if xhr_links else "")
                    )

                    if depth < self.max_depth:
                        if 'text/html' in ct or ct == '':
                            for href in raw_links:
                                absolute_link = urljoin(current_url, href).split('#')[0]
                                if self._is_local(absolute_link) and not self.storage.is_visited(absolute_link):
                                    queue.append((absolute_link, depth + 1, 'link'))
                        # XHR/fetch targets are queued whatever the page's own
                        # content type, so JSON APIs behind rendered pages land
                        # in the map and get audited like any other URL.
                        for href in xhr_links:
                            absolute_link = urljoin(current_url, href).split('#')[0]
                            if self._is_local(absolute_link) and not self.storage.is_visited(absolute_link):
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
    p.add_argument(
        "--resume", action="store_true",
        help="Keep results already in the database and skip those URLs. "
             "By default each run clears the table and re-crawls.",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    get_logger("crawler").info("crawler starting",
                               extra={"start": args.start, "engine": args.engine})
    spider = LocalSpider(
        args.start,
        max_depth=args.max_depth,
        db_name=args.db,
        engine=args.engine,
        timeout_ms=args.timeout,
        resume=args.resume,
    )
    spider.crawl()
