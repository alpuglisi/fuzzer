import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sqlite3
import logging

# Configure logging for production-ready output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class StorageManager:
    """Handles all database interactions to keep the crawler modular."""
    def __init__(self, db_name="spider_results.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        """Creates the schema if it doesn't exist."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                status_code INTEGER,
                depth INTEGER
            )
        ''')
        self.conn.commit()

    def mark_visited(self, url, status_code, depth):
        """Records a URL in the database. Returns False if already exists."""
        try:
            self.cursor.execute('''
                INSERT INTO discovered_pages (url, status_code, depth)
                VALUES (?, ?, ?)
            ''', (url, status_code, depth))
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
    """Manages the HTTP requests and HTML parsing."""
    def __init__(self, start_url, max_depth=3, db_name="spider_results.db"):
        self.start_url = start_url
        self.max_depth = max_depth
        self.storage = StorageManager(db_name)
        
        # Using a Session enables connection pooling for massive performance gains
        self.session = requests.Session()

    def _is_local(self, url):
        """Ensures the crawler doesn't escape to the open web."""
        return urlparse(url).netloc in ['localhost', '127.0.0.1']

    def crawl(self):
        queue = [(self.start_url, 0)]
        logging.info(f"Starting crawl at {self.start_url}")

        try:
            while queue:
                current_url, depth = queue.pop(0)

                # Skip if we hit the depth limit or if the DB already has this URL
                if depth > self.max_depth or self.storage.is_visited(current_url):
                    continue

                try:
                    response = self.session.get(current_url, timeout=3)
                    status = response.status_code
                    self.storage.mark_visited(current_url, status, depth)
                    
                    logging.info(f"[{status}] Depth {depth}: {current_url}")

                    # Only parse HTML pages for new links
                    if 'text/html' in response.headers.get('Content-Type', '') and depth < self.max_depth:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        for link in soup.find_all('a', href=True):
                            absolute_link = urljoin(current_url, link['href']).split('#')[0]
                            
                            if self._is_local(absolute_link) and not self.storage.is_visited(absolute_link):
                                queue.append((absolute_link, depth + 1))

                except requests.RequestException as e:
                    logging.error(f"Failed to connect to {current_url}: {e}")
                    self.storage.mark_visited(current_url, 0, depth) # 0 denotes connection failure

        except KeyboardInterrupt:
            logging.info("Crawl interrupted by user.")
        finally:
            self.storage.close()
            logging.info("Crawl finished. Data saved to SQLite database.")

if __name__ == "__main__":
    target = "http://localhost"
    spider = LocalSpider(target, max_depth=4)
    spider.crawl()
