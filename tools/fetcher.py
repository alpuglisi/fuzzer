import sqlite3
import requests
from bs4 import BeautifulSoup
import logging
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='%(message)s')

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

def audit_page(url, session, indicators, db_conn):
    """Fetches the page and applies checks, logging results to the DB."""
    print(f"\n--- Auditing: {url} ---")
    cursor = db_conn.cursor()
    
    try:
        response = session.get(url, timeout=3)
        parsed_url = urlparse(url)
        
        is_html = 'text/html' in response.headers.get('Content-Type', '')
        soup = BeautifulSoup(response.text, 'html.parser') if is_html else None

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
                        log_finding(cursor, url, category, ind_type, action, str(form)[:150]) # Save first 150 chars of form
            
            # 3. Input Name Checks
            elif ind_type == "Input Names" and soup:
                for hidden in soup.find_all('input', type='hidden'):
                    name = hidden.get('name', 'Unknown')
                    val = hidden.get('value', '')
                    print(f"[!] Logged {ind_type}: field '{name}'")
                    log_finding(cursor, url, category, ind_type, name, str(hidden))

        db_conn.commit()

    except requests.RequestException as e:
        print(f"[-] Connection failed for {url}: {e}")

if __name__ == "__main__":
    targets = load_urls()
    rules = load_indicators()
    
    if not targets or not rules:
        print("Missing required databases. Ensure spider and indicator DBs are populated.")
    else:
        print(f"Loaded {len(targets)} targets and {len(rules)} rules. Beginning audit...")
        
        session = requests.Session()
        results_db = setup_results_db()
        
        for target in targets:
            audit_page(target, session, rules, results_db)
            
        results_db.close()
        print("\nAudit complete. Results saved to audit_results.db.")
