import sqlite3
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Each indicator's `reference` is the folder under references/ whose payloads
# apply to that finding, so the auditor's summary points straight at the
# matching payload catalogue. The indicator_type MUST match a handler key in
# fetcher.py's RULES registry, or the rule silently never runs.
#
# Columns: (category, indicator_type, description, example, reference)
INDICATORS = [
    # --- URL parameters (GET) -------------------------------------------------
    ("URL Parameters (GET)", "Query Strings",
     "Variables passed directly in the URL indicating a backend database lookup.",
     "?id=45 or ?category=electronics", "sql-injection"),
    ("URL Parameters (GET)", "Predictable IDs",
     "Sequential numbers in URLs that likely map to primary keys.",
     "view.php?id=101 -> view.php?id=102", "insecure-direct-object-references"),
    ("URL Parameters (GET)", "Filtered Views",
     "Sort/paginate/filter parameters that reach SQL ORDER BY or LIMIT clauses.",
     "?sort=price&limit=50", "sql-injection"),
    ("URL Parameters (GET)", "File Path Parameters",
     "Parameters that name a file or path, reachable by inclusion or traversal.",
     "?page=home or ?file=/etc/passwd", "file-inclusion"),
    ("URL Parameters (GET)", "URL Parameters",
     "Parameters carrying a URL the server may fetch (SSRF candidate).",
     "?url=http://internal/ or ?image_url=...", "server-side-request-forgery"),
    ("URL Parameters (GET)", "Redirect Parameters",
     "Parameters that control the next location (open-redirect candidate).",
     "?next=/account or ?redirect=//evil", "open-redirect"),
    ("URL Parameters (GET)", "Command Parameters",
     "Parameters whose name suggests a shell or system utility.",
     "?ping=127.0.0.1 or ?cmd=ls", "command-injection"),
    ("URL Parameters (GET)", "LDAP Parameters",
     "Parameters resembling directory attributes (LDAP injection candidate).",
     "?uid=admin or ?cn=...", "ldap-injection"),
    ("URL Parameters (GET)", "XPath Parameters",
     "Parameters that name an XML node or query (XPath injection candidate).",
     "?xpath=//user or ?node=...", "xpath-injection"),
    ("URL Parameters (GET)", "Template Parameters",
     "Parameters selecting a template or view (SSTI candidate).",
     "?template=welcome or ?theme=...", "server-side-template-injection"),
    ("URL Parameters (GET)", "Duplicated Parameters",
     "The same parameter supplied more than once (HTTP parameter pollution).",
     "?id=1&id=2", "http-parameter-pollution"),

    # --- HTML forms (POST) ----------------------------------------------------
    ("HTML Forms (POST)", "Action Attributes",
     "Form tags pointing to a backend script, indicating a DB insert or update.",
     "<form action=\"process_login.php\" method=\"POST\">", "sql-injection"),
    ("HTML Forms (POST)", "Input Names",
     "Named form fields a user can submit (reflected/stored XSS surface).",
     "<input name=\"q\"> or <textarea name=\"bio\">", "xss"),
    ("HTML Forms (POST)", "Upload Fields",
     "File upload inputs (unrestricted upload candidate).",
     "<input type=\"file\" name=\"avatar\">", "upload-insecure-files"),
    ("HTML Forms (POST)", "Privileged Hidden Fields",
     "Client-supplied fields that look privileged (mass-assignment candidate).",
     "<input type=\"hidden\" name=\"role\" value=\"user\">", "mass-assignment"),
    ("HTML Forms (POST)", "Unprotected Forms",
     "POST forms with no anti-CSRF token among their fields.",
     "<form method=\"POST\"> ... no csrf token ...", "cross-site-request-forgery"),

    # --- Dynamic behaviours ---------------------------------------------------
    ("Dynamic Behaviors", "AJAX Live Search",
     "Background fetch/XHR calls that query a database directly.",
     "api/search.php?q=a", "sql-injection"),
    ("Dynamic Behaviors", "Reflected Values",
     "A request parameter echoed verbatim into the response (reflected XSS pre-req).",
     "?q=<script> reflected in the page body", "xss"),
    ("Dynamic Behaviors", "DOM Sinks",
     "Client-side script sending an attacker-reachable source into a dangerous sink.",
     "location.hash -> element.innerHTML", "xss"),
    ("Dynamic Behaviors", "Prototype Pollution Vectors",
     "A parameter or recursive-merge sink that can reach Object.prototype.",
     "?__proto__[x]=1 or $.extend(true, ...)", "prototype-pollution"),
    ("Dynamic Behaviors", "GraphQL Endpoints",
     "A GraphQL endpoint (introspection and query-depth candidate).",
     "/graphql", "graphql-injection"),
    ("Dynamic Behaviors", "Export Endpoints",
     "Endpoints/parameters producing CSV/spreadsheet output (CSV injection).",
     "?export=csv or /download.csv", "csv-injection"),
    ("Dynamic Behaviors", "Unsafe Target Blank",
     "target=_blank links without rel=noopener (reverse tabnabbing).",
     "<a target=\"_blank\" href=\"...\">", "tabnabbing"),

    # --- Data formats & error induction ---------------------------------------
    ("Data Formats", "XML Inputs",
     "Endpoints/fields accepting XML (XXE and stylesheet injection candidate).",
     "Content-Type: text/xml or name=\"xml\"", "xxe-injection"),
    ("Data Formats", "NoSQL Operators",
     "Bracketed parameters or values carrying document-store operators.",
     "?user[$ne]= or {\"$gt\": \"\"}", "nosql-injection"),
    ("Data Formats", "SSI Enabled Pages",
     "Pages served with an SSI-processed extension.",
     "page.shtml", "server-side-include-injection"),
    ("Data Formats", "Serialized Tokens",
     "Serialized blobs/tokens in responses or inputs (deserialization candidate).",
     "JWT, PHP/Java serialized objects, pickles", "insecure-deserialization"),
    ("Error Induction", "SQL Syntax Errors",
     "A raw database error already visible in the response body.",
     "?id=45' -> 'You have an error in your SQL syntax near...'", "sql-injection"),
]


def build_indicator_database(db_name="php_indicators.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Fresh schema every build so the reference column and rows stay in sync
    # with fetcher.py. Dropping avoids stale columns from older versions.
    cursor.execute('DROP TABLE IF EXISTS indicators')
    cursor.execute('''
        CREATE TABLE indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            description TEXT NOT NULL,
            example TEXT NOT NULL,
            reference TEXT NOT NULL
        )
    ''')

    cursor.executemany('''
        INSERT INTO indicators (category, indicator_type, description, example, reference)
        VALUES (?, ?, ?, ?, ?)
    ''', INDICATORS)

    conn.commit()
    logging.info(f"Successfully populated '{db_name}' with {len(INDICATORS)} indicators.")

    logging.info("\n--- Current Database Contents ---")
    cursor.execute('SELECT category, indicator_type, reference FROM indicators ORDER BY id')
    for category, indicator_type, reference in cursor.fetchall():
        print(f"[{category}] {indicator_type} -> references/{reference}/")

    conn.close()


if __name__ == "__main__":
    build_indicator_database()
