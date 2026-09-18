import sqlite3
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def build_indicator_database(db_name="php_indicators.db"):
    # 1. Connect to SQLite (creates the file if it doesn't exist)
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # 2. Create the schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            description TEXT NOT NULL,
            example TEXT NOT NULL
        )
    ''')

    # Clear existing data to prevent duplicates if run multiple times
    cursor.execute('DELETE FROM indicators')

    # 3. Define the indicators based on our previous discussion
    indicators_data = [
        (
            "URL Parameters (GET)", 
            "Query Strings", 
            "Variables passed directly in the URL indicating a backend database lookup.", 
            "?id=45 or ?category=electronics"
        ),
        (
            "URL Parameters (GET)", 
            "Predictable IDs", 
            "Sequential numbers in URLs that likely map to primary keys in a database table.", 
            "view.php?id=101 -> view.php?id=102"
        ),
        (
            "HTML Forms (POST)", 
            "Action Attributes", 
            "Form tags pointing to a backend processing script, often indicating a database insert or update.", 
            "<form action=\"process_login.php\" method=\"POST\">"
        ),
        (
            "HTML Forms (POST)", 
            "Input Names", 
            "Input attributes that mirror typical database column names, including hidden fields.", 
            "<input type=\"hidden\" name=\"user_role\" value=\"customer\">"
        ),
        (
            "Dynamic Behaviors", 
            "AJAX Live Search", 
            "Auto-complete bars making rapid background calls to query a database for matches.", 
            "api/search.php?q=a"
        ),
        (
            "Dynamic Behaviors", 
            "Filtered Views", 
            "UI elements that sort or paginate data, passing instructions to SQL ORDER BY or LIMIT clauses.", 
            "?sort=price&limit=50"
        ),
        (
            "Error Induction", 
            "SQL Syntax Errors", 
            "Unsanitized input (like a single quote) breaking the backend query and returning a raw database error.", 
            "?id=45' -> 'You have an error in your SQL syntax near...'"
        )
    ]

    # 4. Insert the data
    cursor.executemany('''
        INSERT INTO indicators (category, indicator_type, description, example)
        VALUES (?, ?, ?, ?)
    ''', indicators_data)
    
    conn.commit()
    logging.info(f"Successfully populated '{db_name}' with {len(indicators_data)} indicators.")

    # 5. Verify and display the data
    logging.info("\n--- Current Database Contents ---")
    cursor.execute('SELECT category, indicator_type, example FROM indicators')
    for row in cursor.fetchall():
        print(f"[{row[0]}] {row[1]}: {row[2]}")

    conn.close()

if __name__ == "__main__":
    build_indicator_database()
