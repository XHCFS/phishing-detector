import sqlite3

def get_connection():
    conn = sqlite3.connect("emails.db")
    return conn
# THIS IS A PLACEHOLDER
def init_db():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            subject TEXT,
            is_phishing BOOLEAN
        )
    """)
    conn.commit()
    conn.close()

