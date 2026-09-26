"""
Legacy Insecure User Portal (Vulnerable Baseline)
Contains deliberate vulnerabilities: SQL Injection, Command Injection, Plaintext Secrets.
"""

import sqlite3
import os

DB_FILE = "insecure_users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, role TEXT)")
    c.execute("DELETE FROM users")
    # Vulnerability 1: Plaintext password storage
    c.execute("INSERT INTO users VALUES ('admin', 'SuperSecretAdminPass123', 'admin')")
    c.execute("INSERT INTO users VALUES ('alice', 'alicepassword', 'user')")
    conn.commit()
    conn.close()

def login_vulnerable(username, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Vulnerability 2: SQL Injection via direct f-string formatting
    query = f"SELECT role FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"[DEBUG QUERY] {query}")
    try:
        c.execute(query)
        res = c.fetchone()
        conn.close()
        return res[0] if res else None
    except Exception as e:
        # Vulnerability 3: Verbose error leaking schema internals
        print(f"[LEAK ERROR] Database error: {e}")
        return None

def ping_user_host_vulnerable(hostname):
    # Vulnerability 4: OS Command Injection via unvalidated shell string
    cmd = f"ping -c 1 {hostname}"
    os.system(cmd)

if __name__ == "__main__":
    init_db()
    print("Insecure authentication portal initialized.")
