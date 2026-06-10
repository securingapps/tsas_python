"""
SQL Injection Demo — educational purposes only.
Shows a vulnerable query, an exploit payload, and the secure fix.
"""

import sqlite3

DB = ":memory:"


def setup(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.executemany(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [("alice", "s3cr3t"), ("bob", "hunter2"), ("admin", "adminpass")],
    )
    conn.commit()


# --- VULNERABLE -----------------------------------------------------------

def login_vulnerable(conn: sqlite3.Connection, username: str, password: str):
    """
    String interpolation lets an attacker craft a payload that changes query logic.
    Never do this in production.
    """
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"  Query: {query}")
    return conn.execute(query).fetchall()


# --- SECURE ---------------------------------------------------------------

def login_secure(conn: sqlite3.Connection, username: str, password: str):
    """Parameterized query — user input is never interpreted as SQL."""
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print(f"  Query: {query}  params=({username!r}, {password!r})")
    return conn.execute(query, (username, password)).fetchall()


# --- DEMO -----------------------------------------------------------------

def demo() -> None:
    conn = sqlite3.connect(DB)
    setup(conn)

    # 1. Normal login (both versions behave identically here)
    print("\n[1] Legitimate login — alice / s3cr3t")
    print("  Vulnerable:", login_vulnerable(conn, "alice", "s3cr3t"))
    print("  Secure:    ", login_secure(conn, "alice", "s3cr3t"))

    # 2. Classic bypass: ' OR '1'='1
    # The injected payload turns the WHERE clause into always-true,
    # returning every row regardless of the supplied password.
    payload_user = "' OR '1'='1"
    payload_pass = "' OR '1'='1"
    print("\n[2] SQLi bypass payload: username =", repr(payload_user))
    print("  Vulnerable (all rows returned):", login_vulnerable(conn, payload_user, payload_pass))
    print("  Secure     (no rows returned): ", login_secure(conn, payload_user, payload_pass))

    # 3. Comment-based bypass: admin'--
    # The -- comments out the rest of the query, skipping the password check.
    payload_user2 = "admin'--"
    payload_pass2 = "anything"
    print("\n[3] Comment-based bypass: username =", repr(payload_user2))
    print("  Vulnerable (admin row returned):", login_vulnerable(conn, payload_user2, payload_pass2))
    print("  Secure     (no rows returned):  ", login_secure(conn, payload_user2, payload_pass2))

    conn.close()


if __name__ == "__main__":
    demo()
