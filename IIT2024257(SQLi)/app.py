"""
Cyber Security (IT-30001) — Web Server Security Assignment
SQL Injection — Variant 1: Authentication Bypass
Mitigation implemented: Parameterized Queries (prepared statements)

This single Flask app intentionally ships BOTH an insecure and a secure
implementation of the same login feature behind a mode switch, so the
grader/viva panel can see the exact same payload succeed against the
vulnerable code path and fail against the mitigated one.

DO NOT deploy this application anywhere public. It is a teaching artifact.
"""

import sqlite3
import os
from flask import Flask, render_template, request, g, session, redirect, url_for

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "app.db")

app = Flask(__name__)
app.secret_key = "dev-only-secret-key-change-me"


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """(Re)create the database with a couple of demo accounts."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
        """
    )
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("admin", "Sup3rSecretAdminPass!", "admin"),
            ("alice", "alicepassword123", "user"),
            ("bob", "bobbyB0bPass", "user"),
        ],
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# VULNERABLE implementation
# --------------------------------------------------------------------------
def login_vulnerable(username: str, password: str):
    """
    VULNERABLE CODE PATH.

    Root cause: user-controlled input (`username`, `password`) is
    concatenated directly into the SQL statement text using an f-string.
    The database driver therefore cannot distinguish attacker-supplied
    data from SQL syntax, so a crafted string can terminate the intended
    WHERE clause and inject arbitrary boolean logic or additional clauses.

    Example payload (authentication bypass, no valid credentials needed):
        username:  admin' --
        password:  anything

    Resulting query sent to SQLite:
        SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'

    Everything after `--` becomes a SQL comment, so the password check is
    stripped out entirely and the attacker is logged in as 'admin'.

    A second classic payload that needs no valid username at all:
        username:  ' OR '1'='1' --
        password:  anything
    """
    db = get_db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        cur = db.execute(query)
        row = cur.fetchone()
    except sqlite3.OperationalError as e:
        return None, query, f"SQL error: {e}"
    return row, query, None


# --------------------------------------------------------------------------
# SECURE implementation — MITIGATION: parameterized queries
# --------------------------------------------------------------------------
def login_secure(username: str, password: str):
    """
    MITIGATED CODE PATH.

    Fix applied: parameterized queries (prepared statements) via the
    DB-API '?' placeholder mechanism. The SQL text is compiled by SQLite
    BEFORE the user-supplied values are bound to it, so `username` and
    `password` are only ever treated as literal data values — never as
    SQL syntax — no matter what characters they contain. Quotes,
    `--`, `OR 1=1`, etc. are all inert here.
    """
    db = get_db()
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cur = db.execute(query, (username, password))
    row = cur.fetchone()
    shown_query = f"SELECT * FROM users WHERE username = ? AND password = ?  -- bound params: ({username!r}, {password!r})"
    return row, shown_query, None


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("login", mode="vulnerable"))


@app.route("/login/<mode>", methods=["GET", "POST"])
def login(mode):
    if mode not in ("vulnerable", "secure"):
        mode = "vulnerable"

    result = None
    executed_query = None
    error = None
    username = ""
    password = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if mode == "vulnerable":
            row, executed_query, error = login_vulnerable(username, password)
        else:
            row, executed_query, error = login_secure(username, password)

        if row is not None:
            result = {
                "success": True,
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
            }
        else:
            result = {"success": False}

    return render_template(
        "login.html",
        mode=mode,
        result=result,
        executed_query=executed_query,
        error=error,
        username=username,
        password=password,
    )


@app.route("/reset-db")
def reset_db():
    """Convenience endpoint to restore the demo DB to its original state."""
    init_db()
    return redirect(url_for("login", mode="vulnerable"))


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    else:
        init_db()  # always start from a clean, known state during the demo
    app.run(debug=True, host="127.0.0.1", port=5000)
