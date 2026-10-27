# SQL Injection — Authentication Bypass (Variant 1)
**IT-30001 Cyber Security | Web Server Security Assignment | IIIT Allahabad**

This folder contains the SQL injection portion of the group's submission.
It is a self-contained Flask application that demonstrates an authentication-bypass
SQL injection and its mitigation via **parameterized queries**, with a toggle to run
either the vulnerable or the secure code path against the same UI.

## Table 3 — Ownership

| Member name | Roll number | Category | Variant implemented |
|---|---|---|---|
| **G.P. Chandra Sekhar** | **IIT2024257** | SQL Injection | Variant 1 — Authentication bypass |

## How to run

```bash
pip install flask
python app.py
```

Then open `http://127.0.0.1:5000/` in a browser. Use the **Vulnerable mode / Secure mode**
switch at the top of the page to flip between the two implementations without restarting
the server.

Demo accounts (seeded automatically, also resettable via the "reset demo database" link):

| username | password | role |
|---|---|---|
| admin | Sup3rSecretAdminPass! | admin |
| alice | alicepassword123 | user |
| bob | bobbyB0bPass | user |

## (a) Vulnerable implementation

`login_vulnerable()` in `app.py` builds the SQL statement with an f-string:

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cur = db.execute(query)
```

## (b) Working exploit

With **Vulnerable mode** selected, submit the login form with:

- Username: `admin' --`
- Password: *(anything, e.g. `x`)*

The server builds and executes:

```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'x'
```

`--` starts a SQL comment, so everything after it is discarded. The query becomes
"find the user named admin," with no password check at all, and the app logs in as
`admin` without knowing the real password.

A second payload that needs no valid username either:

- Username: `' OR '1'='1' --`
- Password: *(anything)*

which turns the WHERE clause into an always-true condition and returns the first row
in the table.

Both payloads are available as one-click chips in the UI, and both are exercised by
the automated test in `test_app.py`.

## (c) Root cause

User-supplied input (`username`, `password`) is concatenated directly into the SQL
statement's **text**, so the database cannot tell attacker-supplied characters (quotes,
`--`, boolean operators) apart from the actual SQL syntax of the query. Input and code
share the same channel.

## (d) Mitigation implemented — Parameterized queries

`login_secure()` uses the DB-API placeholder mechanism instead of string building:

```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cur = db.execute(query, (username, password))
```

The SQL text (with `?` placeholders) is parsed and compiled by SQLite **before** the
user's values are ever substituted in. The values are then bound to the already-fixed
query plan purely as literal data — they can never change the structure of the query,
no matter what characters they contain. Submitting the exact same payload
(`admin' --`) in **Secure mode** returns "Authentication failed," because SQLite now
looks for a user literally named `admin' --`, which does not exist. A screenshot of
this blocked attempt (shown in the "Execution trace" panel, which displays the bound
parameters) should be captured for the video.

## (e) Other mitigations (theory only, not implemented)

- **Input validation with allow-lists** — restrict the username field to a known-safe
  character set (e.g. alphanumerics and underscore) before it ever reaches the query,
  rejecting anything containing quotes or SQL metacharacters outright.
- **Least-privilege database accounts** — the account the web app connects with
  should only have the minimum rights it needs (e.g. `SELECT` on the `users` table),
  so that even a successful injection cannot read other tables, modify data, or run
  administrative commands.
- **Safe/generic error handling** — never return raw database error messages or the
  executed SQL to the client; a verbose error (as deliberately shown for teaching
  purposes in this app's vulnerable mode) can leak schema details that help an
  attacker refine further injection attempts.

Together with parameterized queries, these form defense-in-depth: parameterization
closes the actual vulnerability, while the others reduce the blast radius if a flaw
is ever introduced elsewhere.

## File overview

```
app.py              Flask app: vulnerable + secure login implementations, routes
templates/login.html  Front-end UI (mode switch, payload chips, execution trace)
test_app.py          Automated checks: bypass works in vulnerable mode, fails in secure mode
app.db               SQLite database (auto-created/reset on startup)
```
