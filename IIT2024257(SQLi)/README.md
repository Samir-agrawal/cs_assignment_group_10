# SQL Injection (SQLi)

**Student Name:** G.P. Chandra Sekhar  
**Roll Number:** IIT2024257  
**Category:** SQL Injection  
**Variant Implemented:** Variant 1: Authentication Bypass  

---

## Overview
This module demonstrates an SQL Injection vulnerability on an authentication login form where user input is directly concatenated into a SQL query string without parameterization or escaping.

### (a) Vulnerable Implementation
The login route dynamically constructs SQL queries via string concatenation:
```javascript
// Vulnerable query construction:
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.get(query, (err, row) => {
  if (row) {
    req.session.user = row.username;
    return res.redirect('/dashboard');
  }
  return res.status(401).send("Invalid credentials");
});
```

### (b) Working Exploit
* **Payload injected in username field:**
  ```sql
  admin' --
  ```
  *(or `admin' OR '1'='1' --`)*
* **Resulting executed query:**
  ```sql
  SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
  ```
  The comment operator (`--`) causes the database to ignore the remainder of the query (the password check), allowing an unauthenticated attacker to immediately log in as the `admin` user.

### (c) Root Cause
The application constructs database queries by directly concatenating unvalidated, unsanitized user-supplied input into the SQL command text, allowing attacker input to break out of data context and alter query structure.

### (d) Implemented Mitigation
**Parameterized Queries (Prepared Statements):**
```javascript
// Secure parameterized query:
const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
db.get(query, [username, password], (err, row) => {
  // Database treats input strictly as literal string values, preventing injection
});
```
When injecting `admin' --`, the database searches for a literal username equal to `admin' --`, causing the exploit to fail completely.

### (e) Other Mitigations (Theory)
1. **Input Validation with Allow-lists:** Validating inputs against strict character sets (e.g., alphanumeric only for usernames) to reject malicious metacharacters (`'`, `"`, `--`, `;`).
2. **Least-Privilege Database Accounts:** Running the application under database accounts configured with only the minimum necessary permissions (`SELECT`, `INSERT`), restricting access to `DROP`, `GRANT`, or administrative system tables.
3. **Safe Error Handling:** Suppressing detailed database stack traces or SQL syntax errors from being returned to the client to prevent reconnaissance.
