# Basic Reflected XSS Lab — Cyber Security Assignment

- **Student:** Ashish (IIT2024261, Group 10)
- **Topic:** Web Server Security — Exploitation and Mitigation of Reflected XSS
- **Technology:** Node.js, Express.js, HTML, CSS

---

## 1. Project Overview

This project is a minimal, beginner-friendly web application designed to demonstrate:
1. **Vulnerable Route (`/vulnerable`)**: Receives user input from a form or URL query string and reflects it directly into the HTML response without escaping. An injected `<script>` tag executes in the browser.
2. **Secured Route (`/secure`)**: Receives the exact same input, but sanitizes it using HTML entity encoding before rendering. The payload is displayed as safe text and does not execute.

---

## 2. Project Files

```text
cs assignmet 4/
├── package.json          # Dependencies & npm scripts
├── server.js             # Backend Express server (pure routing & escaping logic)
├── public/               # Frontend static assets
│   ├── style.css         # Clean, modern CSS stylesheet
│   └── script.js         # Client-side helper scripts
├── views/                # Frontend HTML templates
│   ├── index.html        # Home / portal page
│   ├── vulnerable.html   # Vulnerable route template
│   └── secure.html       # Secured route template
├── README.md             # Documentation & lab explanations
└── .gitignore            # Excludes node_modules
```

---

## 3. How to Install and Run

### Step 1: Install Dependencies
Open your terminal in this folder and run:
```bash
npm install
```
*(On Windows PowerShell, if scripts are restricted, run: `npm.cmd install`)*

### Step 2: Start the Server
```bash
npm start
```
*(Or run `node server.js`)*

### Step 3: Open in Browser
- **Home:** [http://localhost:3000/](http://localhost:3000/)
- **Vulnerable Page:** [http://localhost:3000/vulnerable](http://localhost:3000/vulnerable)
- **Secured Page:** [http://localhost:3000/secure](http://localhost:3000/secure)

---

## 4. How to Test

### Test Payload (Harmless PoC):
```html
<script>alert('XSS')</script>
```

### Steps:
1. Go to `http://localhost:3000/vulnerable`.
2. Enter `<script>alert('XSS')</script>` in the input box and click **Submit**.
   - **Result:** An alert box showing `XSS` immediately pops up. The script executed.
3. Now go to `http://localhost:3000/secure`.
4. Enter the exact same payload `<script>alert('XSS')</script>` and click **Submit**.
   - **Result:** No alert box appears. The text `<script>alert('XSS')</script>` is displayed safely as harmless plain text on the page.

---

## 5. Explanation of Vulnerability & Root Cause

### What is Reflected XSS?
Reflected Cross-Site Scripting (XSS) occurs when an application receives data from an HTTP request (such as a form submission or URL parameter `?name=...`) and immediately includes that data in the HTTP response HTML without sanitizing it.

### Root Cause in `server.js`
In the vulnerable route:
```javascript

const resultHtml = name ? `<p style="font-size: 18px;">Hello, <strong>${name}</strong>!</p>` : '';
```
The variable `name` is inserted raw into the HTML string. When the browser receives the HTML from the server, its HTML parser sees `<script>` and assumes it is legitimate code meant to be run, executing the JavaScript.

### How the Mitigation Works in `server.js`
In the secured route:
```javascript

const resultHtml = name ? `<p style="font-size: 18px;">Hello, <strong>${escapeHtml(name)}</strong>!</p>` : '';
```
Before inserting `name`, we pass it through `escapeHtml()`:
- `<` becomes `&lt;`
- `>` becomes `&gt;`
- `&` becomes `&amp;`
- `"` becomes `&quot;`
- `'` becomes `&#39;`

When the browser parses `&lt;script&gt;`, it does not recognize an opening `<` bracket. It treats the characters as plain text and displays them on screen without executing any code.

---

## 6. Alternative Mitigations (Theory)

1. **Framework Auto-Escaping:**
   Modern frontend frameworks (like React, Angular, or Vue) automatically escape variables rendered inside templates (e.g., `{userName}` in React). They treat data as text nodes unless a developer explicitly uses an unsafe method like `dangerouslySetInnerHTML`.

2. **HTML Sanitisation:**
   If an application intentionally needs to allow user-submitted HTML (like a rich text blog post with `<b>` or `<i>`), simple escaping cannot be used because it would break formatting. Instead, an HTML sanitizer library (such as DOMPurify) is used to parse the HTML, keep safe tags, and strip out dangerous tags like `<script>` or event handlers like `onload` and `onerror`.

3. **Content Security Policy (CSP):**
   CSP is an HTTP response header (e.g., `Content-Security-Policy: default-src 'self'`) that tells the browser which script sources are allowed. A strong CSP disables inline scripts and prevents untrusted scripts from running even if an injection flaw exists. It serves as defense-in-depth.

4. **HttpOnly Cookies:**
   A cookie flag (`Set-Cookie: session=abc; HttpOnly`) that blocks JavaScript from accessing `document.cookie`. This prevents attackers from stealing session cookies via XSS. Note: HttpOnly does *not* prevent XSS itself; an attacker can still execute actions on the user's behalf.

5. **Safe DOM Sinks:**
   When manipulating the DOM with client-side JavaScript, developers should use safe properties like `element.textContent` rather than `element.innerHTML`. `textContent` assigns data directly as text without invoking the browser's HTML parser.
