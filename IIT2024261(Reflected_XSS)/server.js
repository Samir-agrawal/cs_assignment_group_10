/**
 * ============================================================================
 * Cyber Security Lab: Reflected XSS Exploitation & Mitigation
 * Course: IT-30001 | IIIT Allahabad
 * Backend Web Server (Express.js)
 * ============================================================================
 */

const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Serve frontend static assets (CSS & client JS) from 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// Helper to load HTML template files from 'views' folder
function loadView(viewName) {
  return fs.readFileSync(path.join(__dirname, 'views', viewName), 'utf-8');
}

/**
 * HELPER: Context-Appropriate HTML Entity Escaping Function
 * Converts special characters into safe HTML entities so the browser
 * treats them as plain text instead of executable HTML/script tags.
 */
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')   // &  --> &amp;
    .replace(/</g, '&lt;')    // <  --> &lt; (prevents opening tags)
    .replace(/>/g, '&gt;')    // >  --> &gt; (prevents closing tags)
    .replace(/"/g, '&quot;')  // "  --> &quot;
    .replace(/'/g, '&#39;');  // '  --> &#39;
}

// ============================================================================
// ROUTE 0: HOME PORTAL (/)
// ============================================================================
app.get('/', (req, res) => {
  const html = loadView('index.html');
  res.send(html);
});

// ============================================================================
// ROUTE 1: DELIBERATELY VULNERABLE ROUTE (/vulnerable)
// ============================================================================
app.get('/vulnerable', (req, res) => {
  const name = req.query.name || '';

  // =========================================================================
  // 🚨 VULNERABLE LINE (CWE-79: Reflected XSS):
  // User input 'name' is directly concatenated into HTML without escaping.
  // The browser interprets and executes any injected <script> tag.
  // =========================================================================
  const outputContent = name 
    ? `<p style="font-size: 1.05rem;">Search result: <strong>${name}</strong></p>` 
    : '<span style="color: #94a3b8; font-style: italic;">(Submit a term above to see reflection)</span>';

  // Load frontend template and inject values
  let html = loadView('vulnerable.html');
  html = html
    .replace('{{INPUT_VALUE}}', name ? name.replace(/"/g, '&quot;') : '')
    .replace('{{OUTPUT_CONTENT}}', outputContent);

  res.send(html);
});

// ============================================================================
// ROUTE 2: SECURED ROUTE (/secure)
// ============================================================================
app.get('/secure', (req, res) => {
  const name = req.query.name || '';

  // =========================================================================
  // 🛡️ MITIGATION LINE (Context-Aware HTML Entity Escaping):
  // User input is sanitized through escapeHtml(). Characters like < and > 
  // become &lt; and &gt;, so the browser renders them safely as plain text.
  // =========================================================================
  const outputContent = name 
    ? `<p style="font-size: 1.05rem;">Search result: <strong>${escapeHtml(name)}</strong></p>` 
    : '<span style="color: #94a3b8; font-style: italic;">(Submit a term above to see reflection)</span>';

  // Load frontend template and inject sanitized values
  let html = loadView('secure.html');
  html = html
    .replace('{{INPUT_VALUE}}', escapeHtml(name))
    .replace('{{OUTPUT_CONTENT}}', outputContent);

  res.send(html);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`  Vulnerable: http://localhost:${PORT}/vulnerable`);
  console.log(`  Secured:    http://localhost:${PORT}/secure`);
});
