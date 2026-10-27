# OS Command Injection

**Student Name:** Sathvik Boina  
**Roll Number:** IIT2024263  
**Category:** OS Command Injection  
**Variant Implemented:** Variant 1: In-band (command output returned)  

---

## Overview
This module demonstrates OS Command Injection where an application invokes a system shell command with untrusted user input concatenated directly into the shell string, returning the execution output directly to the user.

### (a) Vulnerable Implementation
A server endpoint offering a network diagnostic tool (e.g., ping utility) passes user input directly to a system shell:
```javascript
const { exec } = require('child_process');

// Vulnerable route invoking system shell:
app.post('/ping', (req, res) => {
  const host = req.body.host;
  // Flaw: Passing raw input directly to shell
  exec(`ping -c 2 ${host}`, (err, stdout, stderr) => {
    res.send(`<pre>${stdout || stderr}</pre>`);
  });
});
```

### (b) Working Exploit
* **Payload injected into host parameter:**
  ```text
  127.0.0.1; cat /etc/passwd
  ```
  *(or `127.0.0.1 && whoami; id; ls -la`)*
* **Execution:**
  The shell interpreter treats `;` as a command separator, executes `ping -c 2 127.0.0.1`, followed immediately by `cat /etc/passwd`. The server returns the sensitive system file content in the HTTP response.

### (c) Root Cause
The application passes unvalidated user input directly to an operating system shell interpreter (`sh`, `bash`), enabling shell metacharacters (`;`, `&`, `|`, `` ` ``, `$()`) to alter command control flow.

### (d) Implemented Mitigation
**Avoid the Shell via Parameterized Execution (`execFile` with Argument Array):**
```javascript
const { execFile } = require('child_process');

// Secure route: Direct binary execution without shell interpreter
app.post('/ping', (req, res) => {
  const host = req.body.host;
  // Directly execute /sbin/ping passing host strictly as an array argument
  execFile('/sbin/ping', ['-c', '2', host], (err, stdout, stderr) => {
    res.send(`<pre>${stdout || stderr}</pre>`);
  });
});
```
When injecting `127.0.0.1; cat /etc/passwd`, the binary receives the string strictly as a literal hostname argument (no shell interpreter parses the semicolon), and safely returns: `ping: cannot resolve 127.0.0.1; cat /etc/passwd: Unknown host`.

### (e) Other Mitigations (Theory)
1. **Allow-list Input Validation:** Validating user input using strict regular expressions (e.g., IP address regex `/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/`), rejecting any command metacharacters.
2. **Least-Privilege Execution:** Running the web server process under a dedicated low-privilege system user account (e.g. `www-data` with `nologin`), restricting read/write access to system directories.
3. **Use Built-in Language APIs:** Using native language network libraries (e.g. Node.js `net.isIP()`, `dns.lookup()`) instead of spawning operating system processes.
