# Harborline Hosting — OS Command Injection (In-Band)

Cyber Security (IT-30001), Autumn 2026 — Web Server Security assignment.
Category: **OS command injection**, Variant: **in-band (command output returned)**.

This repository is a small hosting-company demo site (Flask). Most of it is
ordinary, hardcoded marketing content — home page, pricing, about, contact.
Two routes implement a real "server connectivity check" feature twice: once
the way it was originally shipped (vulnerable), and once as it was rebuilt
(hardened). Functionally they're identical from a visitor's point of view:
type in a hostname or IP, the server pings it, the result is shown.

| Version | URL | Status |
|---|---|---|
| Legacy connectivity check | `/tools/diagnostics` | **Vulnerable** |
| Refreshed connectivity check | `/tools/diagnostics-v2` | **Fixed** |

Both are also reachable from the site itself: **Support → Server
connectivity check** lists both, framed as "classic" vs. "refreshed" — the
same way a real product would deprecate an old internal tool, which is also
why two versions of the same feature plausibly exist side by side.

## 1. Setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5000/`. The app uses the system `ping` command, so
run it on a machine where `ping` is installed (default on Linux, macOS, and
Windows). Demo this on your own machine or an isolated VM — never on shared
or production infrastructure (see Important instructions, item 7, in the
assignment brief).

## 2. (a) Vulnerable implementation

`app.py`, route `diagnostics_legacy()` (`/tools/diagnostics`):

```python
command = f"ping {PING_COUNT_FLAG} 4 {target}"
output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=10)
```

`target` is the raw string typed into the form field. It is concatenated
directly into a shell command string, and `shell=True` hands that whole
string to `/bin/sh` (or `cmd.exe`) to interpret before `ping` ever runs.

## 3. (b) Working exploit

1. Go to `/tools/diagnostics` (or Support → connectivity check → "classic").
2. In the **Hostname or IP address** field, instead of a normal value, enter
   one of the following (Linux/macOS target machine):

   ```
   127.0.0.1; whoami
   127.0.0.1 && id
   127.0.0.1 | uname -a
   127.0.0.1; cat /etc/hostname
   ```

   On a Windows target machine, use `&` instead of `;`:

   ```
   127.0.0.1 & whoami
   ```

3. Click **Run check**. The output panel shows the normal ping attempt
   *plus* the output of the injected command (e.g. the server's username,
   or the contents of `/etc/hostname`) — a second, attacker-chosen command
   ran on the server, appended to the one the form was meant to trigger.

Keep the injected commands read-only/informational (`whoami`, `id`,
`hostname`, `uname -a`, `cat /etc/hostname`) when recording the demo —
that's enough to prove code execution without doing anything destructive.

## 4. (c) Root cause

User input is concatenated into a command **string** that is then passed to
a shell (`shell=True`) instead of being passed as a literal argument to the
`ping` program. The shell treats characters like `; & | $() \`\`` as
syntax — command separators and substitutions — not as ordinary text, so
anything after one of those characters in the input is executed as a
separate, attacker-controlled command with the same privileges as the web
server process.

## 5. (d) Mitigation implemented

`app.py`, route `diagnostics_v2()` (`/tools/diagnostics-v2`) — **avoid the
shell / parameterised execution with an argument vector**:

```python
result = subprocess.run(["ping", PING_COUNT_FLAG, "4", target], capture_output=True, text=True, timeout=10)
```

`subprocess.run` is called with a **list** of arguments and `shell` is left
at its default, `False`. No shell is ever invoked, so there is no
interpreter to hand metacharacters to — the OS passes `target` to the
`ping` executable as a single, literal argument, whatever characters it
contains.

**To show the fix working:** repeat the exact same payloads from section 3
on `/tools/diagnostics-v2`. The output shows `ping` failing to resolve the
whole string (e.g. `ping: 127.0.0.1; whoami: Name or service not known`, or
similar) — the `;`, `&&`, `|`, etc. are now just ordinary characters inside
one invalid hostname, not shell syntax, and `whoami`/`id`/etc. never runs.

## 6. (e) Other mitigations (theory only — not implemented here)

The slides cover four mitigation families for command injection; this
project implements the first and discusses the rest:

- **Avoid the shell / parameterised execution with an argument vector**
  *(implemented above).* Pass arguments directly to the program via an
  argument vector (e.g. `execve`-style APIs, or `subprocess.run([...])`
  without `shell=True`) so no shell ever re-parses the input for
  metacharacters.
- **Allow-list input validation.** Even with the shell avoided, the
  application could additionally check that `target` matches a strict
  pattern for a valid hostname or IPv4/IPv6 address (letters, digits, dots,
  hyphens only, within length limits) and reject anything else before it
  reaches `ping` at all. This is defense-in-depth: it stops malformed input
  even earlier, and helps if a future code change accidentally reintroduces
  a shell call.
- **Least privilege.** Run the web application under a dedicated,
  unprivileged OS account with no unnecessary permissions, and, ideally,
  restrict (e.g. via containers, `seccomp`, AppArmor/SELinux profiles, or a
  minimal container image) which binaries the process is even able to
  execute. Even if an injection flaw existed, the damage an attacker could
  do would be bounded by what that low-privilege account is allowed to do.
- **Avoid shelling out at all, where possible.** For many "run a system
  command" features there's a library call that does the same job without
  spawning a subprocess or shell (for example, resolving a hostname with
  Python's `socket.gethostbyname()` instead of shelling out to `ping` or
  `nslookup`). Removing the subprocess call entirely removes this class of
  bug outright.

## 7. Ownership (Table 3)

| Member name | Roll number | Category | Variant implemented |
|---|---|---|---|
| *(your name)* | *(your roll no.)* | OS command injection | In-band (command output returned) |
| | | | |
| | | | |
| | | | |

## Notes

- `app.py` has inline comments at both routes marking exactly where the
  vulnerable and the fixed code live, for quick reference at the viva.
- This app is for local/sandboxed demonstration only — don't deploy it to
  a public server.
