"""
Harborline Hosting — demo site for the Web Server Security assignment.

Everything on this site except two routes is static, hardcoded marketing
content. The two routes that matter for the assignment are:

    /tools/diagnostics      -> legacy connectivity check (VULNERABLE)
    /tools/diagnostics-v2   -> refreshed connectivity check (SECURE)

Both features do the same thing from a user's point of view: you type in a
hostname or IP address and the server pings it on your behalf and shows you
the result. The difference is entirely in how the server builds the ping
command from your input (see comments in each route below).
"""

import platform
import subprocess
from flask import Flask, render_template, request

app = Flask(__name__)

# ping's "repeat count" flag differs by OS; this just keeps the demo
# working whether you run it on Linux, macOS, or Windows.
PING_COUNT_FLAG = "-n" if platform.system().lower() == "windows" else "-c"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/services")
def services():
    return render_template("services.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    submitted = False
    if request.method == "POST":
        # No real mail is sent in this demo — just acknowledge receipt.
        submitted = True
    return render_template("contact.html", submitted=submitted)


@app.route("/support")
def support():
    return render_template("support.html")


# ---------------------------------------------------------------------------
# LEGACY tool — intentionally vulnerable to OS command injection (in-band).
# ---------------------------------------------------------------------------
@app.route("/tools/diagnostics", methods=["GET", "POST"])
def diagnostics_legacy():
    output = None
    target = ""

    if request.method == "POST":
        target = request.form.get("target", "")

        # --- VULNERABLE IMPLEMENTATION -------------------------------------
        # The user-supplied hostname is concatenated directly into a shell
        # command string, and shell=True means that string is handed to
        # /bin/sh (or cmd.exe) for interpretation. Shell metacharacters in
        # `target` such as ; & | $() ` are interpreted by the shell instead
        # of being treated as part of a hostname, so an attacker can append
        # arbitrary commands to the one the developer intended to run.
        command = f"ping {PING_COUNT_FLAG} 4 {target}"
        try:
            output = subprocess.check_output(
                command,
                shell=True,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            output = exc.output
        except subprocess.TimeoutExpired:
            output = "Request timed out."
        # ---------------------------------------------------------------

    return render_template("diagnostics_legacy.html", output=output, target=target)


# ---------------------------------------------------------------------------
# v2 tool — same feature, hardened against command injection.
# ---------------------------------------------------------------------------
@app.route("/tools/diagnostics-v2", methods=["GET", "POST"])
def diagnostics_v2():
    output = None
    error = None
    target = ""

    if request.method == "POST":
        target = request.form.get("target", "")

        # --- MITIGATION: avoid the shell / parameterised argument vector ---
        # subprocess.run() is called with a LIST of arguments and shell is
        # left at its default (False), so no shell is ever invoked. The
        # string the user typed is passed to the OS as a single, literal
        # argument to the ping executable — it is never re-parsed for
        # ; & | $() ` or any other shell syntax, so there is nothing for an
        # attacker to break out with. A malicious string like
        # "127.0.0.1; whoami" is simply treated as one (invalid) hostname
        # and ping reports it can't be resolved, rather than running
        # `whoami` as a second command.
        if not target.strip():
            error = "Please enter a hostname or IP address."
        else:
            try:
                result = subprocess.run(
                    ["ping", PING_COUNT_FLAG, "4", target],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = (result.stdout or "") + (result.stderr or "")
            except subprocess.TimeoutExpired:
                error = "Request timed out."
            except FileNotFoundError:
                error = "The ping utility is not available on this server."
        # ---------------------------------------------------------------

    return render_template("diagnostics_v2.html", output=output, error=error, target=target)


if __name__ == "__main__":
    # debug=True is only for local demo convenience — never ship this to
    # a real server.
    app.run(debug=True, port=5000)
