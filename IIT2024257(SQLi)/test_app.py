"""
Quick automated checks for the SQLi demo.
Run with: python3 test_app.py
"""

from app import app, init_db


def run():
    init_db()
    client = app.test_client()

    r = client.post("/login/vulnerable", data={"username": "admin' --", "password": "whatever"})
    assert b"Authentication succeeded" in r.data, "Vulnerable mode should be bypassable"
    print("[PASS] vulnerable mode: admin' --  bypasses authentication")

    r = client.post("/login/vulnerable", data={"username": "' OR '1'='1' --", "password": "x"})
    assert b"Authentication succeeded" in r.data, "Vulnerable mode should be bypassable (OR 1=1)"
    print("[PASS] vulnerable mode: ' OR '1'='1' --  bypasses authentication")

    r = client.post("/login/secure", data={"username": "admin' --", "password": "whatever"})
    assert b"Authentication failed" in r.data, "Secure mode must block the same payload"
    print("[PASS] secure mode: same payload is blocked by parameterized query")

    r = client.post("/login/secure", data={"username": "admin", "password": "Sup3rSecretAdminPass!"})
    assert b"Authentication succeeded" in r.data, "Secure mode must still allow legitimate login"
    print("[PASS] secure mode: legitimate credentials still work")

    print("\nAll checks passed.")


if __name__ == "__main__":
    run()
