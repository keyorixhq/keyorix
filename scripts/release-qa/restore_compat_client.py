#!/usr/bin/env python3
"""Small HTTP/archive helper for scenario_restore_compat.sh (stdlib only).

The old release CLIs (v0.95.x/v0.96.x) have no `mfa enroll`, and the login
flow with a TOTP second factor is two requests, so the scenario drives those
over the HTTP API directly. Everything prints to stdout one value per call so
the bash driver can capture it; errors go to stderr with a non-zero exit.

Subcommands:
  totp <base32-secret> [offset-seconds]      print the current TOTP code
  login <url> <user> <password> [totp-secret] print a session token
  enroll-mfa <url> <token> <password>        enrol + activate TOTP, print the secret
  manifest-counts <archive.tar.gz>           print "<table> <row_count>" lines
  post <url> <token> <path> <json-body>      POST, print the response's data as JSON
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import tarfile
import time
import urllib.error
import urllib.request


def die(msg):
    print(f"restore_compat_client: {msg}", file=sys.stderr)
    sys.exit(1)


def totp(secret, offset=0, counter=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    if counter is None:
        counter = int((time.time() + offset) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    pos = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[pos:pos + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def call(url, path, body, token=None):
    req = urllib.request.Request(url.rstrip("/") + path, method="POST",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - local test server
            return json.load(resp).get("data") or {}
    except urllib.error.HTTPError as e:
        die(f"POST {path}: HTTP {e.code}: {e.read().decode(errors='replace')[:400]}")


def fresh_step():
    """A TOTP time step no earlier call has used.

    The server refuses a replayed step, and a restored database carries the
    last step the OLD server accepted, so every code this script submits must
    use a step later than the previous one. KEYORIX_QA_TOTP_STATE names the
    file that remembers it. The server accepts one step of clock skew, so the
    next step can be used right away; beyond that, wait for it.
    """
    state = os.environ.get("KEYORIX_QA_TOTP_STATE")
    last = -1
    if state and os.path.exists(state):
        with open(state) as f:
            last = int(f.read().strip() or -1)
    now = int(time.time() // 30)
    step = max(now, last + 1)
    if step > now + 1:
        wait = (step - 1) * 30 - time.time() + 1
        print(f"waiting {wait:.0f}s for an unused TOTP step", file=sys.stderr)
        time.sleep(max(wait, 0))
    if state:
        with open(state, "w") as f:
            f.write(str(step))
    return step


def login(url, user, password, totp_secret=None):
    data = call(url, "/auth/login", {"username": user, "password": password})
    if data.get("mfa_required"):
        if not totp_secret:
            die(f"login {user}: server asked for MFA but no TOTP secret was given")
        data = call(url, "/auth/mfa/verify",
                    {"mfa_challenge": data["mfa_challenge"], "code": totp(totp_secret, counter=fresh_step())})
    elif totp_secret:
        die(f"login {user}: expected an MFA challenge (TOTP enrolled), got a plain session")
    token = data.get("token")
    if not token:
        die(f"login {user}: no token in response: {data}")
    return token


def enroll_mfa(url, token, password):
    secret = call(url, "/api/v1/auth/mfa/enroll", {}, token).get("secret")
    if not secret:
        die("mfa enroll: no secret in response")
    call(url, "/api/v1/auth/mfa/activate", {"code": totp(secret, counter=fresh_step()), "password": password}, token)
    return secret


def manifest_counts(path):
    with tarfile.open(path, "r:gz") as tf:
        for m in tf:
            if m.name.lstrip("./") == "MANIFEST.json":
                manifest = json.load(tf.extractfile(m))
                break
        else:
            die(f"{path}: no MANIFEST.json")
    for t in manifest.get("tables", []):
        print(f"{t['name']} {t['row_count']}")


def main(argv):
    if len(argv) < 2:
        die(__doc__)
    cmd, args = argv[1], argv[2:]
    if cmd == "totp" and len(args) in (1, 2):
        print(totp(args[0], int(args[1]) if len(args) == 2 else 0))
    elif cmd == "login" and len(args) in (3, 4):
        print(login(*args))
    elif cmd == "enroll-mfa" and len(args) == 3:
        print(enroll_mfa(*args))
    elif cmd == "post" and len(args) == 4:
        print(json.dumps(call(args[0], args[2], json.loads(args[3]), args[1])))
    elif cmd == "manifest-counts" and len(args) == 1:
        manifest_counts(args[0])
    else:
        die(__doc__)


if __name__ == "__main__":
    main(sys.argv)
