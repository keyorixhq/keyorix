"""Driver for the Keyorix Python SDK. One protocol line in, one JSON line out (see ../../PROTOCOL.md)."""
import json
import os
import socket
import sys
import time
import traceback
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.environ["SDKDIFF_SDKS_DIR"], "python"))
import keyorix  # noqa: E402

PLANT = os.environ.get("SDKDIFF_PLANT", "")

if PLANT in ("P4", "P7"):
    _orig_urlopen = urllib.request.urlopen

    def _patched(req, *a, **kw):
        if PLANT == "P4":
            u = urllib.parse.urlsplit(req.full_url)
            if not u.path.endswith("/") and u.path != "/health":
                req.full_url = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path + "/", u.query, u.fragment))
        if PLANT == "P7" and req.data:
            body = json.loads(req.data)
            if body.get("description") == "":
                body["description"] = None
                req.data = json.dumps(body).encode()
        return _orig_urlopen(req, *a, **kw)

    urllib.request.urlopen = _patched


CLIENT_METHODS = ("health", "list_secrets_scoped", "get_secret_scoped", "get_secret_in", "get_secret_by_ref",
                  "list_deleted_secrets", "list_projects", "create_project", "list_environments")


def missing_api():
    """SDK functions this driver calls that the SDK does not define. A renamed method must read as a
    harness failure (driver_error), not as an SDK error to compare, so this is checked up front rather
    than by mapping AttributeError at call time (an SDK may raise it on a scenario that is behaviour)."""
    miss = [] if callable(getattr(keyorix, "login", None)) else ["login"]
    client = getattr(keyorix, "Client", None)
    if client is None:
        return miss + ["Client"]
    return miss + ["Client." + m for m in CLIENT_METHODS if not callable(getattr(client, m, None))]


MISSING = missing_api()


def field(f):
    if f == "~":
        return None
    return bytes.fromhex(f).decode("utf-8", "replace")


def classify(err, force=None):
    cls, status = "other", None
    if force:
        cls = force
    elif isinstance(err, keyorix.AuthError):
        cls, status = "auth", err.status_code
    elif isinstance(err, keyorix.SecretNotFoundError):
        cls = "not_found"
    elif isinstance(err, keyorix.KeyorixError):
        if err.status_code is not None:
            cls, status = "http", err.status_code
        elif str(err).startswith(("Request failed", "Server unreachable")):
            cls = "network"
    elif isinstance(err, (TimeoutError, socket.timeout)):
        cls = "timeout"
    elif isinstance(err, (json.JSONDecodeError, UnicodeDecodeError)):
        cls = "decode"
    elif isinstance(err, OSError):
        cls = "network"
    try:
        # three-argument form: the one-argument form needs Python 3.10+, and a TypeError here would hide "full" from O4
        full = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    except Exception as e2:  # noqa: BLE001
        full = "format failed: " + type(e2).__name__
    return {"ok": False, "class": cls, "status": status, "native": type(err).__name__, "msg": str(err)[:20000],
            "sdk_error": isinstance(err, keyorix.KeyorixError), "full": full[:20000]}


def run(f):
    if MISSING:
        return {"driver_error": "SDK lacks " + ", ".join(MISSING)}
    cmd, base, token = f[0], field(f[1]) or "", field(f[2]) or ""
    timeout_ms = int(f[3] or 0)
    args = [field(x) for x in f[4:]]
    timeout = (timeout_ms / 1000.0) if timeout_ms > 0 else None
    if cmd == "construct":
        try:
            keyorix.Client(base, "x")
            return {"ok": True, "value": {"accepted": True}}
        except Exception as e:  # noqa: BLE001
            return classify(e, "validation")
    if cmd == "login":
        try:
            kw = {"timeout": timeout} if timeout else {}
            tok = keyorix.login(base, args[0], args[1], **kw)
            return {"ok": True, "value": {"token_len": len(tok)}}
        except Exception as e:  # noqa: BLE001
            return classify(e)
    try:
        c = keyorix.Client(base, token, timeout=timeout) if timeout else keyorix.Client(base, token)
    except Exception as e:  # noqa: BLE001
        return classify(e, "validation")
    try:
        if cmd == "health":
            return {"ok": True, "value": c.health()}
        if cmd == "list_secrets":
            env = args[0]
            if PLANT == "P1" and env:
                env = urllib.parse.quote(env)
            return {"ok": True, "value": secret_list(c.list_secrets_scoped("alpha", env))}
        if cmd == "get_secret":
            env = args[1]
            if PLANT == "P1" and env:
                env = urllib.parse.quote(env)
            return {"ok": True, "value": c.get_secret_scoped(args[0], "alpha", env)}
        if cmd == "get_secret_in":
            nm = args[2]
            if PLANT == "P1b" and nm:
                nm = urllib.parse.quote(nm)
            return {"ok": True, "value": c.get_secret_in(args[0], args[1], nm)}
        if cmd == "get_secret_by_ref":
            return {"ok": True, "value": c.get_secret_by_ref(args[0])}
        if cmd == "list_deleted_secrets":
            import re as _re
            if not isinstance(args[0], str) or not _re.fullmatch(r"[0-9]{1,9}", args[0]):
                return {"na": True}
            return {"ok": True, "value": secret_list(c.list_deleted_secrets(int(args[0])))}
        if cmd == "list_projects":
            return {"ok": True, "value": [dict(id=x.id, name=x.name, description=x.description, created_at=x.created_at)
                                          for x in c.list_projects()]}
        if cmd == "create_project":
            x = c.create_project(args[0], args[1])
            return {"ok": True, "value": dict(id=x.id, name=x.name, description=x.description, created_at=x.created_at)}
        if cmd == "list_environments":
            e = c.list_environments(int(args[0]))
            return {"ok": True, "value": [dict(id=x.id, project_id=x.project_id, name=x.name) for x in e]}
        return {"driver_error": "unknown cmd " + cmd}
    except Exception as e:  # noqa: BLE001
        return classify(e)


def secret_list(l):
    return [dict(id=x.id, name=x.name, type=x.type, project_id=x.project_id, environment=x.environment,
                 created_at=x.created_at, purge_at=getattr(x, "purge_at", None)) for x in l]


def main():
    out = sys.stdout
    for line in sys.stdin.buffer:
        line = line.decode("utf-8").rstrip("\r\n")
        if not line:
            continue
        t0 = time.time()
        try:
            res = run(line.split("\t"))
        except Exception as e:  # noqa: BLE001
            res = {"driver_error": repr(e)}
        res["ms"] = int((time.time() - t0) * 1000)
        out.write(json.dumps(res, ensure_ascii=True) + "\n")
        out.flush()


if __name__ == "__main__":
    main()
