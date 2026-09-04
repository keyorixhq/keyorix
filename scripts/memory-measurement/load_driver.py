"""load_driver.py — real HTTP load generation against a running keyorix-server
container, for scripts/memory-measurement/matrix_runner.py. No synthetic
in-process allocation anywhere here: every scenario drives the actual
/auth/login, POST /api/v1/secrets, and GET endpoints a real client would
call, matching the methodology in
docs/adr-100-mlockall-removal-deployment-swap-control.md.

Stdlib only (urllib, concurrent.futures) -- no third-party dependency for a
harness whose whole point is measuring the server's own footprint, not
adding one of its own.
"""

import base64
import concurrent.futures
import json
import random
import time
import urllib.error
import urllib.request


class Client:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def _call(self, method: str, path: str, token: str = None, body: dict = None) -> bytes:
        url = self.base_url + path
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()

    def login(self, username: str, password: str) -> str:
        body = json.loads(self._call("POST", "/auth/login", body={"username": username, "password": password}))
        return body["data"]["token"]

    def create_secret(self, token: str, name: str, size_bytes: int, project_id: int = 1, environment_id: int = 1):
        val = base64.b64encode(b"x" * size_bytes).decode()
        self._call("POST", "/api/v1/secrets", token=token, body={
            "name": name, "value": val, "project_id": project_id,
            "environment_id": environment_id, "type": "password",
        })

    def get(self, token: str, path: str) -> bytes:
        return self._call("GET", path, token=token)

    def health(self):
        try:
            self._call("GET", "/health")
        except Exception:
            pass


def create_burst(client: Client, token: str, count: int, size_bytes: int, concurrency: int, prefix: str) -> dict:
    """Create `count` secrets of `size_bytes` each, at the given client
    concurrency. Returns {"elapsed_s", "succeeded", "failed"}."""
    names = [f"{prefix}-{i}" for i in range(count)]
    succeeded = 0
    failed = 0
    t0 = time.time()

    def _one(name):
        client.create_secret(token, name, size_bytes)

    if concurrency <= 1:
        for n in names:
            try:
                _one(n)
                succeeded += 1
            except Exception:
                failed += 1
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            futs = [ex.submit(_one, n) for n in names]
            for f in concurrent.futures.as_completed(futs):
                try:
                    f.result()
                    succeeded += 1
                except Exception:
                    failed += 1

    return {"elapsed_s": time.time() - t0, "succeeded": succeeded, "failed": failed}


def hit_endpoint(client: Client, token: str, path: str) -> dict:
    t0 = time.time()
    body = client.get(token, path)
    return {"elapsed_s": time.time() - t0, "bytes": len(body)}


def sustained_mixed_load(client: Client, token: str, concurrency: int, duration_s: int,
                          on_sample=None, sample_every_s: int = 120):
    """Mixed create(~300B)/list/get workload at fixed concurrency for
    duration_s wall-clock seconds. Calls on_sample(elapsed_s, iterations)
    every sample_every_s if given, so a caller can interleave RSS sampling
    without this module needing to know about proc_status/docker at all."""

    def _one_iteration(i):
        op = random.choice(["create", "list", "get_by_list"])
        if op == "create":
            client.create_secret(token, f"sustained-{i}-{time.time()}", 300)
        elif op == "list":
            client.get(token, "/api/v1/secrets?project_id=1&environment_id=1&page_size=20")
        else:
            body = json.loads(client.get(token, "/api/v1/secrets?project_id=1&environment_id=1&page_size=20"))
            secs = body.get("data", {}).get("secrets") or []
            if secs:
                try:
                    client.get(token, f"/api/v1/secrets/{secs[0]['ID']}")
                except Exception:
                    pass

    t_start = time.time()
    t_last_sample = t_start
    i = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = set()
        while time.time() - t_start < duration_s:
            while len(futs) < concurrency:
                i += 1
                futs.add(ex.submit(_one_iteration, i))
            done, futs = concurrent.futures.wait(futs, timeout=1, return_when=concurrent.futures.FIRST_COMPLETED)
            for f in done:
                try:
                    f.result()
                except Exception:
                    pass
            if on_sample and time.time() - t_last_sample >= sample_every_s:
                t_last_sample = time.time()
                on_sample(time.time() - t_start, i)
        for f in futs:
            try:
                f.result()
            except Exception:
                pass
    return {"elapsed_s": time.time() - t_start, "iterations": i}
