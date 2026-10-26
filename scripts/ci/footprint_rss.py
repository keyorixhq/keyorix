#!/usr/bin/env python3
"""footprint_rss.py -- one idle-RSS measurement for scripts/ci/footprint-check.sh.

Initialises a fresh SQLite install with the SECURE baseline config (`admin init`
without --dev: TLS on, rate limit on), starts the server on a free loopback port,
waits until /health answers, leaves it idle for --idle seconds, stops it with
SIGTERM and prints the peak resident set size of the exited process.

Peak (getrusage ru_maxrss of the exited child) rather than a live sample: it
needs no `ps` or /proc, so it is the same measurement on macOS and Linux, and it
includes the start-up spike a device must have room for. Same method as
server/edge_footprint_test.go.

Usage: python3 -I footprint_rss.py <server-binary> <empty-work-dir> <idle-seconds>
Last stdout line on success: RSS_KIB=<int>. Progress goes to stderr.
Exit: 0 ok, 2 the server could not be initialised/started/stopped.
"""
import os
import re
import resource
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

PASSPHRASE = "footprint-check-passphrase"  # throwaway install, never reused


def log(msg):
    print("footprint_rss: " + msg, file=sys.stderr, flush=True)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def healthy(port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the baseline's self-signed certificate
    try:
        with urllib.request.urlopen(f"https://127.0.0.1:{port}/health", timeout=2, context=ctx) as r:  # nosec - loopback
            return r.status == 200
    except OSError:
        return False


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    binary, workdir, idle = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2]), float(sys.argv[3])
    env = {"HOME": workdir, "PATH": "/usr/bin:/bin", "KEYORIX_MASTER_PASSWORD": PASSPHRASE}
    if os.environ.get("TMPDIR"):
        env["TMPDIR"] = os.environ["TMPDIR"]

    for args in (["init"], ["encryption", "init"], ["migrate"]):
        cmd = [binary, "admin", *args, "--config", "./keyorix.yaml"]
        r = subprocess.run(cmd, cwd=workdir, env=env, capture_output=True, text=True)  # nosec - own binary
        if r.returncode != 0:
            log(f"{' '.join(cmd[1:])} failed ({r.returncode}):\n{r.stdout}{r.stderr}")
            return 2

    cfg = os.path.join(workdir, "keyorix.yaml")
    with open(cfg, encoding="utf-8") as f:
        text = f.read()
    port = free_port()
    new, n = re.subn(r'port: "8080"', f'port: "{port}"', text, count=1)
    if n != 1:
        log('config template no longer has the `port: "8080"` line this script rewrites')
        return 2
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(new)

    logpath = os.path.join(workdir, "server.log")
    with open(logpath, "w", encoding="utf-8") as logf:
        proc = subprocess.Popen([binary], cwd=workdir, env={**env, "KEYORIX_CONFIG_PATH": "./keyorix.yaml"},  # nosec - own binary
                                stdout=logf, stderr=logf)
        try:
            deadline = time.time() + 45
            while not healthy(port):
                if proc.poll() is not None or time.time() > deadline:
                    break
                time.sleep(0.2)
            else:
                log(f"healthy on 127.0.0.1:{port}; idle for {idle:g}s")
                time.sleep(idle)
                if proc.poll() is None:
                    proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    log("server ignored SIGTERM for 30s and was killed")
                    return 2
                peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
                # ru_maxrss is bytes on macOS, KiB on Linux.
                print(f"RSS_KIB={peak // 1024 if sys.platform == 'darwin' else peak}")
                return 0
            log("server did not become healthy:")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    with open(logpath, encoding="utf-8", errors="replace") as f:
        sys.stderr.write("".join(f.readlines()[-20:]))
    return 2


if __name__ == "__main__":
    sys.exit(main())
