"""proc_status.py — sample and parse a container's real server process's
/proc/<pid>/status, the same way every number in ADR-100
(docs/adr-100-mlockall-removal-deployment-swap-control.md) was obtained:
docker exec into the container and read the kernel's own accounting for the
process, not an estimate or a Go-runtime-reported figure.

PID 6 is the real `keyorix-server` process inside the image built from
server/Dockerfile (PID 1 is entrypoint.sh, which backgrounds the server and
waits on it) -- confirmed by `docker exec <container> ps aux` matching this
every time this harness (and the manual measurements that preceded it) has
been run. If a future Dockerfile change alters the process tree, update
SERVER_PID below and re-verify with `ps aux` before trusting new numbers.
"""

import re
import subprocess

SERVER_PID = 6

_FIELDS = ("VmSize", "VmLck", "VmRSS", "VmHWM")


def sample(container: str) -> dict:
    """Return {field: kilobytes} for VmSize/VmLck/VmRSS/VmHWM, read live from
    the container's real server process. Raises CalledProcessError if the
    container isn't running or the process is gone (e.g. OOM-killed --
    callers checking for that should catch this, not treat it as zero)."""
    out = subprocess.check_output(
        ["docker", "exec", container, "sh", "-c",
         f"grep -E '^({'|'.join(_FIELDS)}):' /proc/{SERVER_PID}/status"],
        text=True,
    )
    values = {}
    for line in out.splitlines():
        m = re.match(r"^(\w+):\s+(\d+) kB$", line.strip())
        if m:
            values[m.group(1)] = int(m.group(2))
    missing = [f for f in _FIELDS if f not in values]
    if missing:
        raise RuntimeError(f"proc_status.sample: missing fields {missing} in output: {out!r}")
    return values


def oom_killed(container: str) -> bool:
    """True if docker reports this container's process was OOM-killed."""
    out = subprocess.check_output(
        ["docker", "inspect", "-f", "{{.State.OOMKilled}}", container], text=True
    )
    return out.strip() == "true"


def container_exit_code(container: str) -> int:
    out = subprocess.check_output(
        ["docker", "inspect", "-f", "{{.State.ExitCode}}", container], text=True
    )
    return int(out.strip())
