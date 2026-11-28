#!/usr/bin/env bash
# scripts/e2e/lib/airgap-e2e_test.sh -- runs scripts/airgap-e2e.sh against a FAKE
# container engine (no Docker needed) to check the two things the real drill got wrong
# for every caller that is not uid 1001 (#4700):
#   1. every container is started as the caller (--user "$(id -u):$(id -g)", plus
#      --userns=keep-id under podman), so the 0700 mktemp dirs and 0600 env files it
#      bind-mounts are readable and writable;
#   2. when the server never becomes healthy the script prints the engine's own state and
#      `logs` output, not only "never became healthy".
# The real container run stays a manual `make airgap-e2e` (pending e2e VM).
set -uo pipefail # no -e: every check runs and is counted

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${AIRGAP_E2E_SCRIPT:-$HERE/../../airgap-e2e.sh}" # override to red-proof against another revision

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed (airgap-e2e.sh requires it)"; exit 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fails=0
check() { # check <description> <condition-exit-status>
    if [ "$2" -eq 0 ]; then echo "ok   - $1"; else echo "FAIL - $1"; fails=$((fails + 1)); fi
}

# make_engine <name> <info-exit-status>: a fake engine that logs its argv, answers `info`,
# fails every `exec` (so the health wait times out) and prints a recognisable log on `logs`.
make_engine() {
    local name="$1" info_status="$2"
    cat >"$TMP/bin/$name" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$TMP/calls.log"
case "\$1" in
    info) exit $info_status ;;
    exec) exit 1 ;;
    logs) echo "FAKE-SERVER-LOG: open /app/data/keyorix.yaml: permission denied" ;;
    ps) echo "fake-container: Exited (1) 2 seconds ago" ;;
esac
exit 0
EOF
    chmod +x "$TMP/bin/$name"
}

run_drill() { # run_drill <label>: runs the script, leaves exit status in $status, output in $TMP/out.txt
    : >"$TMP/calls.log"
    PATH="$TMP/bin:$PATH" KEYORIX_AIRGAP_E2E_IMAGE=fake:image KEYORIX_AIRGAP_E2E_HEALTH_WAIT_SECS=1 \
        bash "$SCRIPT" >"$TMP/out.txt" 2>&1
    status=$?
    echo "-- $1: exit $status"
}

uid_gid="$(id -u):$(id -g)"

# --- docker ---
mkdir -p "$TMP/bin"
make_engine docker 0
run_drill docker
check "docker: the drill fails when the server is never healthy" "$([ "$status" -ne 0 ]; echo $?)"
grep -q '^run ' "$TMP/calls.log"
check "docker: a container was started" $?
! grep '^run ' "$TMP/calls.log" | grep -qv -- "--user $uid_gid "
check "docker: every 'run' passes --user $uid_gid" $?
! grep '^run ' "$TMP/calls.log" | grep -q -- '--userns'
check "docker: no --userns flag" $?
grep -q 'FAKE-SERVER-LOG' "$TMP/out.txt"
check "docker: the container logs are printed on a health timeout" $?
grep -q 'Exited (1)' "$TMP/out.txt"
check "docker: the container state is printed on a health timeout" $?
grep -q 'never became healthy' "$TMP/out.txt"
check "docker: the failure message still says it never became healthy" $?

# --- podman (docker present but its daemon is down, as on a podman-only host) ---
rm -f "$TMP/bin/docker"
make_engine docker 1
make_engine podman 0
run_drill podman
grep '^run ' "$TMP/calls.log" >/dev/null
check "podman: a container was started" $?
! grep '^run ' "$TMP/calls.log" | grep -qv -- "--userns=keep-id --user $uid_gid "
check "podman: every 'run' passes --userns=keep-id --user $uid_gid" $?

if [ "$fails" -ne 0 ]; then
    echo "airgap-e2e_test.sh: $fails check(s) failed; script output:" >&2
    cat "$TMP/out.txt" >&2
    exit 1
fi
echo "airgap-e2e_test.sh: all checks passed"
