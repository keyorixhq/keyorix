# Weekly mutation testing (self-hosted)

Runs [gremlins](https://github.com/go-gremlins/gremlins) mutation testing
against `internal/core` and `internal/storage/store` once a week, on a
dedicated box separate from CI — see `.semgrep/RULE-MINING-PROCESS.md` for
the fix history that motivated adding this. Coverage percentage only tells
you a line was *executed* by some test; mutation testing tells you whether a
test would actually *notice* if that line's logic were subtly wrong (a
flipped comparison, an off-by-one, a swapped boolean). Runs on `main`, not
per-PR: gremlins re-runs the target package's test suite once per surviving
mutant, which on a large, heavily-tested package like `internal/core` is
genuinely slow — well beyond what a CI job's budget affords, same tradeoff
this repo already makes for continuous fuzzing (`scripts/fuzzing/README.md`).

## What you get

- A systemd oneshot service, triggered weekly by a timer, that pulls `main`
  fresh and runs `gremlins unleash` against each target package.
- A summary (mutant counts, test efficacy %) pushed to
  [ntfy.sh](https://ntfy.sh) after every run — normal priority.
- If test efficacy for a package **drops** by more than a configurable
  threshold versus the last recorded run for that same package, a
  high-priority alert plus a GitHub issue listing the specific newly-
  surviving mutants (file:line, mutation type) — deduped, so an unresolved
  regression doesn't get a fresh issue every week.
- Raw per-run gremlins JSON results kept locally (`MUTATION_STATE_DIR`) for
  inspection, not committed anywhere — there's no "reproducer" artifact to
  preserve the way a fuzz crash has one; the point-in-time JSON is only
  useful for the next run's before/after comparison.

## Why this, not the CI runner

An earlier version of this ran as a scheduled GitHub Actions workflow. Moved
here because this repo already has separate, dedicated infrastructure for
exactly this shape of problem (long-running, non-blocking, advisory depth
that a CI job's budget can't afford) — no reason to duplicate that on a
second box when one already exists for the fuzzing setup's sibling need.

## Resource limits

`systemd/keyorix-mutation.service` caps this service to `CPUQuota=400%` and
`MemoryMax=7G`, alongside `Nice=10` — same shape as
`scripts/fuzzing/systemd/keyorix-fuzz.service`, adjust both to fit your own
hardware. Unlike fuzzing's `-fuzztime` (wall-clock, so a lower `CPUQuota`
makes a rotation *shallower*, not longer), a mutation run's total work is
fixed — every covered mutant gets tested exactly once regardless of quota —
so a lower `CPUQuota` here only makes a run take longer, never less thorough.

Provision the container/VM itself with at least 8G RAM (some headroom above
`MemoryMax` for the OS/systemd/other overhead) and set `MUTATION_GOMAXPROCS`
(`config.env`) so `MUTATION_WORKERS * MUTATION_GOMAXPROCS` roughly matches
`CPUQuota`'s equivalent core count (400% -> 4 cores; workers=4 ->
GOMAXPROCS=1 each) — leaving `GOMAXPROCS` unset lets every worker's `go
build`/`go test` subprocesses assume the host's full visible thread count
each, oversubscribing the quota and starving individual runs past gremlins'
per-mutant timeout (every mutant comes back `TIMED OUT` instead of a real
result). And an undersized `MemoryMax` doesn't fail cleanly either --
`MemorySwapMax` defaults to `infinity`, so hitting the cap means swapping,
not an OOM kill: silent thrashing that's easy to mistake for the CPUQuota
problem above if you haven't also checked
`systemctl show keyorix-mutation.service -p MemoryCurrent -p MemoryMax`.

### Disk: `GOCACHE` grows without bound

Mutation testing is inherently cache-hostile -- gremlins recompiles a new,
distinct source variant per mutant, and Go's build cache is content-
addressed, so nearly every mutant produces a brand-new cache entry with
little reuse. Go's own automatic cache GC is age-based (days), not
size-based, so it doesn't kick in fast enough for a workload that can
generate double-digit GiB within hours -- this has filled a container's
disk to 100% (and stalled the in-progress run) before this existed.

`trim-gocache.sh`, run periodically via `keyorix-mutation-cache-trim.timer`
(every 10 minutes, independent of `keyorix-mutation.timer`'s own weekly
schedule), checks disk usage and, only once it's over
`TRIM_DISK_THRESHOLD_PCT` (default 85%), deletes the *oldest* files under
`GOCACHE` until usage drops back to `TRIM_DISK_TARGET_PCT` (default 65%).
Most firings are a no-op `df` check. Deliberately not a periodic
`go clean -cache` (a full wipe): that needs an exclusive lock on the whole
cache, so running it unconditionally on a fixed interval would frequently
collide with gremlins' own in-flight compiles over a run lasting hours.
Deleting the oldest files individually is much less likely to touch
anything actively in use -- a live compile's own cache writes are, by
definition, the newest files on disk.

## One-time setup (on the LXC/VM)

Same base requirements as `scripts/fuzzing/README.md` (Go matching `go.mod`,
`git`, `curl`, `ca-certificates`, `sudo`, `gh` CLI) plus `gremlins` itself.

1. **Install Go and `gremlins`** as the eventual service user (see step 2):
   ```
   go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0
   ```
   (Installs to `$GOPATH/bin` — make sure that's on `PATH` for the service
   user, or symlink the binary somewhere that already is, e.g.
   `ln -s $(go env GOPATH)/bin/gremlins /usr/local/bin/gremlins`.)

2. **Create a dedicated user**:
   ```
   useradd -m -s /bin/bash mutation
   mkdir -p /opt/keyorix-mutation /etc/keyorix-mutation
   chown mutation:mutation /opt/keyorix-mutation
   ```

3. **Get GitHub access for the `mutation` user.** Only `git fetch` (read-only
   — this box never pushes) and `gh issue create/comment` need auth. A
   single fine-grained PAT with **Contents: Read** and **Issues: Read and
   write** covers both; `gh` reads it from `GH_TOKEN` in `config.env` (see
   step 6), and the same value can back a git credential helper for the
   `https://github.com/...` clone in step 4:
   ```
   sudo -u mutation git config --global credential.'https://github.com'.helper \
     '!f() { echo username=x-access-token; echo password=$(cat /etc/keyorix-mutation-gh-token); }; f'
   ```
   (See `scripts/fuzzing/README.md` step 3 for the deploy-key alternative if
   you'd rather keep the clone credential and the `gh` token fully separate —
   not necessary here since this box never writes to the repo via git, only
   via `gh issue`.)

4. **Clone the repo** as the `mutation` user:
   ```
   sudo -u mutation git clone https://github.com/keyorixhq/keyorix.git /opt/keyorix-mutation/keyorix
   sudo -u mutation git config --global --add safe.directory /opt/keyorix-mutation/keyorix
   ```

5. **Pick an ntfy.sh topic** (optional — see `config.env.example`).

6. **Write the config file**:
   ```
   cp scripts/mutation-testing/config.env.example /etc/keyorix-mutation/config.env
   $EDITOR /etc/keyorix-mutation/config.env   # set GH_TOKEN and optionally NTFY_TOPIC
   echo 'PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
     >> /etc/keyorix-mutation/config.env
   chmod 600 /etc/keyorix-mutation/config.env
   chown mutation:mutation /etc/keyorix-mutation/config.env
   ```
   Make sure the `PATH` line covers wherever `gremlins`, `go`, and `gh` are
   actually installed — systemd's `EnvironmentFile=` does not source
   `/etc/profile.d/`.

7. **Install the systemd units:**
   ```
   cp scripts/mutation-testing/systemd/*.service scripts/mutation-testing/systemd/*.timer /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now keyorix-mutation.timer
   systemctl enable --now keyorix-mutation-cache-trim.timer
   ```
   **If this is an unprivileged Proxmox LXC**, see
   `scripts/fuzzing/README.md` step 7's journald note — the same
   `ImportCredential=journal.*` issue on a fresh Debian 13 template can
   apply here too.

8. **Verify** (don't wait for Tuesday — trigger the oneshot service
   directly):
   ```
   systemctl start keyorix-mutation.service
   journalctl -u keyorix-mutation.service -f
   ```
   A full run against both target packages currently takes a few minutes
   (`internal/storage/store` alone: ~1200 mutants, ~2 minutes on 4 workers —
   `internal/core` is larger). Check `systemctl status
   keyorix-mutation.timer` to confirm the weekly schedule is armed.

## Day-to-day

- **Efficacy-regression issue arrives** → the issue body lists the specific
  newly-surviving mutants (file:line, mutation type). Each one is a place a
  test currently runs the line but wouldn't fail if that exact piece of
  logic broke — write (or fix) an assertion that would.
- **No summary notification this week** → check `systemctl status
  keyorix-mutation.timer` / `journalctl -u keyorix-mutation.service` for
  what went wrong; unlike fuzzing there's no separate heartbeat timer here
  since a oneshot service either ran (you'll see the normal-priority
  summary) or didn't (silence itself is the signal, checkable via
  `systemctl list-timers keyorix-mutation.timer`).
- **Widening scope** → add another `pkg|label` line to the `PACKAGES` list
  in `run-mutation.sh`. Do this deliberately, one package at a time, once
  the packages already covered are in good shape — see that script's own
  comment for why this doesn't default to repo-wide.
- **Raw results for a specific run** → `MUTATION_STATE_DIR/last-<label>.json`
  (this run) is overwritten every run; there is no history beyond
  "current vs. immediately-previous" by design (that's all the regression
  check needs). Copy a result out first if you want to keep it longer.

## Design notes

- Read-only against the repo: unlike the fuzzing box (which pushes corpus
  commits to `fuzz-corpus`), this box only ever `git fetch`/`reset --hard`s
  locally and calls `gh issue create/comment` — it never pushes a branch or
  opens a PR, since there's no code artifact to commit (a JSON result isn't
  something to merge into `main`).
- A `LIVED` mutant is not automatically a bug — it means a specific line's
  behavior isn't independently verified by the test suite, which is a
  different (softer) signal than "this code is wrong." That's why this
  notifies on *regression* (efficacy getting worse for a package that was
  previously better), not on the raw LIVED count each run — a package's
  LIVED count naturally fluctuates a little as normal feature work adds
  covered-but-not-yet-fully-asserted code; only a real drop is worth an
  issue.
