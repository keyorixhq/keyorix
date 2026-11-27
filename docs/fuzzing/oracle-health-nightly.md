# Nightly oracle-health run (pve01, systemd, no GitHub workflow)

Runbook for `scripts/fuzzing/oracle-health/nightly/` (wrapper, units, env example).
The suite itself (`oracle-health.sh`, entries, verdicts) is described in
`scripts/fuzzing/README.md` ("Oracle health"). This page is only about running it
every night without anyone starting it, and about being told when it stops
protecting you.

## Why it exists

`oracle-health.sh --heavy --strict` re-plants a known defect per harness in a
throwaway copy and fails when a harness no longer catches it. It was built and green
but ran only by hand, so a harness that went blind would be found whenever someone
next remembered to run it. There is deliberately no workflow: the heavy entries need
a Postgres superuser and the pve01 Postgres 17, and pve01 is shared.

## What one run does

`oracle-health-nightly.sh`, started by `oracle-health-nightly.timer`:

1. **Gate.** Skips quietly (exit 0, reason in `nightly.log`, no alert) when
   `/root/PVE-BENCH-LOCK` exists, or temp_avg >= 86 C, load5 >= 6, MemAvailable
   < 12 GB, or `/dev/shm` free < 8 GB. A lock directory the service user cannot
   search, or a sensor that cannot be read, **refuses** (fail closed) instead of
   guessing "all clear". Every refusal bumps a counter; **3 skipped nights in a
   row raise one "STALE" alert** (and one more per day while it continues). A run
   that passes the gate resets the counter.
2. **Clone.** Fast-forwards the dedicated clone to `origin/main`. A dirty tree, a
   branch other than `main`, a failed fetch or a non-fast-forward is a refusal
   and is alerted; the suite never runs on a stale tree.
3. **Run.** `nice -n 10`, `GOMAXPROCS=2`, hard timeout (`OHN_TIMEOUT_SECS`, 3 h,
   then `-k 120`), `TMPDIR`/`GOTMPDIR` and the throwaway trees on tmpfs
   (`/dev/shm`), `PATH` extended with `/usr/lib/postgresql/17/bin`:
   `oracle-health.sh --heavy --strict --workdir <tmpfs> --tsv <tmpfs>`.
4. **Record.** Under `OHN_LOG_DIR` (default `/var/lib/oracle-health-nightly/logs`):
   `oracle-health-<UTC stamp>.log` (the full output, DSNs/passwords/tokens redacted)
   and `oracle-health-<UTC stamp>.summary`: a `# tree= rc= secs=` header and one
   `ENTRY<TAB>VERDICT<TAB>detail` line per entry (`DETECTED`, `KNOWN-BLIND`,
   `BLIND-FIXED`, `CONTROL-RED`, `MISSED`, `SKIP`, `PLANT-STALE`, `PLANT-BROKEN`,
   `WRONG-MARKER`, `CONF-ERROR`). `nightly.log` holds the wrapper's own events.
   Files older than 30 days are pruned.
5. **Alert.** Any verdict other than `DETECTED` or `KNOWN-BLIND` sends **one** ntfy
   message to `https://ntfy.sh/andrey_fuzz_allert`: the title lists the entries
   (`oracle-health: beta=MISSED, gamma=CONTROL-RED`), the body is capped at 1 KB
   (entry, verdict, detail, host, tree, log path). **At most one alert per entry
   per UTC day** (state in `alerted.tsv`); a key is recorded only after curl
   succeeded, so a failed send is retried by the next run. A fully healthy run
   sends nothing. The URL and optional token go to curl through `-K -` (stdin),
   never argv.
   Also alerted, under the key `run`: no result table (`NO-RESULT`), a timeout
   (`TIMEOUT`), and a runner exit code that disagrees with an all-healthy table
   (`EXIT-<n>`).

Exit code: 0 healthy / skipped / another run in progress; 1 not healthy (the unit
shows `failed` in `systemctl`, which is intended); 2 misconfigured.

`KNOWN-BLIND` is accepted because the registry says so (`KNOWN_BLIND=<issue>` in
the entry's conf); it stays visible in every summary and flips to `BLIND-FIXED`
(alerted) the day the harness sees its plant.

## What it does NOT verify

- **That a harness has an entry.** A new harness with no entry is invisible here.
  Entries still need their own red-proof when written (plant red, control green).
- **That an entry's plant is a realistic defect.** It proves the harness sees *this*
  plant, on its seed corpus, deterministically. It does not fuzz.
- **That a `KNOWN-BLIND` harness is being fixed.** It alerts once (when the entry
  was flagged), then never again until it flips.
- **Anything about a night that was skipped.** A skipped night tests nothing; only
  the 3-night counter says so.
- **Anything while the host is off, or the timer is disabled or failed to start.**
  Nothing in this design notices silence from the host itself (see "Residual risks").
- **DashDiag entries** (`dashdiag.d/`); this runs keyorix's `entries.d/` only.
- **That the benchmark lock stays free for the whole run.** The lock is checked
  once, at start (the cross-replica rig also re-checks it while running; this does
  not).
- Alert delivery beyond a successful `curl` exit; ntfy has no acknowledgement.

## Install (coordinator, on pve01, as root)

Sessions cannot do this (no pve01 root). Nothing here was run on pve01 by the
author of the PR; the units and the built-in temperature gate are untested on that
host, hence steps 6 and 7.

1. **User and directories.**
   ```
   useradd --system --create-home --home-dir /var/lib/oracle-health-nightly \
           --shell /usr/sbin/nologin oracle-health
   install -d -o oracle-health -g oracle-health /opt/oracle-health-nightly
   ```
2. **Dedicated clone** (read access to `keyorixhq/keyorix`, e.g. a read-only deploy key
   for this user). Do not point this at a working checkout: it is fast-forwarded and
   a dirty tree is refused.
   ```
   sudo -u oracle-health git clone git@github.com:keyorixhq/keyorix.git /opt/oracle-health-nightly/keyorix
   sudo -u oracle-health go version        # must be the Go the repo's go.mod needs
   ```
   If `go` is not on systemd's default PATH, set `PATH=` in the env file (step 4).
   Until this PR is merged, the clone has no `nightly/` directory: clone the PR
   branch, or install the three files from the PR by hand and `git pull` after merge.
3. **Postgres role.** The heavy entries (`canary-echo-pg`, `authzdiff-plants`) need a
   superuser; the other `pg` entries need a database. This is a superuser on the
   shared Postgres 17: if a separate cluster is possible, prefer it.
   ```
   sudo -u postgres createuser --superuser --pwprompt oh_nightly
   ```
4. **Environment file** (mode 0600, root-owned; never commit it).
   ```
   install -d -m 0755 /etc/oracle-health-nightly
   install -m 0600 -o root -g root \
     /opt/oracle-health-nightly/keyorix/scripts/fuzzing/oracle-health/nightly/oracle-health-nightly.env.example \
     /etc/oracle-health-nightly/env
   $EDITOR /etc/oracle-health-nightly/env   # set KEYORIX_TEST_PG_DSN (the oh_nightly role), PATH if needed
   ```
5. **Units.**
   ```
   install -m 0644 /opt/oracle-health-nightly/keyorix/scripts/fuzzing/oracle-health/nightly/oracle-health-nightly.service /etc/systemd/system/
   install -m 0644 /opt/oracle-health-nightly/keyorix/scripts/fuzzing/oracle-health/nightly/oracle-health-nightly.timer   /etc/systemd/system/
   systemctl daemon-reload
   ```
6. **Check the gate and the alert path before enabling** (both run as the service user
   with the real env file):
   ```
   systemd-run --pipe --wait --collect -p User=oracle-health -p EnvironmentFile=/etc/oracle-health-nightly/env \
     /opt/oracle-health-nightly/keyorix/scripts/fuzzing/oracle-health/nightly/oracle-health-nightly.sh --gate-only
   systemd-run --pipe --wait --collect -p User=oracle-health -p EnvironmentFile=/etc/oracle-health-nightly/env \
     /opt/oracle-health-nightly/keyorix/scripts/fuzzing/oracle-health/nightly/oracle-health-nightly.sh --test-alert
   ```
   `--gate-only` must print `gate: go` on an idle host. If it says `temperature
   unreadable`, set `OHN_TEMP_CMD`; if `no search permission on /root`, the service
   user cannot see `/root/PVE-BENCH-LOCK` (make a readable copy of the convention, or
   run the unit as root like `keyorix-xreplica-fuzz.service`). The wave8 launch gate
   (`/mnt/data/wave8/gate.sh`) was not available to the author; if you prefer it, set
   `OHN_GATE_CMD=/mnt/data/wave8/gate.sh` after checking that it exits 0 for "go". The
   built-in thresholds are the ones in the brief (86 C, load5 6, 12 GB) plus a
   `/dev/shm` floor (8 GB, an estimate). `--test-alert` must produce one message on
   the `andrey_fuzz_allert` topic.
7. **Run once by hand** (see below) and read the summary before trusting the timer.
8. **Enable.**
   ```
   systemctl enable --now oracle-health-nightly.timer
   systemctl list-timers oracle-health-nightly.timer
   ```
   The timer fires at 03:40 local +- 20 min (`RandomizedDelaySec`) and, with
   `Persistent=true`, once after a boot that missed it (the gate still applies).
   Check `systemctl list-timers` for other jobs near that time.

## Run it once by hand

```
systemctl start oracle-health-nightly.service      # blocks until done; goes through the gate
journalctl -u oracle-health-nightly.service -n 50 --no-pager
ls -t /var/lib/oracle-health-nightly/logs | head
cat /var/lib/oracle-health-nightly/logs/oracle-health-<stamp>.summary
```
A gate refusal is a skip, not a failure: the reason is in `logs/nightly.log` and the
unit exits 0. Do not delete the benchmark lock to force a run. For a one-entry check
use the runner directly as the service user, from the clone:
`scripts/fuzzing/oracle-health/oracle-health.sh --only <id>`.

## Disable

```
systemctl disable --now oracle-health-nightly.timer
systemctl stop oracle-health-nightly.service          # only if a run is in progress
```
Full removal: delete `/etc/systemd/system/oracle-health-nightly.{service,timer}`,
`/etc/oracle-health-nightly/`, `/opt/oracle-health-nightly/`,
`/var/lib/oracle-health-nightly/` (the logs), run `systemctl daemon-reload`,
`sudo -u postgres dropuser oh_nightly` and `userdel oracle-health`. Disabling is
silent by design: it neither alerts nor leaves a counter behind, so note it
somewhere a person will read.

## Residual risks

- **pve01 off, or the timer not running: silence.** The stale counter runs on pve01
  itself, so it cannot report that pve01 is down. A skipped-forever night (lock held
  for weeks, a hot host) alerts on the 3rd night and then daily; a host that is off
  alerts nothing. Cheap outside check: from any other machine, "newest
  `oracle-health-*.summary` on pve01 is older than 36 h". Not implemented here.
- **Skipped-forever looks like this:** `nightly.log` lines `SKIPPED night N in a row:
  <reason>`, `consecutive-skips` growing, a daily `STALE=SKIPPED-N-NIGHTS` ntfy line
  quoting the last reason, and no new `.summary` files.
- **Alert fatigue.** One persistent `MISSED` alerts once per day, every day, until
  fixed or flagged `KNOWN_BLIND` in the registry.
- **Superuser DSN on a shared Postgres**, and a host-level lock only checked at start.
- **Resource estimates are unmeasured on pve01**: tmpfs use (22 trees kept until the
  run ends, charged to the unit's `MemoryMax=12G` cgroup), run time (3 h limit) and
  `TimeoutStartSec=3h30m` are guesses; read the first real run's `secs=` and the peak
  `/dev/shm` use and adjust.
- A dirty or diverged clone stops the nightly (alerted) until someone cleans it.
