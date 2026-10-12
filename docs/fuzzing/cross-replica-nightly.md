# Nightly cross-replica invariant run

Operator runbook for `scripts/fuzzing/nightly-cross-replica.sh` and its systemd
units (`scripts/fuzzing/systemd/keyorix-xreplica-fuzz.{service,timer}`).

## Why this target has its own unit

Every other Keyorix fuzz target runs under the external `fuzz-harness` runner
(see `scripts/fuzzing/README.md`: one standardized runner shared with DashDiag
and the third-party-libs rigs). `FuzzCrossReplicaInvariants` cannot, and the
reason matters: it needs a real multi-connection PostgreSQL server and
**skips outright** when `KEYORIX_TEST_PG_DSN` is unset. On the generic rig it
would therefore report a perfect clean run forever — the worst failure mode a
fuzz target can have, because it is indistinguishable from working.

So it gets its own unit with its own throwaway Postgres. Everything *else*
about it deliberately matches the shared rig's conventions rather than
inventing new ones: crashers go to the **private** corpus repo only, never a
public issue or PR (an unfixed own-code race must not be disclosed before its
fix); one ntfy line per **new** failure; the topic URL travels via `curl -K`
so it never appears in `ps`.

## What a run does

1. **Host-lock check.** If `/root/PVE-BENCH-LOCK` exists, the run **skips**
   (exit 0, no alert). pve01 is shared with the benchmark sessions, whose
   numbers a parallel CPU load silently corrupts. A skipped night is not a
   failure and must not page anyone.
2. **Update the checkout** to `origin/main` and `git clean` the in-tree fuzz
   corpus directory. The clean is not cosmetic — see "Gotchas" below.
3. **Start a dedicated Postgres**, wait for `pg_isready` (not a guessed
   `sleep`), export `KEYORIX_TEST_PG_DSN`.
4. **Ordering sweep** (`KEYORIX_INTERLEAVE_SWEEP=1`,
   `TestOrderingSweep_Postgres`): ~175 forced interleavings across the
   conflicting-pair catalog. This is the only place that enumeration runs
   anywhere. It runs **first**: a sweep failure is a specific, named,
   reproducible finding, worth alerting on immediately rather than after four
   hours of fuzzing.
5. **Fuzz** `FuzzCrossReplicaInvariants` for `$FUZZTIME`.
6. **Classify and alert.** A new crasher whose violation lines all name an
   issue in `KNOWN_OPEN_CLASSES` is logged and kept but **not** alerted on.
   Anything else pushes one ntfy line and exits 1.

A **lock watcher** runs throughout and aborts cleanly if a benchmark session
claims the lock mid-run. Checking only at startup would be useless: the run is
four hours long and the benchmark sessions start whenever their operator is
awake. An interrupted run is reported as "no finding", never as a failure, so
it cannot produce a false alert.

## Install

Installation is the **only** step that needs `/root/PVE-BENCH-LOCK`: it
compiles the Go test binary, which is exactly the CPU load the lock exists to
keep off a benchmark. Take it, install, release it. The nightly run itself
needs no lock — it checks for one and yields.

```sh
# 0. Claim the lock (NEVER delete another session's claim; wait instead).
ssh root@192.168.10.20 'cat /root/PVE-BENCH-LOCK 2>/dev/null'   # must be empty
ssh root@192.168.10.20 'echo "xreplica-install $(date -u +%FT%TZ)" > /root/PVE-BENCH-LOCK'

# 1. Lay out the rig (on the box, as root).
mkdir -p /opt/keyorix-xreplica/{state,go-cache,go-mod,gopath}
git clone https://github.com/keyorixhq/keyorix.git /opt/keyorix-xreplica/keyorix
git clone <private fuzz-corpus remote> /opt/keyorix-xreplica/fuzz-corpus

# 2. Config. NTFY_TOPIC is the only value you must set for the rig to be
#    useful: without it, a finding goes to a log and nobody is told.
mkdir -p /etc/keyorix-xreplica
install -m 0600 /opt/keyorix-xreplica/keyorix/scripts/fuzzing/systemd/config.env.example \
    /etc/keyorix-xreplica/config.env
$EDITOR /etc/keyorix-xreplica/config.env

# 3. Prove the pieces work BEFORE trusting the timer. See "Smoke test" below.

# 4. Units.
cp /opt/keyorix-xreplica/keyorix/scripts/fuzzing/systemd/keyorix-xreplica-fuzz.* \
    /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now keyorix-xreplica-fuzz.timer
systemctl list-timers keyorix-xreplica-fuzz.timer

# 5. Release the lock.
ssh root@192.168.10.20 'rm -f /root/PVE-BENCH-LOCK'
```

## Smoke test

A guard nobody has watched fail is not a guard, and this script decides
whether a human gets woken up. Watch it do all four things before enabling the
timer. `KEYORIX_REF` exists for exactly this: it lets you point a run at a
branch, so the first time anyone sees the script run is not the first night it
mattered.

```sh
# a) the classifier, both directions, no Postgres needed (9 cases)
scripts/fuzzing/nightly-cross-replica.sh --self-test

# b) the host-lock skip path: must exit 0 and send nothing
printf 'SOMEONE-ELSE %s\n' "$(date -u +%FT%TZ)" > /tmp/fake-lock
HOST_LOCK=/tmp/fake-lock scripts/fuzzing/nightly-cross-replica.sh

# c) the happy path, short budget, sweep off (the sweep is minutes)
STATE_DIR=/tmp/xr-smoke HOST_LOCK= RUN_SWEEP=0 FUZZTIME=120s \
  KEYORIX_REF=origin/main scripts/fuzzing/nightly-cross-replica.sh

# d) the sweep, once, on its own
STATE_DIR=/tmp/xr-smoke HOST_LOCK= FUZZTIME=1s scripts/fuzzing/nightly-cross-replica.sh
```

`RUN_SWEEP=0` is for (c) only. Leaving it off permanently would reduce this
unit to running a fuzz target, which is the one half CI cannot do but also the
half with no enumeration behind it.

## Gotchas found by actually running it

These are recorded because each one was a real failure during the first
afternoon of smoke runs, and each would have silently degraded the rig.

- **`git reset --hard` does not remove untracked files, and `go test -fuzz`
  writes crashers as untracked files.** Without the scoped `git clean` in
  step 2, the first crasher poisons every subsequent night: it replays in the
  seed phase, the run fails before exploring anything, no *new* corpus entry
  appears, and the "non-zero exit with no new entry" branch reports "the rig
  is broken". Wrong, and the kind of wrong that gets a rig switched off.
- **"Failed but wrote nothing new" has two causes and they need different
  readings.** An invariant break on an already-committed corpus seed is a
  regression (a finding). No invariant line at all is a rig fault (build
  failure, dead Postgres). Alerting "a race was found" for the second sends
  the reader to entirely the wrong place.
- **The fuzzer emits combined class markers** — `(#2646/#2647 class)`,
  `(#2653/#2654 class)`, `(#2657/#2659 class)`. A suppression matcher that
  only knew the single `#NNNN class` form suppressed none of them. Caught by
  `--self-test`'s combined-marker case on its first run, not by reading the
  code. The classifier now extracts every number in the marker and requires
  all of them to be listed.
- **The ordering sweep was quadratic.** Checking the audit-chain invariant
  after each of 174 runs re-hashes a monotonically growing audit log; the first
  real sweep blew a 60-minute timeout without finishing. The chain is now
  checked once at the end of the sweep (and still per-pair in the per-issue
  tests and the fuzz target, where attributing a break to one operation is the
  point).

## `KNOWN_OPEN_CLASSES`: why it exists and when to delete entries

The first smoke run of this script found **#2649 by blind fuzzing in seven
seconds**. That is not luck: before #2768 fixed the fuzzer's world, the whole
share/ACL op family could not execute at all and its invariants were vacuous.
Now they are reachable immediately — and with the fix stack (#2664, #2667,
#2668, #2669, #2671–#2675) still open, an unsuppressed rig would spend every
night re-reporting the same known bugs, never get deep enough into the input
space to find a new one, and train its recipient to mute the topic. That last
part is how a real second finding gets missed.

Same discipline as `server/faultops`' `knownOpenTolerances` (COMMON-RULES):
scope the entry to the specific open issue, and **delete it in the PR that
fixes that issue**. A suppression that outlives its bug silences a regression
forever. The sweep step is deliberately *not* suppressible — its ledger
(`g5KnownOrderingViolations`) lives in-tree, where a stale row fails
`TestOrderingSweep_KnownViolationKeysAreWellFormed`.

Current value to set, until that stack lands:

```
KNOWN_OPEN_CLASSES=2646 2647 2649 2650 2651 2652 2653 2654 2655 2656 2657 2659
```

## Scheduling

`OnCalendar=*-*-* 01:00:00` local, `RandomizedDelaySec=10m`,
`Persistent=false`.

- **Local, not UTC**: the 01:00–05:00 window exists because a human operator
  is asleep, and that follows local time.
- **`Persistent=false`, unlike `keyorix-mutation.timer`**: a missed night must
  not be made up at boot. A catch-up run firing at 10:00 because the box was
  down overnight lands squarely in a benchmark session. The script would skip
  it only if the lock happened to be held at that exact moment, which is not
  something to rely on.
- `FUZZTIME` defaults to **3h45m, not the brief's literal 4h**: the window is
  four hours *wide*, and the run also pays for the container start, the schema
  migration, the ordering sweep and the corpus push. A literal 4h fuzztime
  starting at 01:00 ends after 05:00 and collides with exactly the window the
  whole lock dance exists to protect. `RuntimeMaxSec=4h15m` in the unit is the
  backstop.

## Reading a run

```sh
systemctl status keyorix-xreplica-fuzz.service
journalctl -u keyorix-xreplica-fuzz.service -n 100 --no-pager
ls -t /opt/keyorix-xreplica/state/runs/ | head
```

Exit codes: `0` clean or skipped; `1` a finding; `2` the rig itself is broken.

Alert dedup markers live in `/opt/keyorix-xreplica/state/alerted/`. Delete one
to make its finding page again — e.g. after a fix lands and you want to
confirm the finding is genuinely gone rather than merely deduplicated.
