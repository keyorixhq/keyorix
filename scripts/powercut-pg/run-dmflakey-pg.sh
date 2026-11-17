#!/usr/bin/env bash
# Power-cut test for the PostgreSQL backend on a dm-flakey device.
#
#   sudo scripts/powercut-pg/run-dmflakey-pg.sh [--cut-mode wal|checkpoint|clean]
#        [--durability strict|standard] [--n 20000] [--run-secs 5] [--workers 4]
#
# The PostgreSQL twin of scripts/powercut/run-dmflakey.sh. It builds its own
# sparse file -> loop device -> dm-flakey -> ext4 exactly like that script, then
# `initdb`s a THROWAWAY PostgreSQL 17 cluster whose data directory lives on that
# filesystem and starts `postgres` on it on a scratch Unix socket (it NEVER
# touches the host's real cluster: a different data dir, a different socket, a
# non-default port, run as the `postgres` system user because the server refuses
# to run as root). It then commits acknowledged Keyorix audit events through the
# PRODUCTION storage factory (scripts/powercut-pg, storage.type: postgres),
# cuts power with dm-flakey drop_writes + force unmount + mapping removal,
# recreates the device healthy, remounts (ext4 replays its journal), restarts
# `postgres` (which runs its OWN crash recovery / WAL replay — the part the
# in-process SQLite tool has no equivalent of), and verifies no acknowledged
# commit was lost.
#
# Needs root, dm-flakey (modprobe dm-flakey), dmsetup/losetup/mkfs.ext4/e2fsck,
# and PostgreSQL 17 server binaries on PATH or at /usr/lib/postgresql/17/bin.
#
# Sequence:
#   1. ext4 on loop -> dm-flakey (healthy). initdb a fresh cluster on it, start
#      `postgres` (fsync=on, synchronous_commit=on, full_page_writes=on).
#   2. `powercut-pg write` commits audit events on that cluster and records each
#      acknowledgement (index + timestamp) on the HOST filesystem. Under
#      -durability strict a returned commit means its WAL record was fsync'd
#      (the sound oracle); -durability standard is Postgres's own relaxed
#      default where an acknowledgement promises nothing (a NEGATIVE control —
#      acknowledged commits MAY be lost there, by design, not a failure).
#   3. --cut-mode picks when: `wal` cuts mid-write-stream; `checkpoint` fires a
#      CHECKPOINT at the cut instant to catch a mid-checkpoint crash; `clean`
#      drains the writer and CHECKPOINTs BEFORE the cut (nothing in flight — the
#      sanity control that must always pass).
#   4. Record the cut time, suspend --nolockfs, load the drop_writes table,
#      resume. The writer keeps "succeeding" ~1s; those acks are after the cut
#      and excluded. kill -9 the writer and `postgres`, force-unmount, remove
#      the mapping (device page cache discarded: this is the power cut).
#   5. Recreate healthy, mount (ext4 journal replay), restart `postgres` (WAL
#      replay — the server log is checked for a clean recovery, not just that it
#      started), then `powercut-pg verify`: every commit acknowledged before the
#      cut is present and the audit hash chain verifies. pg_amcheck (heap+btree
#      structural check, the Postgres analog of SQLite's PRAGMA integrity_check)
#      runs while the server is up; e2fsck -fn runs after it is stopped. Either
#      failing fails the run.
#
# What this does NOT model (same as the SQLite tool): a disk whose volatile
# write cache lies about flushes, torn sector writes below the bio layer, or any
# filesystem other than ext4. dm-flakey drops whole bios after the switch;
# flushes issued before it are honoured. A PASS means "no acknowledged commit
# lost on ext4 over dm-flakey in this run", not a proof for all power-loss
# behaviour.
set -euo pipefail

PGBIN=/usr/lib/postgresql/17/bin
[ -x "$PGBIN/initdb" ] || PGBIN=$(dirname "$(command -v initdb 2>/dev/null || true)")

BIN=""
DURABILITY=strict
CUT_MODE=wal
N=20000
RUN_SECS=5
WORKERS=4
SIZE_MB=1024
PORT=0
WORK=/var/tmp/powercut-pg

while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN=$2; shift 2 ;;
    --durability) DURABILITY=$2; shift 2 ;;
    --cut-mode) CUT_MODE=$2; shift 2 ;;
    --n) N=$2; shift 2 ;;
    --run-secs) RUN_SECS=$2; shift 2 ;;
    --workers) WORKERS=$2; shift 2 ;;
    --size-mb) SIZE_MB=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    --work) WORK=$2; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done

case "$CUT_MODE" in wal|checkpoint|clean) ;; *) echo "unknown --cut-mode $CUT_MODE" >&2; exit 2 ;; esac
case "$DURABILITY" in strict|standard) ;; *) echo "unknown --durability $DURABILITY" >&2; exit 2 ;; esac
[ "$(id -u)" = 0 ] || { echo "must run as root (dmsetup/losetup/mount)" >&2; exit 2; }
for c in dmsetup losetup mkfs.ext4 e2fsck mount umount blockdev runuser; do
  command -v "$c" >/dev/null || { echo "missing command: $c" >&2; exit 2; }
done
for c in initdb pg_ctl postgres psql pg_amcheck; do
  [ -x "$PGBIN/$c" ] || { echo "missing postgres binary: $PGBIN/$c" >&2; exit 2; }
done
id postgres >/dev/null 2>&1 || { echo "no 'postgres' system user to run the server as" >&2; exit 2; }
modprobe dm-flakey 2>/dev/null || true
dmsetup targets | grep -q '^flakey' || { echo "kernel has no dm-flakey target" >&2; exit 2; }

# Build the tool if --bin was not given.
if [ -z "$BIN" ]; then
  REPO=$(cd "$(dirname "$0")/../.." && pwd)
  BIN=$WORK/powercut-pg.bin
  mkdir -p "$WORK"
  echo "building powercut-pg -> $BIN"
  ( cd "$REPO" && go build -o "$BIN" ./scripts/powercut-pg )
fi

[ "$PORT" = 0 ] && PORT=$(( 50000 + (RANDOM % 10000) ))

NAME=pcpg-$$
IMG=$WORK/$NAME.img
MNT=$WORK/$NAME.mnt
PGDATA=$MNT/pgdata
SOCKDIR=$WORK/$NAME.sock
ACKS=$WORK/$NAME.acks
PGLOG=$WORK/$NAME.pg.log
LOOP=""
WPID=""
mkdir -p "$WORK" "$MNT" "$SOCKDIR"
# 755, not 777: root runs $BIN from here, so no other user may write into it.
# postgres only needs to traverse $WORK to reach the mount and its socket dir.
chmod 755 "$WORK"
# postgres (the system user) must be able to traverse to the mount and own the socket dir.
chmod 755 "$MNT"
chown postgres:postgres "$SOCKDIR"

as_pg() { runuser -u postgres -- "$@"; }

pg_running() { [ -f "$PGDATA/postmaster.pid" ] && kill -0 "$(head -1 "$PGDATA/postmaster.pid")" 2>/dev/null; }

pg_kill9() {
  # kill -9 the whole cluster hard (NO clean shutdown / checkpoint — this is the
  # cut), emulating the total loss of process + shared memory a real power cut
  # causes. Scoped to THIS data dir so the host's real cluster is never touched.
  # Kill the postmaster's whole process GROUP so every child backend dies too —
  # an orphaned backend still holding the socket/shm is what made the restart
  # refuse with "another server might be running".
  local pid pgid
  if [ -f "$PGDATA/postmaster.pid" ]; then
    pid=$(head -1 "$PGDATA/postmaster.pid")
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
    [ -n "$pgid" ] && kill -9 -- "-$pgid" 2>/dev/null || true
    kill -9 "$pid" 2>/dev/null || true
  fi
  pkill -9 -f "postgres -D $PGDATA" 2>/dev/null || true
  # Wait for every matching process to actually be gone.
  for _ in $(seq 1 40); do
    pgrep -f "postgres -D $PGDATA" >/dev/null 2>&1 || break
    sleep 0.25
  done
}

# pg_clear_stale removes the stale postmaster.pid a kill -9 leaves behind. On a
# real reboot there are no postgres processes and no shared memory, so postgres
# starts despite a stale pid; on this still-running host we clear it explicitly
# AFTER confirming (pg_kill9) every process is gone, so the restart does genuine
# crash recovery instead of refusing. Never called while any backend is alive.
pg_clear_stale() {
  rm -f "$PGDATA/postmaster.pid" 2>/dev/null || true
}

cleanup() {
  [ -n "$WPID" ] && kill -9 "$WPID" 2>/dev/null || true
  pg_kill9
  sleep 0.3
  mountpoint -q "$MNT" && umount -l "$MNT" || true
  dmsetup remove --retry "$NAME" 2>/dev/null || true
  [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
  rm -f "$IMG"
  rm -rf "$SOCKDIR"
  rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

truncate -s "${SIZE_MB}M" "$IMG"
LOOP=$(losetup -f --show "$IMG")
SECTORS=$(blockdev --getsz "$LOOP")

healthy_table() { echo "0 $SECTORS flakey $LOOP 0 1 0"; }
dropping_table() { echo "0 $SECTORS flakey $LOOP 0 0 1 1 drop_writes"; }

healthy_table | dmsetup create "$NAME"
mkfs.ext4 -q -F "/dev/mapper/$NAME"
mount "/dev/mapper/$NAME" "$MNT"
FSTYPE=$(findmnt -no FSTYPE "$MNT")

# Fresh data dir on the dm-flakey filesystem, owned by the postgres user.
install -d -o postgres -g postgres -m 700 "$PGDATA"
as_pg "$PGBIN/initdb" -D "$PGDATA" --auth-local=trust --auth-host=trust -U postgres >/dev/null
# initdb's final pass fsyncs the whole data directory, so the default
# postgresql.conf it wrote is DURABLE before the first write. Every override is
# passed as a `postgres -c` command-line option (PGOPTS) rather than appended to
# the config file: a shell append is not fsync'd, so the cut would otherwise
# shear the config's tail and the post-cut restart would die on a syntax error
# (an artifact of the harness, not of Postgres). The durability knobs below are
# the stock defaults, pinned so a packaging change cannot silently weaken the
# test: synchronous_commit=on + fsync=on is what makes a returned COMMIT under
# -durability strict a real fsync.
PGOPTS="-c port=$PORT -c unix_socket_directories=$SOCKDIR -c listen_addresses= -c unix_socket_permissions=0700 -c fsync=on -c synchronous_commit=on -c full_page_writes=on -c wal_level=replica"
[ "$CUT_MODE" = checkpoint ] && PGOPTS="$PGOPTS -c checkpoint_timeout=30s"

touch "$PGLOG"; chown postgres:postgres "$PGLOG"
as_pg "$PGBIN/pg_ctl" -D "$PGDATA" -l "$PGLOG" -o "$PGOPTS" -w -t 60 start >/dev/null
for _ in $(seq 1 60); do
  as_pg "$PGBIN/pg_isready" -h "$SOCKDIR" -p "$PORT" -U postgres >/dev/null 2>&1 && break
  sleep 0.5
done
as_pg "$PGBIN/pg_isready" -h "$SOCKDIR" -p "$PORT" -U postgres >/dev/null 2>&1 || { echo "postgres did not come up" >&2; cat "$PGLOG" >&2; exit 3; }

DSN="host=$SOCKDIR port=$PORT dbname=postgres user=postgres sslmode=disable"
echo "device=/dev/mapper/$NAME backing=$IMG fs=$FSTYPE pg=$PGDATA port=$PORT cut-mode=$CUT_MODE durability=$DURABILITY"

: >"$ACKS"

if [ "$CUT_MODE" = clean ]; then
  # Negative control: run the writer to completion, CHECKPOINT so every ack is
  # on disk, THEN cut. Nothing is in flight, so no acknowledged commit may be
  # lost (verified against ALL acks below).
  "$BIN" write -dsn "$DSN" -acks "$ACKS" -durability "$DURABILITY" -n "$N" -workers "$WORKERS"
  as_pg "$PGBIN/psql" -h "$SOCKDIR" -p "$PORT" -U postgres -c "CHECKPOINT" >/dev/null
  CUT_NS=0   # require EVERY ack
else
  "$BIN" write -dsn "$DSN" -acks "$ACKS" -durability "$DURABILITY" -n "$N" -workers "$WORKERS" &
  WPID=$!
  sleep "$RUN_SECS"
  kill -0 "$WPID" 2>/dev/null || { echo "writer finished before the cut; raise --n or lower --run-secs" >&2; exit 3; }
  CUT_NS=$(date +%s%N)
  if [ "$CUT_MODE" = checkpoint ]; then
    # Drive a CHECKPOINT so the crash lands mid-checkpoint (buffers being flushed
    # to the heap while WAL keeps advancing).
    as_pg "$PGBIN/psql" -h "$SOCKDIR" -p "$PORT" -U postgres -c "CHECKPOINT" >/dev/null 2>&1 &
  fi
fi

# --nolockfs: a plain suspend freezes the filesystem (sync_filesystem) first,
# writing every dirty page and the journal to the device BEFORE the drop table
# loads — which would make durable whatever the commit's own sync left unsynced.
# xfstests' dm-flakey helper uses --nolockfs for the same reason.
dmsetup suspend --nolockfs "$NAME"
dropping_table | dmsetup load "$NAME"
dmsetup resume "$NAME"
sleep 1
[ -n "$WPID" ] && { kill -9 "$WPID" 2>/dev/null || true; wait "$WPID" 2>/dev/null || true; WPID=""; }
pg_kill9
sleep 0.5

umount -l "$MNT" || true
dmsetup remove --retry "$NAME"
blockdev --flushbufs "$LOOP"

healthy_table | dmsetup create "$NAME"
mount "/dev/mapper/$NAME" "$MNT"   # ext4 journal replay happens here

# Restart postgres on the recovered data dir: this is the Postgres-specific part
# — crash recovery / WAL replay. Confirm it from the server log, not just "it
# started". Mark a boundary in the (appended) log so we read THIS boot's lines,
# and clear the stale pid the kill -9 left so the restart does real recovery.
pg_clear_stale
echo "=== RESTART-AFTER-CUT $(date +%s%N) ===" >>"$PGLOG"
BOOT2_FROM=$(( $(grep -c '' "$PGLOG") ))
set +e
as_pg "$PGBIN/pg_ctl" -D "$PGDATA" -l "$PGLOG" -o "$PGOPTS" -w -t 120 start >/dev/null
START_RC=$?
set -e
for _ in $(seq 1 120); do
  as_pg "$PGBIN/pg_isready" -h "$SOCKDIR" -p "$PORT" -U postgres >/dev/null 2>&1 && break
  sleep 0.5
done

BOOT2LOG=$WORK/$NAME.boot2.log
tail -n +"$BOOT2_FROM" "$PGLOG" >"$BOOT2LOG" 2>/dev/null || cp "$PGLOG" "$BOOT2LOG"
RECOVERED=no
if as_pg "$PGBIN/pg_isready" -h "$SOCKDIR" -p "$PORT" -U postgres >/dev/null 2>&1; then
  RECOVERED=yes
fi
if grep -qiE 'PANIC|could not locate a valid checkpoint|invalid primary checkpoint|database files are incompatible|corrupt' "$BOOT2LOG"; then
  echo "RECOVERY FAILED: postgres reported corruption on WAL replay:" >&2
  grep -iE 'PANIC|could not|invalid|corrupt|redo' "$BOOT2LOG" >&2 || true
  RECOVERED=no
fi
echo "postgres_recovery=$RECOVERED (start_rc=$START_RC)"
grep -iE 'recovery|redo|ready to accept|not properly shut down' "$BOOT2LOG" | sed 's/^/  pglog: /' || true
if [ "$RECOVERED" != yes ]; then
  echo "postgres did not recover cleanly after the cut; boot2 log:" >&2
  cat "$BOOT2LOG" >&2 || true
  exit 6
fi

RC=0
set +e
"$BIN" verify -dsn "$DSN" -acks "$ACKS" -cutoff-ns "$CUT_NS"
RC=$?
set -e

if [ "$CUT_MODE" = clean ]; then
  # The sanity control: a clean, fully-checkpointed state must lose nothing.
  if [ "$RC" = 0 ]; then
    echo "clean-mode control ok: every acknowledged commit survived a checkpoint-then-cut"
  else
    echo "CONTROL FAILED: clean-mode run lost an acknowledged commit after a CHECKPOINT (no write was in flight)" >&2
  fi
else
  # Positive control: judged against ALL acks (no cutoff) the run MUST fail,
  # because commits acknowledged after the cut were dropped. If it passes, the
  # drop never took effect and the PASS above proved nothing. (Only meaningful
  # under -durability strict; under standard a surviving-everything outcome is
  # legitimate, so the control is informational there.)
  set +e
  "$BIN" verify -dsn "$DSN" -acks "$ACKS" >"$WORK/$NAME.control.txt" 2>&1
  CRC=$?
  set -e
  if [ "$CRC" = 0 ]; then
    if [ "$DURABILITY" = strict ]; then
      echo "CONTROL FAILED: every post-cut ack survived; dm-flakey dropped nothing, result is vacuous" >&2
      [ "$RC" = 0 ] && RC=4
    else
      echo "control (standard): every post-cut ack happened to survive — legitimate under relaxed durability, not a failure"
    fi
  else
    echo "control ok: $(grep -m1 '^acknowledged_before_cut=' "$WORK/$NAME.control.txt" || true)"
  fi
fi

# pg_amcheck: heap + btree structural integrity across every table/index in the
# cluster (the Postgres analog of the SQLite tool's PRAGMA integrity_check). Run
# while the server is up, before the clean stop below. The amcheck extension is
# created AFTER recovery (a post-cut write — the check reads the heap/indexes
# that survived the cut, so when the extension catalog entry was created is
# irrelevant to what it verifies).
as_pg "$PGBIN/psql" -h "$SOCKDIR" -p "$PORT" -U postgres -c "CREATE EXTENSION IF NOT EXISTS amcheck" >/dev/null 2>&1 || true
set +e
as_pg "$PGBIN/pg_amcheck" -h "$SOCKDIR" -p "$PORT" -U postgres -d postgres --heapallindexed >"$WORK/$NAME.amcheck.txt" 2>&1
ACRC=$?
set -e
if [ "$ACRC" = 0 ]; then
  echo "pg_amcheck=clean"
else
  echo "PG_AMCHECK FAILED: structural corruption after the power cut (log: $WORK/$NAME.amcheck.txt)" >&2
  head -20 "$WORK/$NAME.amcheck.txt" >&2 || true
  # A structural failure outranks verify's rc 1 (acknowledged commits missing).
  if [ "$RC" = 0 ] || [ "$RC" = 1 ]; then RC=7; fi
fi

# Clean stop now that verification is done, then fsck the ext4.
as_pg "$PGBIN/pg_ctl" -D "$PGDATA" -m immediate -w -t 60 stop >/dev/null 2>&1 || pg_kill9
sleep 0.3
umount "$MNT"
set +e
e2fsck -fn "/dev/mapper/$NAME" >"$WORK/$NAME.e2fsck.txt" 2>&1
FRC=$?
set -e
if [ "$FRC" = 0 ]; then
  echo "e2fsck=clean"
else
  echo "FSCK FAILED: e2fsck reported problems after the power cut (log: $WORK/$NAME.e2fsck.txt)" >&2
  if [ "$RC" = 0 ] || [ "$RC" = 1 ]; then RC=5; fi
fi

echo "RESULT_RC=$RC"
exit "$RC"
