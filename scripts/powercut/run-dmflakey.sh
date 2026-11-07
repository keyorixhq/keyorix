#!/usr/bin/env bash
# Power-cut test for the SQLite backend on a dm-flakey device.
#
#   sudo scripts/powercut/run-dmflakey.sh --bin ./powercut [--fdatasync] [--n 20000] [--run-secs 5]
#
# Needs root, a Linux kernel with dm-flakey (modprobe dm-flakey), dmsetup,
# losetup, mkfs.ext4, e2fsck. It works on a sparse file behind a loop device it
# creates itself; it never touches an existing block device.
#
# Sequence:
#   1. ext4 on loop -> dm-flakey (healthy "linear"-like state: up forever).
#   2. `powercut write` commits audit events on that filesystem and records each
#      acknowledgement (index + timestamp) on the HOST filesystem.
#   3. After --run-secs: record the cut time, suspend the device, reload it as
#      flakey with drop_writes (every write silently dropped), resume. Writers
#      keep "succeeding" for 1s; those acks promise nothing and are excluded.
#   4. kill -9 the writer, force-unmount, remove the mapping (page cache of the
#      device is discarded: this is the power cut).
#   5. Recreate the mapping healthy, mount (ext4 replays its journal), then
#      `powercut verify`: PRAGMA integrity_check, audit hash chain, and every
#      commit acknowledged before the cut is present. Also e2fsck -fn.
#
# What this does NOT model: a disk whose volatile write cache lies about
# flushes, torn sector writes, or any filesystem other than ext4. dm-flakey
# drops whole bios after the point it is switched; flushes issued before the
# switch are honoured. A PASS means "no acknowledged commit lost on ext4 over
# dm-flakey in this run", not a proof for all power-loss behaviour.
set -euo pipefail

BIN=""
FDATASYNC=""
N=20000
RUN_SECS=5
WORKERS=4
SIZE_MB=512
WORK=/var/tmp/powercut

while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN=$2; shift 2 ;;
    --fdatasync) FDATASYNC=-fdatasync; shift ;;
    --n) N=$2; shift 2 ;;
    --run-secs) RUN_SECS=$2; shift 2 ;;
    --workers) WORKERS=$2; shift 2 ;;
    --size-mb) SIZE_MB=$2; shift 2 ;;
    --work) WORK=$2; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done

[ -n "$BIN" ] || { echo "--bin is required" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "must run as root (dmsetup/losetup/mount)" >&2; exit 2; }
for c in dmsetup losetup mkfs.ext4 e2fsck mount umount blockdev; do
  command -v "$c" >/dev/null || { echo "missing command: $c" >&2; exit 2; }
done
modprobe dm-flakey 2>/dev/null || true
dmsetup targets | grep -q '^flakey' || { echo "kernel has no dm-flakey target" >&2; exit 2; }

NAME=powercut-$$
IMG=$WORK/$NAME.img
MNT=$WORK/$NAME.mnt
ACKS=$WORK/$NAME.acks
LOOP=""
WPID=""
mkdir -p "$WORK" "$MNT"

cleanup() {
  [ -n "$WPID" ] && kill -9 "$WPID" 2>/dev/null || true
  mountpoint -q "$MNT" && umount -l "$MNT" || true
  dmsetup remove --retry "$NAME" 2>/dev/null || true
  [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
  rm -f "$IMG"
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
echo "device=/dev/mapper/$NAME backing=$IMG ($(df -P "$WORK" | tail -1 | awk '{print $1}')) fs=$FSTYPE fdatasync=$([ -n "$FDATASYNC" ] && echo on || echo off)"

: >"$ACKS"
"$BIN" write -db "$MNT/pc.db" -acks "$ACKS" $FDATASYNC -n "$N" -workers "$WORKERS" &
WPID=$!
sleep "$RUN_SECS"
kill -0 "$WPID" 2>/dev/null || { echo "writer finished before the cut; raise --n or lower --run-secs" >&2; exit 3; }

CUT_NS=$(date +%s%N)
dmsetup suspend "$NAME"
dropping_table | dmsetup load "$NAME"
dmsetup resume "$NAME"
sleep 1
kill -9 "$WPID" 2>/dev/null || true
wait "$WPID" 2>/dev/null || true
WPID=""

umount -l "$MNT" || true
dmsetup remove --retry "$NAME"
blockdev --flushbufs "$LOOP"

healthy_table | dmsetup create "$NAME"
mount "/dev/mapper/$NAME" "$MNT"   # ext4 journal replay happens here
set +e
"$BIN" verify -db "$MNT/pc.db" -acks "$ACKS" -cutoff-ns "$CUT_NS"
RC=$?
set -e

# Positive control: judged against ALL acks (no cutoff), the run must FAIL,
# because commits acknowledged after the cut were dropped. If it passes, the
# drop never took effect and the PASS above proved nothing.
set +e
"$BIN" verify -db "$MNT/pc.db" -acks "$ACKS" >"$WORK/$NAME.control.txt" 2>&1
CRC=$?
set -e
if [ "$CRC" = 0 ]; then
  echo "CONTROL FAILED: commits acknowledged after the cut were all present; dm-flakey dropped nothing, result is vacuous" >&2
  RC=4
else
  echo "control ok: $(grep -m1 '^acknowledged_before_cut=' "$WORK/$NAME.control.txt")"
fi
umount "$MNT"
e2fsck -fn "/dev/mapper/$NAME" >"$WORK/$NAME.e2fsck.txt" 2>&1 && FSCK=clean || FSCK="exit-$?"
echo "e2fsck=$FSCK (log: $WORK/$NAME.e2fsck.txt)"
exit "$RC"
