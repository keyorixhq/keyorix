# FINDING: SIEM spool append/rewrite has no fsync before durability points

**Date:** 2026-09-19
**Component:** `internal/audit/siem/spool.go`
**Status:** Unfixed (finding only, per task scope — do not fix here)

## Summary

`internal/audit/siem/spool.go` persists audit events that could not be
delivered to an external SIEM, so they can be retried later. Two write paths
never `fsync` before the data is considered durable:

- `(*spool).add` (`spool.go:92-118`): opens the spool file
  `O_APPEND|O_CREATE|O_WRONLY` and calls `f.Write` (line 113), then closes via
  a deferred `f.Close()` (line 112). No `f.Sync()` anywhere on this path.
- `(*spool).rewrite` (`spool.go:207-231`): writes the still-undelivered lines
  to a temp file (`tmp.Write`, line 215), `tmp.Close()` (line 222), then
  `os.Rename(tmpName, s.path)` (line 227). No `tmp.Sync()` before either the
  close or the rename.

Under an actual power-loss / OS crash (not merely a killed process — a killed
process's already-`write()`'d bytes are typically still recoverable from page
cache on reboot), the classic "rename without fsync" hazard applies: the
temp file's content is not guaranteed to have reached stable storage before
the rename lands, and on some filesystems/mount options a subsequent crash
can leave the renamed-to file truncated, zero-length, or reverted, even
though the rename itself appeared to succeed to the calling process.

## Durability model traced (this determines severity)

The spool is **not** the audit system of record. Traced the full call path:

1. `internal/core/service.go:607` `emitAudit` calls
   `c.storage.LogAuditEvent(ctx, event)` (line 628) **first** — this is the
   local, DB-backed audit chain (the durable system of record; see
   `store.auditWriteContext` and the request-cancellation-immunity fix
   referenced at `service.go:621-627`). If this write fails, `emitAudit`
   returns immediately (line 634) and explicitly does **not** forward the
   event to the SIEM ("do NOT forward a phantom event... the off-box mirror
   must reflect the durable chain, not events that never landed").
2. Only after that DB write succeeds does `emitAudit` call
   `c.auditForwarder.Forward(event)` (line 637). `AuditForwarder`'s own doc
   comment (`service.go:486`) states it "ships **persisted** audit events to
   an external sink (e.g. a SIEM)."
3. `Forwarder.Forward` (`forwarder.go:234`) is explicitly non-blocking /
   best-effort (doc comment at `forwarder.go:4`, `forwarder.go:232-233`); on
   a full buffer or repeated delivery failure it falls through to
   `f.spool.add(event)` (`forwarder.go:244,307,318`) — i.e. the spool exists
   *only* to retry delivery to the external SIEM, never as a place Keyorix's
   own audit trail depends on for anything.
4. `spool.go`'s own package doc comment (lines 1-9) states this design
   intent directly: "The local audit chain remains the durable system of
   record either way; the spool only protects the off-box mirror... a crash
   mid-rewrite may at worst re-deliver an event (SIEMs dedupe on the event
   id), never silently drop one."

Point 4's claim ("never silently drop one") is the part this finding
qualifies: that guarantee is stated for a *process* crash mid-rewrite, where
`rename`'s atomicity is sufmicient because both the old and new file's
bytes are already in the page cache and survive a process kill. It is not
actually guaranteed under a *power-loss* crash, precisely because of the
missing `fsync` documented above — a power-loss at the wrong instant could
in principle lose spooled-but-undelivered lines (silent drop), not just
cause a re-delivery. The doc comment's stated invariant and the code's
actual guarantee diverge specifically in the power-loss case.

## Severity: **Low**

- The spool is a secondary, best-effort forwarding buffer for the *external*
  SIEM mirror, not Keyorix's own audit trail. `LogAuditEvent` (the DB write)
  is unconditionally durable-first and is never gated on the spool.
- Worst realistic outcome of this gap: under a rare power-loss event
  (not an ordinary process crash/restart, which this code already handles
  correctly via `rename`'s atomicity plus the page-cache-survives property),
  some already-persisted-in-the-DB audit events that were queued for retry
  to the external SIEM could fail to reach that external SIEM and would not
  be retried again (since the spool line recording "this still needs
  delivery" is what could be lost). No secret value, no plaintext, and no
  entry in Keyorix's own authoritative audit chain is at risk.
- This does contradict the spool's own doc-comment claim of "never silently
  drop one" in the power-loss case specifically, which is worth correcting
  (either the comment's precision, or the code, or both) — but it is not a
  security boundary defect (authz/crypto/credential/data-loss-in-the-actual-
  system-of-record), so it does not meet this repo's bar for an urgent fix.

## Scope note

This finding was produced while investigating file-I/O fault-injection seams
for a new fuzz harness (`FuzzFaultInjectedOperations`, targeting
core/storage/encryption durability under ENOSPC/EIO/short-write/fsync-error/
SQLITE_BUSY/conn-reset faults). The SIEM/notification/evidence-export sinks
were explicitly excluded from that harness's scope (they cannot violate its
atomicity/data-loss/no-plaintext-spill/fail-closed oracles by construction,
since they sit behind the durable DB write and are best-effort by design).
This gap was noticed during that seam-mapping pass and is recorded here for
visibility; per task scope, it is not being fixed as part of that work.
