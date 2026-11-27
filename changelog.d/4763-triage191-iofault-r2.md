### Testing

- faultops: pin the TRIAGE-191 (fuzz-corpus#191) verdict with a reproduction that
  drives the real router + auth middleware — a sticky ENOSPC on the cache-hit
  session-liveness read authenticates via the documented read-fallback (a full disk
  still serves reads) and the same op under a sticky EIO is refused by the auth
  middleware itself (503, its fixed message; a control fault past the liveness read
  is refused by a later layer instead, so the assertion discriminates), and the lost
  audit event is the best-effort template-applied append swallowed by the same
  sticky disk. Confirms the live harness's `!stickyDisk` R2 gate is load-bearing (the
  rebuilt #191 seed raises R2 on the pre-gate commit, not on main) and that the
  check reached the #191 shape; no product change.
