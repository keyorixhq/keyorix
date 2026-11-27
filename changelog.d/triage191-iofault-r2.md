### Testing

- faultops: pin the TRIAGE-191 (fuzz-corpus#191) verdict with a reproduction that
  drives the real router + auth middleware — a sticky ENOSPC on the cache-hit
  session-liveness read authenticates via the documented read-fallback (a full disk
  still serves reads) and the same op under a sticky EIO fails closed with 503, and
  the lost audit event is the best-effort template-applied append swallowed by the
  same sticky disk. Confirms the live harness's `!stickyDisk` R2 gate is load-bearing;
  no product change.
