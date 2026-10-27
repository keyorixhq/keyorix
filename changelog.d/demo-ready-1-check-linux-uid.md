### Fixed
- **`scripts/demo/check.sh --postgres` now comes up on any Linux host, not only a uid-1001 CI runner.**
  The server refuses secret files owned by another user, and the check's throwaway Postgres stack
  creates them as the host user, so on a normal dev box (uid 1000) the backend exited at startup and
  the check never ran. The files are now handed to root (passwordless `sudo`, else a throwaway
  `docker run --user 0`) on every non-root Linux host.
- **`scripts/demo/check.sh` latency step has a baseline** (`scripts/demo/latency-baseline.txt`), so the
  p50 secret-read time prints next to a recorded number and fails only at 10x it.
