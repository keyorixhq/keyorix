### Testing
- **`scripts/ci/tz-sweep.sh`** runs time-sensitive Go packages one at a time under non-UTC zones (default Asia/Kolkata and America/Los_Angeles) and lists every failing zone/package pair; a zone Go cannot load is refused (exit 2). Not wired into CI.
