### Testing
- **Process-level crash-recovery fuzzer.** `TestCrashRecoveryFuzz_SQLite` kills `admin encryption rotate`, `rotate-kek`, `backup` and `restore` with SIGKILL at fuzzed points, recovers with the documented commands only, and checks whole-install invariants. Rules and results are in `server/CRASH_RECOVERY_FUZZ.md`; the first campaign did not meet its pre-registered bar (R2).
