### Testing
- **PostgreSQL leg of the process-death crash fuzzer.** `FuzzProcessCrashRecoveryPG` kills the process (and cuts the connection) at fuzzed points during encryption rotation, backup and restore against real PostgreSQL, recovers with documented commands only and checks whole-install invariants; red-proofs cover the migration schema oracle. Registered in `scripts/fuzzing/targets.conf`.
