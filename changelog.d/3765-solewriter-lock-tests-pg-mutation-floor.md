### Fixed
- **`scripts/mutation-testing/run-mutation.sh` measures packages again.** Since #3733 the comment lines inside the double-quoted `PACKAGES` string quoted code in backticks, which bash ran as command substitutions, so under `set -euo pipefail` the script exited 127 before measuring any package. `PACKAGES` is now a quoted heredoc. Guard: `scripts/mutation-testing/run_mutation_packages_test.py`.

### Testing
- **The solewriter own-table lock test runs on a non-superuser PostgreSQL and covers every covered table.** `TestPoll_OwnTableLockKeepsTheHolderLock` grants its test role to the current user (it failed on a NOSUPERUSER CREATEROLE role before taking any lock), holds the lock until the test releases it, and loops over every fenced and own table: where the lock blocks the poll (the own tables and the fenced tables with a `WHEN` trigger) the lease must lapse and stay lapsed, elsewhere a poll must succeed, and on every table a write under the lock is refused. `TestCheckOff` also runs with `storage.type: postgresql`, killing the fence.go negation mutants for that spelling.

### Internal
- **Optional fifth field in the mutation `PACKAGES` list: the efficacy floor when `KEYORIX_TEST_PG_DSN` is set.** The PostgreSQL-only tests then cover mutants a run without a DSN reports as not covered. `internal/serverguard` gets its measured Postgres floor; the `internal/solewriter` one follows.
