### Testing
- **One-command RC gate: `scripts/release/rc-gate.sh <candidate-tag> [<previous-tag>]`.** Downloads the candidate's and the previous release's binaries, runs `verify-release.sh` on the candidate, hashes the previous binaries, then runs `scripts/drills/upgrade.sh` (downgrade probe and restore-as-rollback included) and `scripts/drills/backup-restore.sh` on SQLite and PostgreSQL with the previous release as the old server. It prints one PASS/FAIL/SKIP line per leg (a SKIP names its reason), writes `rc-gate-result.tsv` and exits non-zero on any FAIL; `--check-result` re-checks a result file. `scripts/release/rc-gate-selftest.sh` calibrates the exit code red and green without a network.

### Documentation
- **RC gate section in `docs/operator/upgrade-rollback.md` and a hard step in `RELEASING.md`:** what each leg proves, what it does not (container and Kubernetes legs are pending the e2e VM), and the rule that a final tag needs a green gate result of its last release candidate.
