### Added
- `keyorix-server admin restore` prints a progress line on stderr (table, rows loaded, elapsed) at each table boundary and every 10 seconds inside a large table, so a restore of millions of rows no longer looks hung. Shown when stderr is a terminal, or with the new `--verbose`; the stdout summary is unchanged.
- `scripts/release-qa/restore_compat_matrix.sh --tags N` adds the newest N release tags to the cross-version restore matrix.

### Changed
- Restore runbook (`docs/operator/restore-failure-modes.md`): recovering from a PostgreSQL restore killed during the load is `admin restore --recover` followed by `admin restore --input ... --overwrite-existing`, with what each step checks.
