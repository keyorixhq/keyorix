### Documentation
- **Large database: what was tested and what to do before moving one.** `docs/operator/backup-restore-scale.md` states the tested sizes (up to 10,000 secrets with 3 versions and 200,000 audit events, both directions between SQLite and PostgreSQL), the memory behaviour (backup, restore and the move read table by table and insert in batches of 200, so memory does not grow with a table) and a pre-move checklist (#3462).

### Testing
- **Scale tests for the SQLite/PostgreSQL move and restore.** A seeded-instance generator (secrets with versions encrypted under the instance's own key, users, roles, shares, access logs, chained audit log; sizes from `KEYORIX_MIGSCALE_*`) drives in-process tests of `admin backup` + `admin restore` in both directions: equal row counts, `verify-audit` valid, decrypt-all, bounded peak heap at two sizes. The loader's batch size and the refusal of a restore onto a populated SQLite database are pinned by tests (#3462).
