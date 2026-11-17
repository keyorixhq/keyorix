### Testing
- **SQLite to PostgreSQL check asserts the audit head.** `scripts/migrate/sqlite-to-pg-check.sh` now also proves that the head row of the audit chain keeps its id and entry hash through `admin backup` / `admin restore`, and that the first event written on PostgreSQL chains onto it. Run under a non-UTC host time zone (`TZ=Pacific/Auckland`).

### Documentation
- **Growing from SQLite to PostgreSQL: what is and is not verified.** `docs/SELF_HOSTING.md` ("Moving from SQLite to Postgres") states the audit-chain and time-zone results and lists the unverified parts (containers, non-empty targets, very large databases, other key providers, live or multi-replica moves).
