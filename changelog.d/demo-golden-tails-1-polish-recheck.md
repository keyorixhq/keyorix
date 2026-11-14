### Testing
- The audit actor-search test now also pins that `actor_type` combines with an actor term (machine and user terms, each kind), on SQLite and PostgreSQL, and the degraded break-glass owed-audit row is asserted to carry the same named-user text (`user 2 ("dana")`) as a normally written one.

### Documentation
- `docs/demo/GOLDEN-PATH.md`: the demo-polish notes for the actor search, the missing key directory message and the `verify-audit` / `restore` wording are brought up to date (the old-hash-format reason is described in plain words, no "pre-#1452").
