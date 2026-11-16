### Testing
- The audit actor-search test now also pins that `actor_type` combines with an actor term (machine and user terms, each kind), on SQLite and PostgreSQL, and the degraded break-glass owed-audit row is asserted to carry the same named-user text (`user N ("<username>") self-granted`) as a normally written one.

### Documentation
- `docs/demo/GOLDEN-PATH.md`: the demo-polish notes for the actor search, the missing key directory message and the `verify-audit` / `restore` wording are brought up to date (`verify-audit` still quotes "pre-#1452" for an old-format row until #4218 lands).
