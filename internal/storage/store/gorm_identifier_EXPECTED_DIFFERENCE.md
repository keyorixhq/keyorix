# GM1 gorm-identifier differential — EXPECTED-DIFFERENCE table

`FuzzGormListSQLShape` (`gorm_identifier_fuzz_test.go`) builds the three
caller-influenced list queries (`ListSecrets`, `ListUsers`, `GetAuditLogs`) on
the SQLite and PostgreSQL dialects in gorm DryRun and compares the emitted
**parameterised** SQL. The two dialects legitimately emit different SQL *text*
for the same query; the oracle therefore compares a **structural skeleton**
(ordered keyword sequence + bind-placeholder count) rather than the raw text, so
these known classes are abstracted away and only a NEW divergence fails.

Each row names a difference the skeleton deliberately does not treat as a
disagreement, and *why it is not an injection or a tenant-isolation risk*.

| # | Class | SQLite form | PostgreSQL form | Why it is benign | How the skeleton abstracts it |
|---|-------|-------------|------------------|------------------|-------------------------------|
| 1 | `placeholder-style` | `?` | `$1`, `$2`, … | Both are bind placeholders; the value never enters the statement text. | `placeholderRe` counts both; the token itself is not compared. |
| 2 | `identifier-quoting` | backtick `` `col` `` | double-quote `"col"` | Pure quoting dialect; the identifier is a trusted constant column, not caller input. | Quote chars are not keywords, so they never appear in the keyword skeleton. |
| 3 | `fold-expression` | `keyorix_fold(col) LIKE ?` | `translate(LOWER(normalize(col, NFC)), 'ς','σ') LIKE translate(LOWER(normalize(? \|\| substr(col,1,0), NFC)), 'ς','σ')` | `foldedContainsClause` builds both from a **trusted constant** column name; the caller term is the single bind var on each side. | Function names are not tracked keywords; both forms have exactly one placeholder. |
| 4 | `in-subquery-vs-any-array` | `user_id IN (SELECT id FROM users WHERE …)` | `user_id = ANY(ARRAY(SELECT id FROM users WHERE …))` | Same set semantics; a performance rewrite pinned by `TestAuditListQueries_UseTheirIndexes_Postgres`. Both nest one `SELECT`. | Both contribute the same `select … where` keyword run; `IN`/`ANY`/`ARRAY` are not tracked. |
| 5 | `glob-vs-like` | `event_type GLOB ?` / `GLOB 'admin_job.*'` | `event_type LIKE ? ESCAPE '\'` / `LIKE 'admin\_job.%'` | Case-sensitive prefix match on both; the term is escaped for its own operator (`escapeGLOB`/`escapeLIKE`) and bound. | `GLOB`/`LIKE`/`ESCAPE` are not tracked keywords; bind count is identical. |
| 6 | `limit-offset-literal` | `LIMIT 25` (integer literal) | `LIMIT $7` (bound) | The value is a clamped integer from `clampPageSize`/`clampPage`, never caller text. | `limitOffsetLiteralRe` folds `LIMIT <int>`/`OFFSET <int>` to a placeholder before counting binds. |
| 7 | `bind-value-transform` | binds `FoldForSearch(escapeLIKE(term))` | binds `escapeLIKE(term)` raw | The two backends fold/escape the term differently on purpose (SQLite folds in Go, PG folds in SQL); the *value* differs but it is always a bound argument. | The oracle compares statement shape, not bind *values*; the INJ check still proves no term byte reaches the text. |

## What a NEW (failing) class looks like

The skeleton fails the differential only on a change that moves structure, e.g.:

- an extra or missing `JOIN` / `WHERE` on one backend (set-affecting),
- a stacked statement (a second top-level `SELECT`/`;`),
- a differing number of bound arguments after row 6 normalisation,
- a keyword run present on one backend and absent on the other.

Any of these is either a real cross-engine divergence or an injection and is
meant to fail. When a genuinely new-but-benign dialect difference appears, add a
row here and extend the corresponding normalisation in `skeletonOf` — never
widen a check to swallow an unexplained divergence.

## Execution-oracle classes (`FuzzGormListTenantIsolation`)

The tenant-isolation oracle *executes* the query and additionally compares the
error CLASS (both nil / both error) between backends. One class is expected:

| # | Class | Behaviour | Why it is benign |
|---|-------|-----------|------------------|
| 8 | `pg-text-encoding-reject` | A payload containing an invalid UTF-8 byte sequence **or an embedded NUL (`0x00`)** makes a UTF8-encoded **PostgreSQL** server reject the bound string (`SQLSTATE 22021`, "invalid byte sequence for encoding UTF8"), while **SQLite** tolerates arbitrary bytes and returns a normal (empty) result. | PostgreSQL **fails closed** — it errors rather than returning rows, so tenant isolation is unaffected; the cross-tenant `assertOnlyProject` check runs unconditionally on both backends and still holds. Found by the GM1 fuzzer at payloads `0xd5` and `0x00`. Reachable from a live caller only via such a byte in a list filter/query param (percent-encoded); the observable effect is a 500 on PG vs 200 on SQLite — a minor robustness inconsistency, **not** a leak. |

The error-class check excludes exactly this class by matching PostgreSQL's own
error (`isPGTextEncodingReject`: the 22021 / "invalid byte sequence" message) —
keyed on PG's error rather than guessed from the payload, since NUL is itself
valid UTF-8. A NEW error-class divergence that is *not* this class still fails.
