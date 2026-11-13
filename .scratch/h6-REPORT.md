# H6 — Deeper hostile-SERVER coverage of Keyorix's third-party DB drivers

> **Report location.** `/mnt/data/wave4/out/` is not writable from this sandboxed
> session (filesystem boundary blocks it even with the sandbox override), so per the
> runtime fallback rule this report lives at `.scratch/h6-REPORT.md`, committed on
> branch `fuzz/thirdparty-h6`.
>
> **Most-reasonable-reading decisions (nobody answers questions here).**
> - "GOMAXPROCS=2" could not be exported via a shell env prefix (the Bash tool's
>   static analyzer rejects `VAR=… go …` forms). Load is instead bounded by
>   `nice -n 10` + `-parallel 2` (≤2 concurrent fuzz workers → ~2 busy cores
>   regardless of GOMAXPROCS). Noted here for honesty.
> - Package temperature sensor (`/sys/.../temp1_input`) is unreadable from the
>   sandbox (blocked path). Thermal safety relies on `nice -n 10` + `-parallel 2`.
> - "internal/store / migrate" connect to **Keyorix's own** Postgres (operator
>   controls both ends); the primary *hostile-remote* surface is dynamic-secrets +
>   rotation against an operator-configured **target** DB, so those are the traced
>   callers below. Store/migrate are noted where a driver call differs.

Status legend for findings: VULNERABILITY / CANDIDATE / SECURITY-DEFECT / HARDENING /
DEFECT / EXPECTED-DIFFERENCE / ARTIFACT.

---

## 0. What is committed and what ran (updated live)

- Working on branch `fuzz/thirdparty-h6`, append-only, DCO sign-off, no AI attribution.
- Existing harnesses (pre-H6): `fuzz/thirdparty/pgx/hostile_pgx_test.go`,
  `fuzz/thirdparty/redis/hostile_redis_test.go` + `moved_redirect_test.go`, shared
  `fuzz/thirdparty/internal/hostile/hostile.go`. `mysql/` was **empty**.
- Confirmed green at start: `go vet ./fuzz/thirdparty/...` clean; redis MOVED
  oracle green (single-node does not follow MOVED) + red proof (ClusterClient dials
  attacker 5×, password leaks).

_(Build/run log is filled in as work lands — see §5.)_

---

## 1. Phase 0 — which driver functions Keyorix calls on the target connection

Versions under test (go.mod): `jackc/pgx/v5 v5.13.0`, `go-sql-driver/mysql v1.10.1`,
`redis/go-redis/v9 v9.23.0`, `go.mongodb.org/mongo-driver/v2 v2.9.2`.

### pgx/v5 — PostgreSQL (dynamic/postgres.go, rotation/postgres.go)
| Driver call | Keyorix caller | Wire surface | Pre-H6 harness | Gap |
|---|---|---|---|---|
| `pgx.ParseConfig*` | `parsePostgresAdminDSN` | — | — | DSN parse (not wire) |
| `pgx.ConnectConfig` | `connectPostgres` | startup+auth (AuthenticationOk/MD5/Cleartext/SASL-SCRAM, ParameterStatus, BackendKeyData, Notice/Error, RFQ) | `FuzzPgxHandshake` | TLS (`SSLRequest`→`S`/`N`) negotiation + ServerHello; GSS |
| `conn.Exec(ctx, sql)` simple | Issue/Revoke/Rotate DDL | simple-query response (RowDescription/DataRow/CommandComplete/Error/Notice; a hostile server may also emit CopyOut/CopyBoth/CopyData) | `FuzzPgxSimpleQueryResponse` | CopyData/CopyBoth message types; NoticeResponse flood (bounded-time/mem) |
| `conn.Exec(ctx, sql, $1,…)` | `pg_terminate_backend … WHERE usename=$1`, `ALTER ROLE … VALID UNTIL` | extended proto (Parse/Bind/Describe/RowDescription/DataRow/CommandComplete/RFQ) | `FuzzPgxExtendedResponse` | — |
| `conn.Query(ctx, sql, args)` | (same extended path) | as above | `FuzzPgxExtendedResponse` | — |
| CopyFrom / LISTEN-NOTIFY / LargeObjects | **none** in dynamic/rotation | — | — | **not reachable** via these callers (stated, not built) |

### go-sql-driver/mysql — (dynamic/mysql.go, rotation/mysql.go)
| Driver call | Keyorix caller | Wire surface | Pre-H6 harness | Gap |
|---|---|---|---|---|
| `sql.OpenDB(connector)` + `db.PingContext` | `openMySQLConfig` | **handshake v10 greeting + auth** (mysql_native_password, caching_sha2 fast/full, auth-switch, cleartext, OK/ERR) + COM_PING | **none** | ALL |
| `db.ExecContext(sql)` no args | CREATE/GRANT/DROP USER, `KILL n` | COM_QUERY response: OK/ERR/result-set, **LOCAL INFILE request (0xFB)**, multi-result (SERVER_MORE_RESULTS) | **none** | ALL |
| `db.QueryContext(sql, ?)` | `SELECT id … processlist WHERE user=?` | **prepared stmt**: COM_STMT_PREPARE_OK + param/col defs + binary result rows | **none** | ALL |
| compression | only if admin DSN sets `compress=true` | compressed packet framing (zlib) | **none** | operator-opt-in; built as gated target |
| TLS | admin DSN `tls=…` | clientSSL upgrade before auth | **none** | noted; caching_sha2-over-TLS path |

Keyorix guard already in path: `dsn.CheckLocalFileOptions` (textual) **and**
`cfg.AllowAllFiles==false` enforced in `openMySQLConfig` → LOCAL INFILE must be refused.

### redis/go-redis/v9 — (dynamic/redis.go, rotation/redis.go)
| Driver call | Keyorix caller | Wire surface | Pre-H6 harness | Gap |
|---|---|---|---|---|
| `redis.NewClient` (single-node ONLY; never Cluster/Failover) | `newRedisClient` | — | — | — |
| `client.Ping` | dynamic connect check | RESP2/3 reply | `FuzzRedisReply` (via Do) | — |
| `client.Do("ACL", …)` | Issue/Revoke/Rotate | RESP2/3 reply, **huge bulk lengths, attributes, push**, `-MOVED/-ASK` redirect | `FuzzRedisReply`, `TestRedisMovedNotFollowed`(+red) | `-ASK` redirect; Sentinel `get-master-addr` → attacker host (egress, red proof) |
| RESP3 nesting depth | — | — | known KFZ-2026-010/080: **no depth limit**; not re-reported, bounded-depth seeds only |

### mongo-driver/v2 — (dynamic/mongodb.go, rotation/mongodb.go)
Covered only if time remains (Phase 1.4). Call shape: `mongo.Connect` → `Ping` →
`RunCommand`(createUser/updateUser/dropUser). Not built unless noted in §5.

---

## 2. Harnesses built in this task
_(filled in §5 as each driver lands; one commit per driver.)_

## 3. Findings
_(none yet; each will carry classification + reachability trace + 3× replay.)_

## 4. Oracles — and what each does NOT verify
_(filled in with the code; every oracle lists its blind spots.)_

## 5. Build / run log
- t0: recon complete, report skeleton written.

## 6. Issue-ready upstream proposals (no production change)
_(filled in at the end; named generically, no unpatched-defect naming in committed files.)_
