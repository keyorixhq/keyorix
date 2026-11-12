# Hostile-server fuzzing of third-party DB client libraries (session h2)

These harnesses attack **third-party client libraries directly**, with no Keyorix
wrapper in the path, so any crash is a bug in the library itself and is
reportable upstream. Each harness stands up a fake server on loopback whose
every post-connect byte (status, framing, length fields) comes from the fuzz
input, and drives the **real** client through its **public API only**.

| Library | Version | Package | Public API driven |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.11.0 | `pgx/` (`pgxfuzz`) | `pgx.ParseConfig` → `pgx.ConnectConfig` → `Conn.Ping` |
| `github.com/go-sql-driver/mysql` | v1.10.1 | `mysql/` (`mysqlfuzz`) | `mysql.NewConnector` → `sql.OpenDB` → `DB.PingContext` / `DB.ExecContext` |

## Why these libraries / where Keyorix uses them

Both drive connections to operator-configured **target** databases for the
dynamic-secrets engine (mint/drop short-lived DB credentials):

- pgx: `internal/dynamic/postgres.go` `dialPostgres` → `pgx.ConnectConfig`.
- mysql: `internal/dynamic/mysql.go` `openMySQL` → `mysql.NewConnector` +
  `sql.OpenDB` + `db.PingContext`.

A malicious / compromised / MITM'd target DB controls every wire byte the client
parses, including the auth handshake — the attack surface these harnesses model.
The admin-DSN password is the **canary** the oracles watch for.

## Oracles (and what each does NOT verify)

- **(a) no panic / no hang / bounded memory.** Panic ⇒ crash. Hangs are bounded
  by a watchdog goroutine (and, for mysql, the driver's own read/write
  timeouts). Memory: the fake server's **declared** body/packet length is capped
  in the decoder (pgx 8 MiB, mysql 1 MiB) to protect the shared host — so the
  loop does NOT exercise each library's true ceiling (pgx ~1 GiB, mysql 16 MiB);
  that amplification is characterised in a dedicated `*_Amplification` test.
  Does NOT catch a slow-but-finishing parse.
- **(b) canary.** The admin password must never appear in a returned error
  string. Does NOT scan the conn/connector value via reflection (it legitimately
  stores the password) nor driver logs (none installed).
- **(c) echo class.** Server-controlled text surfaced in an error is EXPECTED
  echo, not a bug; the fuzz loop fails only on the canary.
- **(d) ignored-read-error.** A server closing mid-body/packet must make the
  client return an error, not a truncated success.
- **(e) LOCAL INFILE guard (mysql only).** A hostile server requesting an
  arbitrary client file must be refused by default, never read off disk.

Each oracle is pinned red/green in a dedicated `oracle_*_test.go` test.

## Running

```
# fast: oracles + seed regression (no fuzzing)
go test ./fuzz/thirdparty/pgx/ ./fuzz/thirdparty/mysql/ -run 'Test|Fuzz.*$' -count=1

# real fuzzing (host-friendly: 2 workers, 2 cores, nice)
nice -n 10 go test ./fuzz/thirdparty/pgx/   -run '^$' -fuzz '^FuzzPgxHostileServer$'   -fuzztime=560s -parallel 2 -cpu 2
nice -n 10 go test ./fuzz/thirdparty/mysql/ -run '^$' -fuzz '^FuzzMySQLHostileServer$' -fuzztime=540s -parallel 2 -cpu 2
```

## Known-library-bug allowlist (mysql)

`FuzzMySQLHostileServer` recovers panics and **swallows only** those whose stack
hits a CONFIRMED, already-minimised go-sql-driver bug site (see
`knownLibPanicSites`); any other panic still fails the run as a novel finding.
This lets the fuzzer explore past the two known DoS panics instead of drowning in
them. The confirmed bugs each have a deterministic reproducer test
(`TestMySQL_*_Reproducer`).

## pgx query path (session n4)

`FuzzPgxHostileQuery` (`pgx/query_pgx_test.go`) completes a fixed valid startup,
then streams fuzz-controlled backend messages while the client runs one of
eight operations (simple / exec-mode / cached-prepared Query, Exec, CopyTo,
CopyFrom, multi-result Exec, typed scans). Oracles: no panic/hang, a TotalAlloc
budget (`allocBudget`), canary never in an error, decoded value or notice.
`clampStream` caps every declared length (framed or raw) at 8 MiB. Its pgx
allowlist (`knownPgxPanicSites`) holds one confirmed site, PGX-1
(`(*baseRows).Values` on a DataRow shorter than its RowDescription, reproducer
`TestPgxValues_ShortDataRow_Reproducer`). Any other panic still fails the run
(`TestPgxQuery_AllowlistStillSurfacesNovelPanics`).

```
nice -n 10 go test ./fuzz/thirdparty/pgx/ -run '^$' -fuzz '^FuzzPgxHostileQuery$' -fuzztime=540s -parallel 2
```

See `/mnt/data/wave4/out/h2-REPORT.md` and `/Users/abeshkov/proj/wave4/out/n4-REPORT.md`
for findings, reproducers and the Keyorix-reachability verdict for each.

## mysql result-set path (session h5)

`FuzzMySQLHostileQuery` (`mysql/query_mysql_test.go`) extends the mysql harness
PAST the handshake. The fake server completes a fixed valid handshake +
`mysql_native_password` auth, then replies to the client's `COM_QUERY` /
`COM_STMT_PREPARE` / `COM_STMT_EXECUTE` with fuzz-controlled response **groups**
(it withholds the next group until the client sends its next command, so
`database/sql` never trips `ErrBusyBuffer`). It drives three public-API ops:
a text query, a binary prepared-statement query (`"… WHERE user = ?"`, the exact
path `internal/dynamic` `killUserConnections` takes on a revoke) and an exec.
Oracles: no panic/hang, a `TotalAlloc` budget, canary never in an error or
decoded value, truncated row must error.

Its allowlist (`knownQueryPanicSites`) holds **seven** confirmed v1.10.1 panic
sites — all one root cause: the result-set parser does no length validation
before slicing server-controlled packets (`readPrepareResultPacket`,
`binaryRows.readRow` NULL bitmap, `handleOkPacket`, `readColumns`,
`readLengthEncodedInteger`, `textRows.readRow`, `handleErrorPacket`). Each has a
deterministic reproducer (`TestMySQLQ{1..7}_*_Reproducer`) and the allowlist is
proven to still surface a novel panic (`TestMySQLQuery_AllowlistStillSurfacesNovelPanics`).
The class is pervasive — a new offset surfaces on most passes — which is itself
the finding; see `/mnt/data/wave4/out/wm-REPORT.md`.

```
nice -n 10 go test ./fuzz/thirdparty/mysql/ -run '^$' -fuzz '^FuzzMySQLHostileQuery$' -fuzztime=540s -parallel 2 -cpu 2
```
