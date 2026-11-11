# Third-party client-library hostile-server fuzzers

These harnesses attack **third-party client libraries directly**, with no Keyorix
wrapper in the path, so any crash is a bug in the library itself and is
reportable upstream. Each harness stands up a fake server on loopback whose
every post-connect byte comes from the fuzz input, and drives the **real** client
through its **public API only**.

## Cloud-SDK libraries (h3)

Covers AWS and Azure cloud-SDK libraries over HTTP/TLS. A fuzzer-controlled
loopback server (`net.Listen 127.0.0.1:0`, TLS for Azure) feeds the real client
arbitrary HTTP status lines, headers, bodies and wire framing. Any finding therefore
localises to the library (or the stdlib `net/http` response reader under it) and is
upstream-reportable, independent of Keyorix's own response handling.

### Packages

- `aws/` — AWS SDK for Go v2: `secretsmanager.GetSecretValue` (AWS JSON 1.1),
  `sts.AssumeRole` (AWS Query/XML), `kms.Decrypt` (AWS JSON 1.1 blob I/O).
  Targets: `FuzzSecretsManager`, `FuzzSTS`, `FuzzKMS`.
- `azure/` — Azure `azsecrets` Key Vault client over azcore's pipeline (retry +
  bearer-token challenge-authentication). Target: `FuzzAzureGetSecret`. Serves TLS
  because azcore refuses to attach a bearer token over plaintext http.

### Oracles (identical four classes in both packages)

- **(a) no-panic / no-hang / bounded alloc** — op under a client timeout + 20s
  watchdog; a panic in the SDK fails the test. Attacker bytes capped at 64KB/response,
  so unbounded-allocation-from-length-field is probed via lying-Content-Length /
  truncated-chunk (client must error), not by measuring RSS.
- **(b) canary leak** — client built with high-entropy secret canaries (AWS secret
  key + session token; Azure bearer token); asserts they never appear in a returned
  error string or `fmt %+v` of the output. Does not inspect the on-wire request
  (signing/bearer legitimately use the secret).
- **(c) echo class** — server body text copied into an error is EXPECTED, logged
  under `echo:`, never a finding.
- **(d) ignored-read-error** — when the final response the client received declared
  more body than it delivered, the client must error, not return truncated success.
  Keyed on the server's record of the last response actually served
  (`fakeServer.lastResponseTruncated`), mirroring `writeResponse` including net/http's
  no-body-status rule (1xx/204/304).

Each fatal oracle is validated red/green in `*_oracle_validation_test.go`, and the
truncation predicate is pinned to `writeResponse`'s wire behaviour in
`TestSpecTruncates_MirrorsWriteResponse`.

## Database drivers (h2)

`pgx/` and `mysql/` attack the two DB client libraries the dynamic-secrets
engine dials against an **operator-configured target** database:

| Library | Version | Package | Public API driven |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.11.0 | `pgx/` (`pgxfuzz`) | `pgx.ParseConfig` → `pgx.ConnectConfig` → `Conn.Ping` |
| `github.com/go-sql-driver/mysql` | v1.10.1 | `mysql/` (`mysqlfuzz`) | `mysql.NewConnector` → `sql.OpenDB` → `DB.PingContext` / `DB.ExecContext` |

### Why these libraries / where Keyorix uses them

Both drive connections to operator-configured **target** databases for the
dynamic-secrets engine (mint/drop short-lived DB credentials):

- pgx: `internal/dynamic/postgres.go` `dialPostgres` → `pgx.ConnectConfig`.
- mysql: `internal/dynamic/mysql.go` `openMySQL` → `mysql.NewConnector` +
  `sql.OpenDB` + `db.PingContext`.

A malicious / compromised / MITM'd target DB controls every wire byte the client
parses, including the auth handshake — the attack surface these harnesses model.
The admin-DSN password is the **canary** the oracles watch for.

### Oracles (and what each does NOT verify)

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
# h3: cloud-SDK targets
env GOCACHE=... GOMODCACHE=... GOFLAGS= GOMAXPROCS=2 \
  go test ./fuzz/thirdparty/aws/   -run '^$' -fuzz '^FuzzSecretsManager$' -fuzztime 600s -parallel 2

# h2: fast — oracles + seed regression (no fuzzing)
go test ./fuzz/thirdparty/pgx/ ./fuzz/thirdparty/mysql/ -run 'Test|Fuzz.*$' -count=1

# h2: real fuzzing (host-friendly: 2 workers, 2 cores, nice)
nice -n 10 go test ./fuzz/thirdparty/pgx/   -run '^$' -fuzz '^FuzzPgxHostileServer$'   -fuzztime=560s -parallel 2 -cpu 2
nice -n 10 go test ./fuzz/thirdparty/mysql/ -run '^$' -fuzz '^FuzzMySQLHostileServer$' -fuzztime=540s -parallel 2 -cpu 2
```

Seed corpora (valid exchanges + known-bad shapes) are added via `f.Add` in
`seed_test.go`; discovered crashers live under `<pkg>/testdata/fuzz/<Target>/`.

## Known-library-bug allowlist (mysql)

`FuzzMySQLHostileServer` recovers panics and **swallows only** those whose stack
hits a CONFIRMED, already-minimised go-sql-driver bug site (see
`knownLibPanicSites`); any other panic still fails the run as a novel finding.
This lets the fuzzer explore past the two known DoS panics instead of drowning in
them. The confirmed bugs each have a deterministic reproducer test
(`TestMySQL_*_Reproducer`). pgx has no allowlist — it produced no crashes.

## Findings

**h3 (cloud SDKs):** See `/mnt/data/wave4/out/h3-REPORT.md`. Summary: **AZURE-1** — a library panic
(index-out-of-range in `keyvault/internal` `challenge_policy.go` `parseTenant`) is
reachable through `azsecrets.GetSecret` from a malformed server `WWW-Authenticate`
header; minimal reproducer in `azure/repro_panic_test.go`. The AWS targets found no
library defects over the runs recorded in the report.

**h2 (DB drivers):** See `/mnt/data/wave4/out/h2-REPORT.md` for findings, reproducers and the
Keyorix-reachability verdict for each.
