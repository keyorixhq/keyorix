# Architecture growth baseline

Measured 2026-10-27 on `origin/main` at `bf93a951c` (PR #3771), with
`scripts/ci/growth_measure.py`. This is the data the growth ceilings in
`scripts/ci/check-growth-guards.sh` were calibrated against; the ceilings were
chosen after this table existed, not before.

## Method

Scope: every package of the root Go module under `internal/` and `server/`
(108 packages, including `server`, the `package main` of `server/main.go`).
`cli/` and `operator/` are separate Go modules and are not measured.

| Column | How it is computed |
|---|---|
| files | non-test `.go` files in the package (`GoFiles` + `CgoFiles` of `go list -json ./...`) |
| LOC | physical lines in those files (generated files included) |
| dependents | packages of the root module that transitively import the package: for every package P, every module package in P's `Deps` (`go list -deps` of P) gets P as a dependent. Test-only imports are not followed, `go list` default |

Regenerate: `python3 scripts/ci/growth_measure.py --table files` (or `loc`,
`dependents`). Check against the ceilings: `make check-growth`.

## Which signal: files, not LOC

LOC is the weaker signal here because it counts generated code, which is not a
sign of design growth. `server/proto/pb` is 2 files and 17,361 lines (rank 2 by
LOC), `internal/faultstorage` is 3 files and 8,163 lines (rank 5): both are
generator output and would eat the headroom of a LOC ceiling or force a
generated-file exclusion list that itself decays. The file count does not move
when a generator runs, and it does rise when each new feature adds one more
file to a package that already has 100+. Both metrics agree on the same three
worst offenders (`internal/core`, `server/http/handlers`,
`internal/storage/store`), so nothing is lost by choosing files.

Dependents is the second ceiling because a package that many packages depend on
turns each change into a rebuild and retest of a large part of the tree and
into a review that has to consider every dependent.

## Findings

- Worst by files: `internal/core` 226 (68,522 LOC), then `server/http/handlers`
  130, `internal/storage/store` 96, `server` (main) 63, `internal/core/storage/storagetest`
  51, `internal/config` 50. Everything else is 47 files or fewer; 71 of 108
  packages have 3 files or fewer.
- Worst by dependents: `internal/core/ports` 38, `internal/secretenv` 37,
  `internal/securefiles` 34, `internal/envflag` 29, `internal/connect/connecttypes`
  28, `internal/storage/models` 28. These are small, deliberately central leaf
  packages (1 to 8 files). A high dependents count there is by design; the
  ceiling exists to stop the next one from becoming a hub by accident.
- Both big and central: `internal/config` (50 files, 26 dependents) and
  `internal/core/storage` (47 files, 21 dependents) are the only packages with
  both 40+ files and 20+ dependents. These are where a split pays the most.

## Full table (sorted by files, descending)

| package | files | LOC | dependents |
|---|---:|---:|---:|
| `internal/core` | 226 | 68522 | 14 |
| `server/http/handlers` | 130 | 22395 | 1 |
| `internal/storage/store` | 96 | 21458 | 8 |
| `server` | 63 | 5628 | 0 |
| `internal/core/storage/storagetest` | 51 | 4679 | 0 |
| `internal/config` | 50 | 7157 | 26 |
| `internal/core/storage` | 47 | 4429 | 21 |
| `internal/storage` | 36 | 6025 | 4 |
| `server/admin` | 32 | 8535 | 0 |
| `internal/encryption` | 28 | 5753 | 2 |
| `server/middleware` | 22 | 4461 | 4 |
| `server/grpc/services` | 17 | 4974 | 1 |
| `internal/auditverify` | 13 | 1918 | 4 |
| `internal/core/rules` | 12 | 938 | 23 |
| `internal/crypto` | 12 | 1709 | 6 |
| `internal/backupfmt` | 10 | 1879 | 1 |
| `internal/connect` | 10 | 1359 | 0 |
| `internal/dynamic` | 10 | 2016 | 2 |
| `internal/rotation` | 10 | 1389 | 0 |
| `server/grpc/interceptors` | 9 | 1239 | 2 |
| `internal/storage/models` | 8 | 2944 | 28 |
| `internal/encryptionops` | 7 | 2534 | 1 |
| `internal/k8ssync` | 7 | 2220 | 1 |
| `internal/notifychan` | 7 | 927 | 0 |
| `internal/storage/sqlitedialect` | 6 | 1254 | 8 |
| `server/http/handlers/contracttest` | 6 | 1054 | 0 |
| `server/http/handlers/httpx` | 6 | 526 | 3 |
| `internal/core/ports` | 5 | 685 | 38 |
| `internal/cryptoinventory` | 5 | 809 | 2 |
| `internal/solewriter` | 5 | 2085 | 3 |
| `internal/evidencesink` | 4 | 595 | 0 |
| `internal/keyfiles` | 4 | 1269 | 6 |
| `internal/logging` | 4 | 542 | 19 |
| `internal/oidcverify` | 4 | 592 | 15 |
| `internal/testutil/pgdsn` | 4 | 647 | 1 |
| `server/http` | 4 | 1699 | 0 |
| `server/http/handlers/reports` | 4 | 326 | 1 |
| `internal/audit/siem` | 3 | 801 | 0 |
| `internal/faultstorage` | 3 | 8163 | 0 |
| `internal/mcp` | 3 | 672 | 1 |
| `internal/netutil` | 3 | 631 | 22 |
| `internal/notary` | 3 | 480 | 5 |
| `internal/statemap` | 3 | 1161 | 1 |
| `internal/anomaly` | 2 | 426 | 15 |
| `internal/auditverify/anchorbundle` | 2 | 63 | 5 |
| `internal/besteffortguard` | 2 | 1105 | 0 |
| `internal/core/certparse` | 2 | 106 | 15 |
| `internal/core/dsn` | 2 | 487 | 15 |
| `internal/delivery` | 2 | 386 | 27 |
| `internal/encryption/aead` | 2 | 438 | 3 |
| `internal/fuzzutil` | 2 | 107 | 0 |
| `internal/guardrules` | 2 | 254 | 0 |
| `internal/hardening` | 2 | 84 | 0 |
| `internal/pqwrap` | 2 | 1107 | 0 |
| `internal/rotation/quote` | 2 | 138 | 1 |
| `internal/saml` | 2 | 571 | 0 |
| `internal/secretenv` | 2 | 473 | 37 |
| `internal/serverguard` | 2 | 914 | 1 |
| `internal/startup` | 2 | 626 | 2 |
| `internal/testutil/srcpath` | 2 | 308 | 4 |
| `internal/tlsmetrics` | 2 | 134 | 1 |
| `server/proto/pb` | 2 | 17361 | 3 |
| `internal/besteffort` | 1 | 111 | 15 |
| `internal/bundle` | 1 | 37 | 0 |
| `internal/clockcheck` | 1 | 74 | 1 |
| `internal/connect/connecttypes` | 1 | 24 | 28 |
| `internal/core/coretests` | 1 | 10 | 0 |
| `internal/core/guards` | 1 | 21 | 0 |
| `internal/crypto/awskms` | 1 | 174 | 3 |
| `internal/crypto/azurekms` | 1 | 308 | 3 |
| `internal/crypto/gcpkms` | 1 | 246 | 3 |
| `internal/csvsafe` | 1 | 38 | 15 |
| `internal/di` | 1 | 23 | 0 |
| `internal/dynamic/dynamictest` | 1 | 110 | 0 |
| `internal/envflag` | 1 | 35 | 29 |
| `internal/faultstorage/gen` | 1 | 518 | 0 |
| `internal/i18n` | 1 | 229 | 20 |
| `internal/identity` | 1 | 111 | 22 |
| `internal/libconformance` | 1 | 11 | 0 |
| `internal/license` | 1 | 33 | 2 |
| `internal/protectedmetrics` | 1 | 21 | 21 |
| `internal/ratelimitmetrics` | 1 | 41 | 8 |
| `internal/recoverykey` | 1 | 156 | 1 |
| `internal/restorejournal` | 1 | 262 | 2 |
| `internal/saml/samltest` | 1 | 187 | 0 |
| `internal/secrettemplate` | 1 | 277 | 16 |
| `internal/secrettemplate/yamlescape` | 1 | 45 | 0 |
| `internal/securefiles` | 1 | 604 | 34 |
| `internal/solewriter/swstate` | 1 | 47 | 12 |
| `internal/testhelper` | 1 | 441 | 0 |
| `internal/testutil/fuzzworld` | 1 | 174 | 0 |
| `internal/testutil/pgwirecount` | 1 | 244 | 0 |
| `internal/testutil/sqlitetest` | 1 | 127 | 0 |
| `internal/tlsreload` | 1 | 96 | 1 |
| `internal/utils/safeconv` | 1 | 30 | 5 |
| `internal/version` | 1 | 36 | 3 |
| `internal/webauthnrp` | 1 | 258 | 0 |
| `server/grpc` | 1 | 329 | 0 |
| `server/http/handlers/webauthnparse` | 1 | 24 | 0 |
| `server/tools` | 1 | 332 | 0 |
| `server/validation` | 1 | 543 | 2 |
| `server/webui` | 1 | 41 | 1 |
| `internal/docsdrift` | 0 | 0 | 0 |
| `internal/metricsdoc` | 0 | 0 | 0 |
| `internal/refusaldocs` | 0 | 0 | 0 |
| `internal/threatmodelcheck` | 0 | 0 | 0 |
| `server/faultops` | 0 | 0 | 0 |
| `server/httpguards` | 0 | 0 | 0 |
