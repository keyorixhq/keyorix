# SQLite-vs-PostgreSQL storage differential (v2)

Status: PRE-REGISTRATION. This section was committed before the first campaign ran;
the outcome section at the bottom is appended afterwards and the rule above it is not
edited.

## What exists already

`FuzzStorageBackendDifferential` (`internal/storage/store/backend_differential_fuzz_test.go`,
PRs #1899, #1901, #2127, #3956) runs 16 create/get/assign ops on both backends and
compares a boolean error class plus natural-key sets. It uses a 5-name ASCII alphabet,
no updates, no list filters, no pagination, no value payloads and no concurrency, and an
error "class" of nil/non-nil. V2 targets exactly those gaps. The PostgreSQL backend is
complete (it is the production enterprise backend); nothing here invents backend code.

## What v2 adds

| Gap in v1 | v2 |
|---|---|
| error class = nil/non-nil | class = which storage sentinel (`ErrDuplicateUsername`, `ErrDuplicateProjectName`, `ErrDuplicateSecretVersion`, `ErrSecretValueTooLarge`, `gorm.ErrRecordNotFound`, ...) or `other` |
| 5 ASCII names | pool of ~25 edge strings (case pairs, Turkish dotted I, sharp s, combining marks, CJK, emoji, `%`, `_`, `\`, 255/300-char, whitespace variants, `NULL`) plus two fuzzer-supplied strings |
| no updates | `UpdateSecretFields` (name, description, classification, expiry set/clear, max reads set/clear, parent), `UpdateProjectFields`, `UpdateGroupFields` |
| no delete/recreate of users | `DeleteUser` then recreate (partial unique index) |
| no list/filter/paging | `ListSecrets` (search, type, classification, deleted-only, include-deleted, expiry, folder, paging), `ListUsers` (search, active, include-deleted, paging), `ListGroupsPage` |
| no value payloads | `CreateSecretVersion` with nil/empty/1 B/4 KiB/64 KiB/1 MiB/1 MiB+1 values, duplicate version numbers; `GetLatestSecretVersion`, `GetSecretVersions` compared byte-for-byte |
| no project lifecycle | `DeleteProject` / `RestoreProject` cascade counts |
| no concurrency | `TestBackendDifferentialConcurrentUnique`: N goroutines race one unique key on each backend; the multiset of error classes must match |
| ordering never compared | `TestBackendDifferentialOrdering`: seeded fixed data, every `ORDER BY` list compared as an ordered list; one subtest per list function so each is classifiable |

## Normalisations (declared up front; anything else is a candidate)

1. Row ids, `created_at`/`updated_at`/`deleted_at` values: ignored (presence of
   `deleted_at` is compared). Times that the harness itself supplies are whole seconds in
   UTC and are compared.
2. Result sets of queries with no ORDER BY, and the CONTENT of a page of such a query:
   compared as a set over a full page walk, not page by page. Page LENGTH and the
   `total` are compared exactly. Within one backend, the union of a full page walk must
   equal the unpaged set with no duplicates (a within-backend invariant).
3. Strings with a NUL byte or invalid UTF-8 are not generated (PostgreSQL rejects them at
   the driver; the API layer is expected to). Counted, not silently dropped.
4. `ORDER BY <text>` lists are compared in the dedicated ordering test, where a
   collation-only difference (SQLite BINARY vs PostgreSQL `en_US.UTF-8`) is pre-classed
   "backend-inherent / ordering contract" and reported as one item, not per-case.
5. Error text is not compared; error class is.

## Success rule (fixed before running)

- A **divergence** is any `t.Fatalf` whose message starts `BACKEND DIVERGENCE` in the v2
  fuzz target, or a failure of the concurrency/ordering tests, that is not covered by a
  declared normalisation above.
- A divergence becomes a **finding** only after all of: (a) minimised (Go's fuzz
  minimiser, then by hand to the shortest op list); (b) replayed deterministically 3
  times from the minimised input on a fresh schema, same result each time; (c) classified
  as exactly one of **Keyorix bug**, **backend-inherent**, **harness bug** with a
  stated reason. Unreplayable divergences are reported as such and not as findings.
- **Negative result**: 20 CPU-hours of fuzz worker time on the v2 target with zero
  unexplained divergences. If fewer than 20 CPU-hours were run, the report says how many
  and does NOT call the result negative; it says "no divergence in N CPU-hours".
- Campaign limits: runs inside CT 270 (2 cores) on pve01, hard wall stop before
  Tue 2026-11-10 00:00 UTC (CT 100's mutation run is 05:00 UTC). Fuzz workers = 2.
- Divergences that look security-relevant (authorization state, uniqueness of
  credentials, secret value corruption) are written to the private findings file only.

## Reproducing

```
# on the Proxmox host
CTID=270 scripts/fuzzing/pg-differential-ct.sh
# inside the CT
export PATH=$PATH:/usr/local/go/bin
export KEYORIX_TEST_PG_DSN='postgres://difffuzz:difffuzz@127.0.0.1:5432/difffuzz?sslmode=disable'
go test ./internal/storage/store -run 'TestBackendDifferential' -count=1
go test ./internal/storage/store -run '^$' -fuzz '^FuzzStorageBackendDifferentialV2$' -fuzztime 30m -parallel 2
```

## Outcome

(appended after the campaign)
