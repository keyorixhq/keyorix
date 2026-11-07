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
6. (Added after the first smoke run and BEFORE any campaign.) When one `CreateUser`
   violates BOTH the username and the email unique index, the engine decides which one it
   reports: SQLite returned `ErrDuplicateEmail`, PostgreSQL `ErrDuplicateUsername`
   (`isDuplicate*Violation` in `local_users.go` match on engine-specific message text).
   Only in that both-violated case the two classes are treated as one. Single-index
   violations stay exact, and the harness now constructs them separately so the
   normalisation cannot mask them. Recorded as observation O-1 in the outcome.

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

### Campaign 1 (2026-11-06 21:30 UTC to 2026-11-07 07:33 UTC, CT 270 on pve01)

- 168 chunks of up to 10 minutes, 2 workers, nice 19, about 2.3 million executions.
- Time actually spent in the fuzz loop, summed over chunks: 9.77 h x 2 workers = **19.55
  worker-hours** (wall time x workers = 20.08; CT cgroup CPU including PostgreSQL = 19.9
  CPU-hours). The campaign stopped on its 20.08 wall-time budget. Measured by fuzz-loop time it is
  0.45 worker-hours short of the 20 the rule asks for, which does not matter here because the
  result is not negative.
- 161 of 168 chunks ended in a `BACKEND DIVERGENCE`; 7 chunks ran clean. Every crasher was
  clustered (not by input), none is unexplained:

| Class | Crashers | Divergence | Minimal repro | Replayed | Classification | Needs |
|---|---|---|---|---|---|---|
| A | 86 | empty secret value: nil on SQLite, `[]byte{}` on PostgreSQL | 2 ops | 3x | backend-inherent (driver NULL / empty-blob mapping); ciphertext is never empty | harness normalisation 7 (done) |
| B | 58 | projects whose names differ only by non-ASCII case (`ÄÖ`/`äö`, `İstanbul`/`istanbul`): SQLite accepts both, PostgreSQL rejects the second; same for rename and by-name lookup | 2 ops | 3x | Keyorix bug (project-name uniqueness differs by backend; #4019 left the index alone) | code fix + migration; gated in the harness; pinned |
| C | 14 | list pagination without `ORDER BY`: PostgreSQL changes row order when the planner's statistics change (index order to heap order), so a page walk duplicates and skips rows | the 14 crashers did **not** replay; mechanism reproduced deterministically in 4 users + 1 `ANALYZE` between pages | 3x (forced) | Keyorix bug (non-deterministic pagination) | code fix (`ORDER BY` with id tiebreak); statistics refreshed before walks in the harness; pinned |
| D | 3 | `ListUsers{Search}` with a non-ASCII case variant: LIKE on SQLite, ILIKE on PostgreSQL | 2 ops | 3x | Keyorix bug, low; named as a follow-up in #4019 | code fix; gated; pinned |

- F-1 (`ListSecrets` search) and F-2/F-3 (`ListUsers` Username/Email filters), found by the
  first smoke runs of this harness, are fixed by #4019. Their seeds pass against that fix and their
  gates and pinned tests were removed.
- Observations, backend-inherent: O-1 (both user unique indexes violated: different sentinel
  reported), O-2 (`ORDER BY name` collation: bytewise vs `en_US.UTF-8`).
- Concurrency: 200 rounds of 7 contended unique-key races on real connection pools produced
  identical error-class multisets and exactly one winner on both backends.

What the rule yields: **not a negative result.** Four distinct divergence classes plus the three
fixed ones. Details of B and C that go beyond what is written here are kept in the private notes.

Caveats, so the numbers are not over-read:
- A chunk ends at its first divergence, and A and B were found within seconds of every chunk
  start. For most of the 168 chunks the fuzzer therefore spent its time re-finding A/B/C/D, not
  exploring past them. The campaign is evidence about those four classes, not a clean bill for
  the rest of the space.
- An unguided 4-minute run early on found none of F-1..F-3; hand-directed probes did. Reachability
  of cross-operation combinations is limited by the program generator.
- The harness now normalises A and gates B, C and D (narrowly, listed in
  `backend_differential_v2_known_test.go`), so a later campaign can look past them. A
  confirmation run with the gates in place is reported below.

### Confirmation run with A/B/C/D handled

After merging #4019 and adding the normalisation/gates, 3 chunks of 10 minutes, 2 workers
(1.02 worker-hours, about 98k executions, 2026-11-07 10:43 to 11:16 UTC) ran **clean**: no
divergence. That is evidence only for those 30 minutes. It does not restart the 20 worker-hour
count; a further full campaign with the gates in place is the next step, and the gates themselves
(A, B, C, D) are removed one by one as the causes are fixed.
