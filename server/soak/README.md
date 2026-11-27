# server/soak: resource-growth soak harness (SOAK-1)

Every other harness asserts per-request correctness. None asserts that the server does not slowly **grow**: goroutines, file descriptors, database connections, heap, temp files, rows in bookkeeping tables. A leak of one goroutine per request is invisible to a 15-minute fuzz run and fatal to an air-gapped deployment that runs for months. This package drives the real `server/http` router with a seeded mixed workload and judges the resource series with three oracles.

Test-only (`*_test.go`); no product code. How to run it on pve01 and what to read: [`scripts/fuzzing/soak/README.md`](../../scripts/fuzzing/soak/README.md).

## Modes

| Command | What runs | Time |
|---|---|---|
| `go test ./server/soak` | oracle and sampler unit tests only, no server (CI-safe) | seconds |
| `KEYORIX_SOAK=smoke go test ./server/soak -run 'TestSoak$' -v` | 10000 requests, 2 workers, SQLite, idle drain, oracles | 1 to 2.5 min (load on the host) |
| `scripts/fuzzing/soak/run-soak.sh long [duration] [workers]` | timed load, SQLite or PostgreSQL (`KEYORIX_TEST_PG_DSN`) | 30 min default |
| `server/soak/testdata/redproof/run.sh` | control plus five planted leaks, each must fail the right oracle | about 10 to 15 min |

The real-server run is opt-in on purpose: a hard oracle in the default `go test` of a package that imports `core` and `server/http` would put a timing-sensitive 1 to 2 minute run on every PR. Wiring the smoke into a nightly job is a coordinator decision (see the report's LEFTOVERS).

## Oracles (`oracles_test.go`)

| | Statement | Strength |
|---|---|---|
| (a) slope | growth of each series per 1000 requests over the second half of the run stays under `3 x calibrated max + floor` (`testdata/calibration.tsv`) | **report-only** (WARN) |
| (b) return to baseline | after the load stops and an idle drain, goroutines, descriptors, in-use DB connections and temp files are within a small tolerance of the baseline taken after warm-up | **hard**; polls until a deadline, so a goroutine still exiting does not fail it |
| (c) new stacks | no goroutine stack in the final profile that was absent at baseline, unless on `stackAllowlist` with a reason | **hard** |

Soundness notes. (b) is one-sided (a series below baseline passes). (c) cannot see a leak that already happens during warm-up, because its stack is then in the baseline: that is (b)'s job, and (b)'s failure names the growing stack (`grew: +10456 ...plantGoroutineLeak`). (c) exists for what (b)'s tolerance lets through: a new stack that first appears under load, even a single parked goroutine (`plant_one_goroutine`). An unavailable descriptor series prints an explicit `SKIP:` line and never counts as a pass. A run also fails if a kind of the mix never did its job (no effective request), so a mix that bounced off a 401 cannot be green.

### What the soak does NOT verify

- **Slow leaks** below the slope threshold and below the noise of a short run: a goroutine leaked once per 10,000 requests is invisible to the smoke. Only the (b) check after a long run sees it.
- **Leaks on paths the mix does not reach** (table below).
- **Growth outside the Go runtime's view**: cgo allocations, kernel-side state (socket buffers, page cache), another process, the database server.
- **The production factory's auxiliary DB pools** (named-lock, scheduler-lock, read-audit): the world is `LocalStorage` over one pool, so those connections are covered only through the process-wide fd series.
- **Leaks that finish during warm-up** (about 65 requests): absorbed into the baseline.
- **Response correctness**: the other harnesses do that. The mix only records statuses.
- **Multi-replica behaviour** and anything that needs more than one server process.

## Request mix (`workload_test.go`, table `soakMix`)

Seeded: each worker's request sequence is a pure function of `KEYORIX_SOAK_SEED` and its id (with more than one worker the interleaving across workers is not deterministic).

Covered (kind, weight):

| Kind | Weight | Server behaviour exercised |
|---|---|---|
| `secret_create` | 20 | `POST /api/v1/secrets/`: encrypt, version row, audit event (also deletes when the live set reaches 40) |
| `secret_read` | 25 | `GET /api/v1/secrets/{id}`: authorise, decrypt, last-used bookkeeping, access log |
| `secret_update` | 10 | `PUT /api/v1/secrets/{id}`: new version row |
| `secret_delete` | 8 | `DELETE /api/v1/secrets/{id}`: soft delete |
| `secret_list` | 8 | `GET /api/v1/secrets/?project_id=` |
| `project_churn` | 3 | `POST` then `DELETE /api/v1/projects` |
| `environment_churn` | 3 | `POST` then `DELETE` environment |
| `audit_read` | 5 | `GET /api/v1/audit/logs` |
| `login_logout` | 1 | `/auth/login` then `/auth/logout`: bcrypt, session create and delete |
| `failed_login` | 2 | unknown user: failed-attempt bookkeeping; capped at 8 per 15 min so the per-IP budget (10) never locks the run's own logins |
| `bad_bearer` | 4 | invalid and missing token: 401 path |
| `malformed_request` | 5 | bad JSON, wrong content type, unknown route, wrong method, 3 MiB body |
| `disconnect_cancel` | 4 | client cancels 0 to 3 ms in |
| `disconnect_halfbody` | 3 | raw TCP: headers promise 4096 bytes, 20 arrive, socket closes |
| `client_timeout` | 3 | client gives up after 1 to 3 ms |

**Not covered** (a leak there is invisible to this soak): gRPC (`server/grpc`), SSO/OIDC/SAML flows, SCIM, MFA/WebAuthn, machine identities and machine tokens, dynamic-secret leases (issue/renew/revoke needs a live backend; not cheap, so left out), project invitations and access requests, bulk endpoints (bulk-rotate, bulk-delete, CSV export), the audit export, backup and restore, the scheduler and rotation jobs, notification delivery (email/webhook), break-glass, impersonation, shares, secret ACLs, tags and comments, rate-limit paths other than the failed-login budget, TLS, and server-side request timeouts configured through the router (the harness only times out from the client).

## Series (`sampler_test.go`)

`goroutines` (plus the profile grouped by stack), `heap_inuse` and `heap_objects` after two `runtime.GC`, `fds` (`/proc/self/fd`, or `/dev/fd` on macOS; SKIP line if neither), `db_open/in_use/idle/wait` from `database/sql` DBStats, `temp_files` (a soak-owned `TMPDIR`), and `COUNT(*)` of `sessions`, `rate_limits`, `login_attempts`, `audit_events`, `secret_access_logs`, `notifications`, `password_histories` (a table missing on the backend is skipped). `KEYORIX_SOAK_SERIES=<file>` writes every sample as TSV; `KEYORIX_SOAK_HEAPPROFILE=<dir>` writes `baseline.pb.gz` and `final.pb.gz` for `go tool pprof -sample_index=inuse_space -base baseline.pb.gz final.pb.gz`.

## Calibration (recorded 2026-11-27)

Five control smoke runs (SQLite, seeds 1 to 5, final harness), plus one PostgreSQL smoke (seed 1).

| Series | Result over 5 runs | Used as |
|---|---|---|
| goroutines final minus baseline | +0 in all 5 (baseline 4, final 4) | tolerance +3 |
| fds final minus baseline | +1, +2, +0, +1, +1 (earlier harness build: up to +3) | tolerance +6, plus 3 per extra pooled connection |
| db_in_use final minus baseline | 0 in all 5 | tolerance +0 |
| temp_files final minus baseline | 0 in all 5 | tolerance +0 |
| slope per 1k requests, max of 5 (second half) | db_open 0.181, fds 0.313, goroutines 0.186, heap_inuse 91,487 B, heap_objects 921, audit_events 512.7, secret_access_logs 366.9, login_attempts 0.022, sessions 0, temp_files 0 | `testdata/calibration.tsv`; threshold `3 x max + floor` |

PostgreSQL smoke: baseline goroutines 5, fds 8; final 5 and 9; every hard oracle green; all slopes under the SQLite-calibrated thresholds.

The first-half slope of `heap_inuse` is much steeper (250 to 600 KB per 1k requests, 8.8 MB at baseline to about 12.2 MB after 10,000 requests). A heap diff (`-base`) attributes it to `LocalStorage.GetSecret` / `secretMetadataCache.setNode/setVersion` and the token cache: caches that are bounded (`secretMetaCacheMaxEntries = 10000` per map, 5 min TTL) and still filling after about 5,000 created secrets. That is consistent with cache fill and **is not proven to plateau**: the smoke is too short to reach the cap (about 20,000 requests). The long run decides it (see the pve01 README: read `heap_inuse` over the last half of the series).

`audit_events` and `secret_access_logs` grow with every request: audit is append-only by design with an operator-set retention (ADR-029), so their slopes are calibrated, not asserted.

## Red-proof (`testdata/redproof/`)

Plants are drop-in files, not committed code (`scripts/fuzzing/oracle-health` did not exist on origin/main). `run.sh` copies one in as `zz_plant_test.go`, runs the smoke and checks that the right oracle failed. Results of the final harness, one run each, wall-clock seconds on a shared Mac (the host was busier for these than for the first round, which took 66 to 177 s):

| Plant | Oracle that fired | Evidence | Seconds |
|---|---|---|---|
| control (no plant) | none (green) | all hard oracles PASS | 145 |
| goroutine per request, never exits | (b) goroutines | `baseline=80 final=10536 ... grew: +10456 ...plantGoroutineLeak` | 174 |
| one parked goroutine, request 500 | (c) new stack, while (b) goroutines PASSES | `...plantOneGoroutineLeak new goroutine stack absent at baseline, x1` | 151 |
| unclosed `sql.Rows`, requests 501 to 504 | (b) db_in_use | `baseline=0 final=4 (open=6 idle=2)` | 170 |
| temp file never removed, per request | (b) temp_files | `baseline=75 final=10530 files: soak-plant-...` | 191 |
| fd retained open, every 20th request | (b) fds | `baseline=14 final=540 tolerance=+6` | 98 |

Lesson from the first round: two plants (`one_goroutine` at request 50, `rows` on the first four requests) fired during warm-up, landed in the baseline and were, correctly, invisible. Plants that model "growth under load" must fire after request 500; the goroutine, tempfile and fd plants leak per request and are caught regardless.
