# ADR-100: Remove mlockall; move swap protection to deployment-level control

## Status

**Accepted (2026-09-04).** Supersedes the `mlockall` half of
[ADR-098](adr-098-process-memory-hardening.md) — that ADR's core dump
suppression (`RLIMIT_CORE=0`) is unaffected and remains in effect exactly as
originally documented; only the memory-locking mechanism is removed. See
ADR-098 for the historical record of why `mlockall` was originally adopted
and how it was verified at the time.

## Summary

`internal/hardening.ApplyMemoryHardening` no longer calls
`mlockall(MCL_CURRENT | MCL_FUTURE)`. `config.MlockConfig`
(`security.mlock.disabled` / `security.mlock.require_success`) is removed
entirely — there is no config flag or opt-in for the removed control. Core
dump suppression is untouched: it has no operator prerequisite, no failure
mode worth gating behind config, and no relationship to the problem below.

Swap protection for decrypted secret memory is now a **deployment-level**
concern: disable swap on the node, or in the container runtime, rather than
locking memory pages in-process. This is not left as operator best-effort
guidance alone: `deploy/helm/keyorix/values.yaml`'s default `server.resources`
now sets `requests == limits` for both `cpu` and `memory`, which places the
server pod in Kubernetes' **Guaranteed** QoS class. Under `NodeSwap`
(Kubernetes' opt-in swap-on-Linux-nodes feature), the `LimitedSwap` behavior
grants swap access **only to Burstable-QoS pods**
([KEP-2400](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/2400-node-swap/README.md):
"Swap access is granted only for pods of Burstable QoS") — a Guaranteed pod
receives zero swap unconditionally, on a cluster that has opted into
`NodeSwap` or not. This closes a real gap in this ADR's first version, which
documented "disable swap on the node" as operator guidance without the
shipped chart's own default actually landing in the QoS class that
guarantee depends on (the previous default, `requests.memory: 128Mi` against
`limits.memory: 512Mi`, is Burstable — precisely the class `NodeSwap` permits
to swap).

## Why mlockall does not work here

Three independent findings, each sufficient on its own:

1. **Measured, not estimated: the real server binary pins `VmLck` ≈ 1.33 GiB
   at rest**, on a healthy process that has served nothing beyond a
   readiness probe — already **~2.6×** the shipped Helm chart's default
   512Mi memory *limit* (`deploy/helm/keyorix/values.yaml`), before a single
   API request. `VmLck` grows further under ordinary request load (secret
   creation) and does not shrink afterward, even after an idle period long
   enough for garbage collection to run and `debug.FreeOSMemory()` to
   execute — `mlockall`'s locked pages cannot be reclaimed by
   `madvise(MADV_DONTNEED/MADV_FREE)`, the mechanism the Go runtime's
   scavenger uses to return freed memory to the OS. The shipped chart's own
   `securityContext.capabilities.drop: ["ALL"]` (with no `add:` list, and no
   `values.yaml` knob to add one back) means the *only* thing standing
   between "mlockall silently degrades to a no-op-equivalent warning" and
   "mlockall succeeds and pins an ever-growing, non-shrinking floor toward
   an OOM-kill" is the container runtime's default `RLIMIT_MEMLOCK` — a
   value this chart does not control, does not document, and cannot rely on
   being small enough to fail safely.
2. **This is not a tuning problem — `mlockall` cannot deliver the intended
   protection in a garbage-collected runtime.** The Go garbage collector
   moves and copies memory during normal operation; locking a specific
   buffer's virtual address protects that address, not the copies the
   runtime scatters elsewhere as it compacts and reallocates. This is a
   structural mismatch between the mechanism and the language runtime it
   was applied in, not a configuration or scoping choice — scoping the lock
   to a smaller set of addresses narrows the pinned footprint but does not
   fix this mismatch, so it is not implemented here as a middle ground.
3. **The field has moved away from process-wide mlock.** OpenBao (the
   post-fork continuation of the exact tool this repo's original design
   modeled itself on) removed `mlock` entirely
   ([openbao/openbao#363](https://github.com/openbao/openbao/issues/363);
   design rationale: [RFC](https://openbao.org/community/rfcs/mlock-removal/)).
   HashiCorp's own Vault Helm chart dropped `IPC_LOCK` from its default
   deployment in 2020
   ([hashicorp/vault-helm#198](https://github.com/hashicorp/vault-helm/pull/198)).
   HashiCorp's production-hardening guidance treats disabling swap at the
   host level as the baseline, and in-process `mlock` as an additional
   trade-off on top of that baseline, not a replacement for it. Kubernetes
   nodes run with swap disabled by default; `NodeSwap` (opt-in swap support)
   only reached GA recently. The premise this repo's chart already runs on
   swapless nodes in the common case — this ADR makes that premise the
   documented, primary control instead of a redundant in-process backstop
   that actively works against the memory limit on the deployments that
   don't.

## What changes

- `internal/hardening.ApplyMemoryHardening` takes no arguments and only
  disables core dumps. The `mlockallFn` syscall indirection, `MCL_CURRENT`/
  `MCL_FUTURE`, and every log line specific to the mlockall attempt are
  removed.
- `config.MlockConfig` and `SecurityConfig.Mlock` are removed. There is
  deliberately no replacement flag: a knob for a control that does not work
  as intended is worse than the control's absence, because it invites an
  operator to believe they have a working guarantee by setting it.
- `server/main.go`'s call site no longer reads `cfg.Security.Mlock.*`.
- `deploy/helm/keyorix/values.yaml`'s `server.resources` default changes from
  `requests: {cpu: 100m, memory: 128Mi}` / `limits: {cpu: 1, memory: 512Mi}`
  (Burstable) to `requests == limits == {cpu: 1, memory: 512Mi}` (Guaranteed).
  `memory` is unchanged from before this ADR — see "Verification" below for
  why 512Mi is still the right number, now re-derived from measurement rather
  than inherited. `cpu`'s *request* is raised to match the pre-existing
  *limit* — see "Verification" for the trade-off this costs. `web` (the
  bundled nginx reverse proxy + static UI) and the bundled `postgresql` are
  deliberately left Burstable/unchanged: neither ever held decrypted secret
  material in its own process memory (`mlockall` was only ever called from
  `server/main.go`; Postgres stores and serves ciphertext only, encryption
  happens in the Go server before a write and after a read), so neither was
  ever in this control's scope.

## What does not change

- **Core dump suppression (`RLIMIT_CORE = {0, 0}`) is unaffected**, still
  unconditional, still called from the same place, still logs its own line.
  Everything ADR-098 says about it — no operator prerequisite, `Max` lowered
  alongside `Cur`, verified by triggering a real crash — remains accurate.
- The transient in-process exposure of decrypted secret values (the "three
  unwiped heap copies" gap documented alongside ADR-098 and in
  `docs/security-review-2026-09.md`) was never something `mlockall`
  protected against, and remains exactly as it was: unchanged, out of scope
  here, tracked separately.

## Operator guidance: deployment-level swap control

Swap protection for a Keyorix server deployment is now provided by the
environment, not the process — and, for the shipped Helm chart, by the
chart's own default resource shape, not by operator diligence alone:

- **Kubernetes, using this chart's defaults:** the server pod's Guaranteed
  QoS class (see "What changes" above) means it receives zero swap under
  `NodeSwap`'s `LimitedSwap` behavior regardless of whether the cluster or
  node has opted into swap — no additional operator action is required
  beyond leaving `server.resources.requests == server.resources.limits`
  intact if `server.resources` is overridden. Overriding `server.resources`
  to break that equality silently reopens this gap; there is no code-level
  guard against a values.yaml override doing this (a `helm template` /
  `helm lint` custom check could catch it, but is not implemented here).
- **Kubernetes, nodes without `NodeSwap` at all:** the common case today —
  nodes run with swap disabled by default, so this is already true
  regardless of pod QoS class.
- **systemd / bare metal / VM:** disable swap at the host level (`swapoff
  -a` and remove the relevant `swap` entry from `/etc/fstab`, or set
  `vm.swappiness=0` combined with no swap device at all for a stronger
  guarantee than a swappiness tunable alone).
- This guidance is recorded in `deploy/helm/keyorix/README.md`'s Production
  notes and `docs/SECURITY.md`'s deployment security checklist.

## Alternatives considered

- **Scope the lock to secret-bearing buffers only, instead of the whole
  process.** Rejected — see point 2 above: this does not fix the underlying
  GC-copies-memory mismatch, it only shrinks the pinned footprint while
  leaving the same structural gap in place (any address the GC copies a
  locked buffer's contents to is unlocked). It was also independently
  assessed as a large refactor on its own merits — the bounded key material
  (~128 bytes: DEK, DEK snapshot, evidence-signing key, audit-checkpoint
  key) is trivial to scope-lock, but decrypted secret VALUES are smeared
  across at least three unwiped heap copies by construction of
  `encoding/json` and Go's immutable strings, per
  `docs/security-review-2026-09.md`'s own prior finding — scoping the lock
  to that traffic would mean threading `[]byte`-only plaintext through the
  entire read path and abandoning string-based serialization for secret
  fields, a change with a far larger blast radius than this ADR's scope.
- **Add a soft memory ceiling (`GOMEMLIMIT` / `debug.SetMemoryLimit`) below
  the cgroup limit, keep `mlockall`.** Rejected as the primary fix — it
  would only bound how large the *unreclaimable* pinned floor can grow, not
  prevent the floor from being unreclaimable in the first place; the
  process would still hit degraded GC behavior (more frequent, less
  effective collection cycles as it fights to stay under the soft limit
  while `mlockall`'s prior high-water mark can never shrink). Nothing here
  precludes adding `GOMEMLIMIT` as an independent, unrelated improvement to
  general memory behavior in the future — it just isn't a substitute for
  removing `mlockall`.
- **Just raise the default Helm chart memory limit above the pinned-RSS
  floor.** Rejected as the fix, though operators who override the default
  today are free to size their own limits however they like: it papers over
  the mismatch for the shipped default only, does nothing for the
  underlying "grows forever, never shrinks" behavior, and every future MB
  of legitimate peak load (larger secret exports, wider audit queries)
  permanently ratchets the floor higher regardless of what the limit is set
  to.

## Verification

**Follow-up pass (2026-09-04, superseded again same day): observed values,
real binary, real Linux container.** The original version of this ADR
asserted the measurements above from a companion evidence document rather
than from commands run in this ADR's own verification pass. A first
follow-up (below, now itself superseded) closed that gap but used a single
narrow scenario (50 secrets, one client) to size a Guaranteed-QoS
reservation — insufficient, because `requests == limits` means the chosen
number is capacity every install permanently withholds from its node. This
section replaces that narrow measurement with a fuller matrix: secret count
and client concurrency varied independently, the bundled deployment-wide CSV
export and audit-log export surfaces exercised at the largest count tier,
one memory-capped run to directly test for an OOM-kill at the limit
`values.yaml` set, and one 30-minute sustained-load pass. All commands run
directly against `server/Dockerfile`'s image, `linux/arm64` via this
environment's Docker backend (OrbStack — not the `linux/amd64` architecture
the shipped `ghcr.io/keyorixhq/keyorix-server` image and most production
Kubernetes nodes run; not independently re-measured on `amd64` from this
pass). Method: `docker exec <container> cat /proc/6/status` (PID 6 is the
real server process; PID 1 is `entrypoint.sh`), reading `VmRSS`/`VmHWM`
(peak-ever resident set for the process's lifetime so far);
`docker inspect -f '{{.State.OOMKilled}}'` for the OOM check; load generated
via real HTTP calls (`/auth/login` then `POST /api/v1/secrets`,
`GET /api/v1/secrets`, `GET /api/v1/secrets/{id}` — not synthetic in-process
allocation) using a small Python `ThreadPoolExecutor`-based driver
(`.scratch/measure.py`, `.scratch/sustained.py`, not committed — throwaway
per this repo's `.scratch/` convention, reproducible from the commands
described here).

- **`VmLck` is 0 at rest, confirming mlockall is genuinely gone** — the
  literal line from `/proc/<pid>/status` inside the running container, no
  special capability granted:
  ```
  VmLck:	       0 kB
  ```
- **Secret-count axis, concurrency held at 1** (sequential, one client),
  cumulative on one running instance — 50 secrets at ~500KB (matching the
  original narrow test, kept for continuity), then 950 more at a realistic
  ~200B (typical API-key/password size) to reach 1,000, then 9,000 more at
  ~200B to reach 10,000:
  | Point | `VmRSS` | `VmHWM` (peak) |
  |---|---|---|
  | At rest | 23148 kB | 51192 kB |
  | 50 secrets (50×~500KB) | 59084 kB | 61096 kB |
  | 1,000 secrets (+950×~200B) | 44904 kB | 61096 kB (unchanged) |
  | 10,000 secrets (+9,000×~200B) | 48040 kB | 61096 kB (unchanged) |

  **Row count alone, at realistic per-secret size, does not drive memory.**
  Growing the store 200x (50 → 10,000 rows) via small sequential writes
  never raised the peak past what the original 50×500KB burst had already
  set — each request's working set is independent and reclaimed before the
  next.
- **Bulk endpoints at the 10,000-row tier** (the scenario this matrix was
  specifically designed to exercise — a large count meeting a bulk read):
  | Endpoint | Response size | `VmRSS` after | `VmHWM` (peak) |
  |---|---|---|---|
  | `GET /api/v1/secrets?...&page_size=100` (paginated list) | 85029 B | 69236 kB | 69236 kB |
  | `GET /api/v1/secrets/inventory.csv` (deployment-wide, **unbounded** — no `LIMIT`) | 746706 B (10,050 rows) | 57928 kB | 68288 kB |
  | `GET /api/v1/audit/export.csv?limit=10000` (bounded, `csvExportMaxRows` cap) | 1221918 B (10,000 rows) | 48296 kB | 68288 kB (unchanged) |

  **Also negligible.** The unbounded deployment-wide inventory export
  materializes all 10,050 rows into memory before writing a single CSV byte
  (`server/http/handlers/secrets_inventory_deployment_csv.go`) but each row
  is metadata only (name, id, project, classification, owner, timestamps —
  never a secret value), so 10k rows costs single-digit MB, not the
  "row count becomes resident memory" risk this test was built to catch. Row
  count is not the dominant cost driver for this dataset shape; concurrency
  and per-request payload size are (below).
- **Concurrency axis, secret count and size held fixed** (100 secrets per
  burst, added on top of the running 10k-row instance), isolating
  concurrency's own effect:
  | Concurrency | Secret size | `VmHWM` (peak) after burst |
  |---|---|---|
  | 1 | 100KB | 68288 kB (unchanged) |
  | 25 | 100KB | 85304 kB |
  | 100 | 100KB | 128728 kB |
  | 100 | 500KB | 237248 kB |
  | 100 | 2MB | **581864 kB — exceeds the 512Mi (524288 KiB) limit** |

  **Concurrency is the dominant driver, not count.** Throughput barely
  changed between concurrency 1/25/100 at the same 100-secret/100KB size
  (111 → 102 → 97.5 req/s — consistent with SQLite's single-writer lock
  serializing the actual writes), but peak memory rose monotonically and
  steeply (68 → 85 → 129 MB) purely from more requests being held in flight
  simultaneously, with no corresponding throughput benefit. Combined with
  payload size the effect compounds: 100 concurrent × 2MB secrets peaked at
  568 MB, already past the shipped 512Mi limit, in an UNCAPPED container —
  a smaller reservation would not have "handled" this more gracefully, it
  would have been killed before reaching this reading.
- **5-minute idle after the 2MB/concurrency=100 peak:** `VmRSS` fell from
  the 332564 kB reading taken immediately after the burst to 36632 kB —
  reclaimed almost completely once load actually stops. The peak is
  transient, but it still has to be survived in the moment it happens.
- **OOM-kill test, at the exact limit `values.yaml` sets.** Fresh container,
  `docker run --memory=512m` (matching `server.resources.limits.memory:
  512Mi` verbatim):
  - Replaying the identical 100×2MB/concurrency=100 burst: peaked at 500864
    kB (95.5% of the 524288 KiB cap) — survived, but by a margin thin enough
    that GC-timing luck, not design headroom, is the reason it didn't tip
    over (the uncapped run of the same scenario read 581864 kB — above the
    cap — showing this is not a stable, repeatable "safe" number).
  - Escalating to 200×2MB/concurrency=200 on the same capped container: the
    process was killed. `docker inspect -f '{{.State.OOMKilled}}'` → `true`,
    exit code 137. **The current 512Mi default is empirically not safe
    against a plausible concurrent-large-secret burst.**
- **30-minute sustained pass, moderate concurrency (25), mixed realistic
  workload** (random per-iteration choice of create-a-~300B-secret /
  paginated-list / list-then-fetch-one, real HTTP calls throughout, fresh
  container):
  | t | Iterations | `VmRSS` | `VmHWM` (peak) |
  |---|---|---|---|
  | start | 0 | 119948 kB | 198492 kB |
  | +2min | 4,989 | 265104 kB | 298924 kB |
  | +10min | 14,514 | 468256 kB | 506724 kB |
  | +18min | 19,503 | 576680 kB | 618552 kB |
  | +26min | 24,249 | 685712 kB | 713616 kB |
  | +30min (test end) | 26,263 | 655172 kB | **723336 kB** |
  | +5min further idle (test fully stopped) | — | 59276 kB | 723336 kB (unchanged) |

  (The `start` reading is elevated above true cold-boot baseline — an
  earlier, interrupted launch attempt of this same driver had already sent
  some requests to this container before being killed and restarted; the
  trend from `+2min` onward is unaffected and is what matters here.)

  **RSS climbs steadily for the full 30 minutes and does not plateau** —
  every 2-minute sample is higher than the last, right through the end of
  the run, peaking at 723336 kB (**~1.4x the 512Mi limit**, achieved under
  only *moderate* concurrency doing a realistic mixed workload, not an
  adversarial burst). This is a lower bar to trigger than the burst
  scenario above and arguably the more concerning finding. It is **not a
  permanent leak**: 5 minutes after the driver stopped entirely, `VmRSS` had
  fallen to 59276 kB, close to the true cold-boot baseline (~23 MB) — the
  memory is reclaimable, just not reclaimed fast enough relative to the
  sustained allocation rate for Go's default GC pacing (`GOGC=100`, no
  `GOMEMLIMIT`) to keep the process anywhere near its steady-state minimum
  while load continues.

  **Leading cause identified, not just observed:** the server log for this
  run contains 704 occurrences of `SECURITY: failed to persist audit event
  "..." ... database is locked (SQLITE_BUSY)` out of 27,351 iterations
  (~2.6%) — SQLite's single-writer lock rejecting concurrent audit-event
  inserts under this load (logged and dropped, not silently — a real,
  separate finding: audit events are lost under write contention on the
  shipped default backend, worth its own follow-up, out of scope here). The
  `.db-wal` file also grew to 59.5 MB over the run without being
  checkpointed. Neither fact alone accounts for the full ~600 MB of growth,
  but both point the same direction: **this is concurrent write contention
  against the bundled SQLite backend under sustained load, not a Go-level
  memory leak** — the growth's shape (steady climb, then full reclaim once
  load stops) matches GC pacing lagging a sustained allocation rate, not an
  accumulating retained data structure.
- **Core dump suppression, red and green, via the real `ApplyMemoryHardening`
  code path** (not a unit test in isolation): a throwaway harness
  (`internal/hardening.ApplyMemoryHardening()` then a deliberate nil-pointer
  dereference) built and run inside `golang:1.26-bookworm` (matching
  ADR-098's own container choice), `GOTRACEBACK=crash`, `ulimit -c
  unlimited`:
  - **Red (baseline, hardening NOT called):** `panic: runtime error: invalid
    memory address or nil pointer dereference` / `[signal SIGSEGV:
    segmentation violation code=0x1 addr=0x0 pc=0xb0858]`, ending
    `Aborted (core dumped)` — a 39.9 MB `core` file present afterward.
  - **Green (hardening called first):** identical panic and SIGSEGV,
    preceded by the real log line `hardening: core dumps disabled
    (RLIMIT_CORE=0)`, ending `Aborted` (no `(core dumped)` suffix) — no
    `core` file present afterward.
- **`helm template` with default `values.yaml`: confirmed Guaranteed QoS.**
  The rendered `server` Deployment's container resources:
  ```yaml
  resources:
    limits:
      cpu: 1
      ephemeral-storage: 256Mi
      memory: 512Mi
    requests:
      cpu: 1
      ephemeral-storage: 64Mi
      memory: 512Mi
  ```
  `cpu` and `memory` both have `requests == limits` for every field
  Kubernetes' QoS classification actually considers (`ephemeral-storage`
  requests/limits differ and this is fine — ephemeral-storage is not part of
  QoS classification: "Containers in a Pod can request other resources (not
  CPU or memory) and still be classified as `BestEffort`",
  [kubernetes.io/docs/concepts/workloads/pods/pod-qos](https://kubernetes.io/docs/concepts/workloads/pods/pod-qos/)).
  The bundled `postgresql` and `web` Deployments remain Burstable
  (`requests != limits`), confirmed unchanged in the same rendered output —
  intentional, see "What changes" above for why.
- **Guaranteed-QoS/`NodeSwap` premise, confirmed against current upstream
  docs, not assumed:**
  [kubernetes.io/docs/concepts/workloads/pods/pod-qos](https://kubernetes.io/docs/concepts/workloads/pods/pod-qos/)
  ("To be `Guaranteed`... Every Container in the Pod must have a memory
  limit and a memory request, and they must be the same. Every Container in
  the Pod must have a CPU limit and a CPU request, and they must be the
  same." — memory alone does not suffice, which is why `cpu` requests were
  also raised here, not just `memory`) and
  [KEP-2400](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/2400-node-swap/README.md)
  ("Swap access is granted only for pods of Burstable QoS... Guaranteed QoS
  pods are usually higher-priority pods, therefore we want to avoid swap's
  performance penalty for them" — Guaranteed and Best-Effort pods are both
  excluded). `NodeSwap` targeted GA in Kubernetes 1.32 per that KEP's
  implementation history; this pass did not independently re-verify GA
  landed exactly on schedule against a specific cluster version, only that
  the QoS-eligibility rule itself is what the KEP and docs state.
- **Could not verify:** a real production Kubernetes node's containerd/CRI-O
  behavior end-to-end under an actual `NodeSwap`-enabled cluster (this
  environment has no such cluster available) — the verification above is
  the documented, specified behavior per Kubernetes' own KEP and docs, not
  an end-to-end observed test against a live swap-enabled node.
- `internal/hardening/memlock_test.go`: `TestApplyMemoryHardening_DisablesCoreDumps`
  and `TestApplyMemoryHardening_CoreDumpDisableFailureIsFatal` cover the two
  remaining branches of `ApplyMemoryHardening` (success, `setrlimit`
  failure) via the same injected-syscall pattern ADR-098 established, now
  without the mlockall-specific branches this change removes.
- `internal/hardening/mlockall_removal_guard_test.go`: repo-wide guard
  confirming no tracked or untracked-but-not-ignored `*.go` file references
  the `Mlockall` identifier, with its own red/green self-test proving the
  scan mechanism actually detects a deliberately reintroduced
  `unix.Mlockall` call rather than passing vacuously.
- `go build ./...`, `go vet`, `gofmt -l`, and `gosec -severity medium
  -exclude-generated` all clean on every package this change touches
  (`internal/hardening`, `internal/config`, `server`).
- Confirmed no other reference to `MlockConfig`, `mlockallFn`, or
  `security.mlock.*` remains anywhere in the repository (`git grep`, not
  `grep -r`, across `*.go`/`*.yaml`/`*.yml`/`*.md`).

## Sizing recommendation (2026-09-04 follow-up — not yet implemented)

**The matrix above shows 512Mi is not a safe Guaranteed-QoS reservation.**
It was OOM-killed under a directly-reproduced burst scenario, and a separate
30-minute moderate-concurrency sustained run peaked at 723 MB (1.4x the
limit) without plateauing. Neither is a contrived adversarial case — 100-200
concurrent clients and 25 concurrent clients sustained are both ordinary
multi-user load, not an attack.

**Recommended: raise `server.resources.requests/limits.memory` to 768Mi**,
keeping `requests == limits` (Guaranteed QoS, unchanged rationale). Headroom
math: the single-burst worst case measured (100 concurrent × 2MB,
uncapped) peaked at 582 MB; 768Mi (805,306,368 bytes) is ~1.4x that. This
does **not** cover the sustained-pass peak (723 MB) with real margin on its
own — see the `GOMEMLIMIT` recommendation below, which is what actually
closes that gap, not a larger static number chasing an unbounded sustained
scenario.

**What this trades off:** every default install now permanently reserves
768Mi instead of 512Mi — 256Mi of additional capacity every customer holds
whether or not they ever approach it, on a product positioned as
lightweight. The alternative (leave 512Mi and accept the OOM risk this
matrix demonstrated) is not a real option once the risk is measured, not
assumed — a Guaranteed-QoS pod that gets OOM-killed under ordinary
concurrent use fails the exact goal (surviving ordinary load without
disruption) the QoS change in the first follow-up was made for. This
number is **not** sized to survive the sustained-load scenario indefinitely
at 25-concurrency — see below for why that is deliberately a `GOMEMLIMIT`
problem instead of an ever-larger static reservation.

**Not implemented in this pass** — `deploy/helm/keyorix/values.yaml` still
reads 512Mi as of this write-up; this is a recommendation for the next
follow-up PR, stated here so the measurement and the decision aren't
separated in time.

## `GOMEMLIMIT`: recommended, ~85% of the container limit

**Recommend setting `GOMEMLIMIT` to approximately 85% of
`server.resources.limits.memory`** (e.g. `GOMEMLIMIT=650MiB` against a 768Mi
container limit — leaving `GOGC` at its default rather than disabling it,
per the Go team's own guidance for using `GOMEMLIMIT` as a backstop
alongside percentage-based GC, not a replacement for it), set as an
environment variable on the server container (no code change needed — the
Go runtime reads it directly; `internal/config`/`server/main.go` need no
new field).

**Why:** the sustained-load finding above is exactly the failure mode
`GOMEMLIMIT` exists for. Go's default GC (`GOGC=100`, no memory limit
awareness at all when `GOMEMLIMIT` is unset — confirmed by `git grep -n
"GOMEMLIMIT\|SetMemoryLimit" -- '*.go' '*.yaml' '*Dockerfile*'` returning
zero hits anywhere in this repo, both before and after this pass) paces
collection off heap *growth*, not proximity to any external ceiling — it has
no way to know a hard cgroup limit exists at all, let alone that it is
approaching one. Under the sustained scenario measured, RSS climbed for 30
straight minutes with no sign of slowing down on its own; the only reason it
didn't end in an OOM-kill is that the container had no cap during that
specific run. With `GOMEMLIMIT` set, the runtime is required to run
additional GC cycles as live heap approaches the configured limit — trading
CPU (more frequent, harder-working collections) for staying alive, changing
the failure mode from "hard kill, mid-request, no warning" to "degraded
throughput/latency, visible in metrics, process stays up." This is a
strictly better outcome for the exact scenario this pass measured, at the
cost of GC CPU overhead under sustained pressure — not measured directly in
this pass (would require comparing sustained-load CPU utilization with and
without `GOMEMLIMIT` set, a follow-up measurement, not inferred here).

**Not a substitute for the base container limit being large enough for
ordinary bursts.** `GOMEMLIMIT` makes the GC work harder as the heap
approaches it; it does not create memory the process doesn't have. A
container limit sized for the single-burst worst case (the 768Mi
recommendation above) still matters — `GOMEMLIMIT` is what keeps a
*sustained* load from reaching that ceiling in the first place, not a way to
shrink the ceiling itself.

**Not implemented in this pass**, same status as the memory-limit
recommendation above — stated here for the next follow-up PR to carry out.
