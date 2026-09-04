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

**Follow-up pass (2026-09-04): observed values, real binary, real Linux
container.** The original version of this ADR asserted the measurements
above from a companion evidence document rather than from commands run in
this ADR's own verification pass — the same evidence-provenance gap ADR-098
itself had (verified under a configuration, `--cap-add=IPC_LOCK`, the
shipped chart does not grant). This section closes that gap with commands
run directly against `server/Dockerfile`'s image, `linux/arm64` via this
environment's Docker backend (OrbStack — not the `linux/amd64` architecture
the shipped `ghcr.io/keyorixhq/keyorix-server` image and most production
Kubernetes nodes run; not independently re-measured on `amd64` from this
pass).

- **`VmLck` is 0 at rest, confirming mlockall is genuinely gone** — the
  literal line from `/proc/<pid>/status` inside the running container, no
  special capability granted:
  ```
  VmLck:	       0 kB
  ```
- **RSS at rest and under load**, same container, SQLite storage, real
  `/auth/login` + `POST /api/v1/secrets` HTTP calls (not synthetic
  allocation) — 20 secrets at ~500KB then 30 more at ~2MB (~70MB of secret
  payload total), then a 30-second idle period:
  | Point | `VmRSS` | `VmHWM` (peak) |
  |---|---|---|
  | At rest (boot, before any secret) | 22704 kB | 47452 kB |
  | After 20×~500KB secrets | 48684 kB | 52884 kB |
  | After 30 more ×~2MB secrets (peak load) | 75284 kB | 81736 kB |
  | After 30s idle (health-polled every 5s) | 70336 kB | 81736 kB |

  Unlike the pre-removal measurement (byte-for-byte identical before/after
  a 30s idle period — `mlockall`'s locked pages could not be reclaimed),
  RSS here **decreases** during the idle period (75284 → 70336 kB) — the Go
  runtime's scavenger can now actually return freed pages to the OS, because
  nothing is pinning them.
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
