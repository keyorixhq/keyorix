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
locking memory pages in-process.

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

Swap protection for a Keyorix server deployment should now be provided by
the environment, not the process:

- **Kubernetes:** nodes run with swap disabled by default; this is normally
  already the case and requires no chart change. If a cluster has opted
  into `NodeSwap`, exclude the nodes running Keyorix server pods from swap,
  or pin the deployment to a node pool with swap disabled.
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

- `internal/hardening/memlock_test.go`: `TestApplyMemoryHardening_DisablesCoreDumps`
  and `TestApplyMemoryHardening_CoreDumpDisableFailureIsFatal` cover the two
  remaining branches of `ApplyMemoryHardening` (success, `setrlimit`
  failure) via the same injected-syscall pattern ADR-098 established, now
  without the mlockall-specific branches this change removes.
- `go build ./...`, `go vet`, `gofmt -l`, and `gosec -severity medium
  -exclude-generated` all clean on every package this change touches
  (`internal/hardening`, `internal/config`, `server`).
- Confirmed no other reference to `MlockConfig`, `mlockallFn`, or
  `security.mlock.*` remains anywhere in the repository (`git grep`, not
  `grep -r`, across `*.go`/`*.yaml`/`*.yml`/`*.md`).
