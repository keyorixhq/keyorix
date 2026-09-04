# ADR-098: Process memory hardening — mlock and core dump suppression

## Status

**Partially superseded (2026-09-04) — see
[ADR-100](adr-100-mlockall-removal-deployment-swap-control.md).** The
`mlockall` half of this decision is removed: measured against the real
server binary and the shipped Helm chart's default memory limit, it pins an
ever-growing, never-shrinking floor of locked memory (`VmLck`) that already
exceeds that default at rest, and cannot deliver its intended protection in
a garbage-collected runtime regardless of tuning (the GC moves and copies
memory a locked address does not follow). **Core dump suppression
(`RLIMIT_CORE=0`) is unaffected and remains exactly as documented below** —
only the mlockall-specific content in this document (the Summary's item 1,
the "mlockall is opt-out" design decision, and the Operator prerequisites
section) describes a mechanism no longer in the code; everything else here
is still accurate. This document is kept as the historical record of why
mlockall was originally adopted and how it was verified at the time — see
ADR-100 for the removal decision and its own verification.

**Originally accepted (2026-09-02).** Follow-up to the 2026-09 security review
(`docs/security-review-2026-09.md`), specifically its memory-zeroization
finding: `internal/crypto`'s wipe-after-use discipline closes the transient
in-process exposure of decrypted secret values (three unwiped heap copies,
fixed 2026-09-02), but that fix protects the process's own address space
only. It says nothing about two durable ways the same plaintext can leave
that address space and persist: swap, and a core dump. This ADR closes both.

## Summary

Two independent hardening steps are applied once, at server startup, before
any key material or decrypted secret value is allocated
(`internal/hardening.ApplyMemoryHardening`, called from `server/main.go`):

1. **[Superseded by ADR-100 — removed.] `mlockall(MCL_CURRENT | MCL_FUTURE)`** — locks the process's already-
   mapped pages, and every page mapped for the rest of the process's
   lifetime, into physical RAM. The kernel can never swap a locked page to
   disk, so a decrypted secret value can no longer survive in a swap file or
   partition across a reboot or hibernate. This is the same mechanism
   HashiCorp Vault applies at Vault server startup, for the same reason.
2. **`RLIMIT_CORE = {0, 0}`** — both the soft and hard limit are lowered to
   zero, unconditionally, for every process. A core dump captures the
   process's full resident memory at the moment of a crash; with the limit
   at zero the kernel refuses to write one, regardless of what
   `core_pattern` or an inherited shell `ulimit -c` would otherwise do.

## Scope

Applied to the server process (`server/main.go`) only. The CLI binary
(`main.go` → `internal/cli`) is out of scope: it is short-lived (a single
command invocation, not a long-running daemon holding decrypted secret
material resident for extended periods), and Vault's own precedent — the
model this ADR follows — is specifically the *server* daemon, not its CLI
client. If the CLI grows a long-running mode that holds secret material for
an extended period, this scoping decision should be revisited.

## Design decisions

**Core dump suppression is unconditional — no config switch.** Unlike
mlockall, lowering RLIMIT_CORE has no operator prerequisite (no capability,
no raised host limit) and cannot fail for a process operating on its own
resource limits. There is no legitimate operational reason to want core
dumps of a secrets-manager server enabled, so this is not gated behind
config the way mlockall is.

**`Max` is lowered to 0, not just `Cur`.** Setting only the soft limit
(`Cur`) leaves the hard limit (`Max`) at whatever the process inherited,
which would let a later unprivileged `setrlimit` call raise `Cur` back up
within that ceiling. Lowering `Max` to 0 as well closes that — raising it
back would require `CAP_SYS_RESOURCE`, which this process does not need or
request for any other reason. A repo-wide check found no in-process crash
handler, panic recovery path, or signal handler that calls `setrlimit` at
all (`rg -n "Setrlimit|RLIMIT_CORE|debug\.SetTraceback|SIGQUIT|Mlockall"`
across the repo, before this change, returned no matches outside an
unrelated `RLIMIT_FSIZE` test fixture) — so nothing in this codebase
re-enables core dumps after this call. An external supervisor (systemd,
a container runtime) that explicitly sets `LimitCORE=` or `ulimit -c` before
`exec`-ing the process could still raise the *inherited* starting limit
before this code ever runs, and is out of this code's control — see
Operator prerequisites below.

**[Superseded by ADR-100 — mlockall and this config are removed from the
code; kept here only as the historical record of the original design.]**
mlockall is opt-out (`security.mlock.disabled`, default false — attempted
by default), and its failure mode is config-driven
(`security.mlock.require_success`, default false — warn and continue).**
`mlockall` requires `CAP_IPC_LOCK` or a raised `RLIMIT_MEMLOCK`, and many
hosts — unprivileged containers particularly — grant neither by default.
Defaulting to "attempt it, warn loudly on failure" (mirroring Vault's own
default) gets the protection for free on hosts that support it, without
turning an unrelated capability gap into a hard startup failure on hosts
that don't. `security.mlock.require_success=true` is available for
operators who need the guarantee to be enforced rather than best-effort —
matching Vault's own configurable "refuse to start" mode.

**Every outcome produces exactly one log line, unconditionally.** Success,
skipped-by-config, and failure (both warn and fatal) each log a distinct,
explicit message. Silent failure — mlockall silently not applying with no
trace in the log — was called out as the one unacceptable outcome, and is
structurally impossible here: every code path through
`ApplyMemoryHardening` logs before returning.

## What this does not protect against

This narrows the memory-zeroization gap; it does not close it. Specifically,
it does **not** protect against:

- **Transient in-process exposure.** While the process is live and healthy,
  a decrypted secret value is still present in heap memory for whatever
  window exists between decryption and the wipe-after-use call — the exact
  exposure documented and accepted in the memory-zeroization review entry
  this ADR follows up on. `mlockall` keeps that memory off disk; it does not
  make it inaccessible to something that can read the live process's address
  space (`ptrace`, `/proc/[pid]/mem`, a hypervisor-level memory inspection).
- **A privileged local attacker.** Anyone with the capability to attach a
  debugger to the process, or root access to the host, can read locked
  memory just as easily as unlocked memory — mlock defends against swap
  persistence, not against process introspection.
- **Memory captured before this code runs.** `mlockall(MCL_CURRENT | ...)`
  only locks pages mapped *by the time the call executes*. It runs as early
  as practical in `server/main.go` (immediately after config validation and
  startup validation, before core-service/encryption initialization), but
  anything hypothetically allocated earlier in the Go runtime's own startup
  is outside this guarantee. In practice nothing secret-bearing is allocated
  that early.
- **A core dump explicitly forced by an external supervisor bypassing this
  process's own limits**, or a kernel-level memory capture mechanism (e.g. a
  hypervisor snapshot, `kdump`) that doesn't go through this process's
  `RLIMIT_CORE` at all.
- **The CLI process** (see Scope above).

## Operator prerequisites

**[Superseded by ADR-100 — mlockall is removed; this section no longer
applies. See ADR-100's "Operator guidance: deployment-level swap control"
for the current recommendation.]**

`mlockall` needs one of:

- The `CAP_IPC_LOCK` capability granted to the process (e.g. in a container:
  `--cap-add=IPC_LOCK`; in Kubernetes: the `IPC_LOCK` capability in the
  container's `securityContext.capabilities.add`), or
- `RLIMIT_MEMLOCK` raised above the process's resident set size. Under
  systemd, set `LimitMEMLOCK=infinity` (or a large explicit value) in the
  unit file. Docker's default `--ulimit memlock` is often small or absent
  and commonly needs to be raised explicitly for a non-root container user.

Without either, `mlockall` fails with `EPERM`/`ENOMEM`, which is logged as a
`WARNING` (or is fatal, if `security.mlock.require_success=true`) — it is
never silent.

## Verification

Verified with a real Linux container (this repo's development host is
macOS, which has no `mlockall`/`/proc` equivalent to test against directly),
`golang:1.26-bookworm`, matching this repo's pinned Go version:

- **mlockall success, quoting `/proc/self/status`:** run with
  `--cap-add=IPC_LOCK`, unprivileged (`--user 1000:1000`, `--cap-drop=ALL`
  otherwise):
  ```
  hardening: core dumps disabled (RLIMIT_CORE=0)
  ApplyMemoryHardening returned nil
  VmLck:	 1227348 kB
  hardening: mlockall succeeded -- process memory locked against swap
  ```
  `VmLck` was `0` before this change; it is non-zero and reflects the
  process's actual locked memory after.
- **mlockall failure warns, does not fail startup:** run with
  `--cap-drop=ALL --ulimit memlock=0:0` (no capability, no raised limit),
  `security.mlock.require_success` unset:
  ```
  hardening: core dumps disabled (RLIMIT_CORE=0)
  WARNING: hardening: mlockall failed (operation not permitted) -- decrypted
  secret memory CAN be swapped to disk. Grant CAP_IPC_LOCK or raise
  RLIMIT_MEMLOCK (systemd unit: LimitMEMLOCK=infinity) to fix, or set
  security.mlock.disabled=true to silence this warning
  ApplyMemoryHardening returned nil
  ```
- **mlockall failure is fatal with `require_success=true`:** same
  no-capability container, `RequireSuccess: true` — process exits 1 with the
  same message, prefixed "refusing to start: security.mlock.require_success=true".
- **Core dump suppression, verified by triggering a real crash, not by
  reading the rlimit back:** baseline (no hardening applied, `GOTRACEBACK=crash`,
  shell `ulimit -c unlimited`) produces a 46 MB `core` file on a deliberate
  nil-pointer dereference. The identical crash, in a process that called
  `ApplyMemoryHardening` first, produces **no** core file — the shell
  process reports `Aborted` (not `Aborted (core dumped)`), and the working
  directory is empty afterward. This confirms the in-process `RLIMIT_CORE=0`
  genuinely overrides the *inherited* shell limit, which is the case that
  actually matters (a process is normally started by a supervisor whose own
  ulimit posture this code cannot control any other way).

Unit tests (`internal/hardening/memlock_test.go`) cover all four branches
(success, disabled, failure-warns, failure-fatal) deterministically via
injected syscall stubs, independent of the test host's actual
capabilities — mutation-tested by reverting each of the `Max: 0` and
`RequireSuccess` fatal-path lines in turn and confirming the corresponding
test goes red.

## Alternatives considered

- **Make mlockall required (fatal by default).** Rejected: would break
  startup on the (common) hosts that don't grant `CAP_IPC_LOCK` by default,
  turning an availability regression into the cost of a protection most
  operators wouldn't have configured for anyway. Matches the reasoning
  behind Vault's own default.
- **Gate core dump suppression behind config too, for symmetry with
  mlockall.** Rejected: the two mechanisms don't share a failure mode.
  mlockall has a real operator prerequisite it can legitimately lack;
  `RLIMIT_CORE=0` does not, so there is nothing for a config switch to
  usefully opt out of.
