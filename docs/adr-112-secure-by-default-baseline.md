# ADR-112: Secure-by-default baseline, and loud, audited opt-outs

## Status

**Proposed** (2026-10-02). Two decisions are already recorded (see "Decisions recorded"); the remaining open questions are listed at the end.

Amended 2026-10-05 (decision by Andrei, "Amendment 1" below): the
audit-before-disclosure and `synchronous` baseline items gain one named
`insecure_` opt-out, `storage.database.insecure_audit_skip_durable_sync`. The
defaults are unchanged. Full spec: `docs/specs/fast-audit-mode.md`.

Related: ADR-111 (signed connector host, host connector allowlist), ADR-098 (process memory hardening), ADR-064 (air-gap update bundles), ADR-109 (air-gapped build profile).

A read-only gap check of `main` @ 219160b2 against this baseline (2026-10-02) found 9 of 22 items in place, 5 partial and 8 missing; see "Gap check results".

## Context

Keyorix's promise is "easy to operate, secure by default, with opinionated settings from experienced security people". Today that is true in many places (fail-closed startup, no default passwords, hash-chained audit, signed releases), but it isn't written down as one baseline, so:
- nobody can check a deployment against it in one step;
- a new feature can ship with a weaker default without anyone noticing;
- an operator can weaken a setting without the change being visible to auditors.

Regulated buyers (DORA, NIS2, ENS, CRA) ask for exactly this: what the secure configuration is, and how deviations are detected.

## Decision (proposed)

### 1. The opt-out rule

Every setting that weakens security below the baseline:
- is named with an `insecure_` prefix (for example `insecure_allow_plain_http`), so it can't be enabled by accident or misread in review;
- logs a warning at **every** start, naming the setting;
- is audited when it changes: config has no hot reload, so at every start the server compares the security-relevant settings with those recorded at the previous start and writes an audit event with the old and new values for any difference;
- appears in the posture report (below) as a deviation.

No setting may weaken security silently. A new feature's defaults must meet the baseline; a PR that adds a weaker default must use an `insecure_` setting instead.

### 2. The posture report

`keyorix-server admin posture` (or an extension of `admin validate`) prints every deviation from the baseline: `insecure_*` settings in effect, file permissions, TLS configuration, admin MFA coverage, key rotation age, connector allowlist contents. It exits non-zero when any deviation exists, so it can run in CI or monitoring. The same data is available read-only over the API for dashboards.

### 3. The baseline

Each item is a default that holds unless an `insecure_` setting says otherwise.

**Process and host**
- Refuse to start if config, database or key files are readable by group or others (as `ssh` does with keys). The server already sets umask 0077 for files it creates (#1647).
- Core dumps disabled and the process marked non-dumpable, so a crash can't write keys or secrets to disk.
- Runs as non-root. The shipped systemd unit and container image are hardened: read-only root filesystem, no new privileges, no extra capabilities, minimal base image.
- Key material is wiped from memory after use where Go allows it (byte slices, not strings).

**Network**
- TLS 1.3 preferred; TLS 1.2 allowed by default but only with forward-secret AEAD cipher suites. TLS 1.0/1.1 are never accepted. A single setting (`tls_mode: strict`) switches to TLS 1.3 only, and the posture report shows which mode is in effect. Rationale: NIST SP 800-52 Rev. 2 requires servers to support both 1.2 and 1.3, BSI TR-02102-2 prefers 1.3 while planning 1.2's phase-out, and OT and legacy clients still need 1.2; TLS 1.2 with modern ciphers is therefore compliant, not an `insecure_` opt-out.
- No plaintext listener except a localhost health endpoint.
- Optional mutual TLS for machine identities.
- Administrative endpoints on a separate listener bound to localhost by default.

**Identity and access**
- No default credentials; first access uses the one-time bootstrap token.
- MFA required for admin accounts by default.
- Short default session lifetime; short-lived machine tokens; revocation takes effect immediately (#G18).
- Break-glass stays single-person, so it works in a real emergency, but it always produces an immediate alert and an audit event, and every activation must be reviewed afterwards: an open activation without a recorded review shows as a posture deviation. This matches the market (Infisical's "bypass approvals" works the same way) and DORA, which requires emergency access on a need-to-use basis and segregation of duties but not multiple approvers (RTS 2024/1774 Art. 21).
- Approval workflows ("dual control": a second person must approve before a secret is read, for selected policies) are a separate, later feature, not part of this baseline. Vault (control groups) and Infisical (access requests) both sell this as an enterprise feature; whether Keyorix includes it in the AGPL core or gates it is an open licensing decision (see open questions). Key-management dual control (PCI DSS 3.6/3.7) is already covered by the Shamir recovery split.
- Authorization is deny by default; any error while resolving permissions denies (fail closed). The fault-injection fuzzer's oracle (c) enforces this; #2412 is a current violation.

**Secrets and audit**
- A secret value is never returned before its audit record is durably committed (audit-before-disclosure, group commit). If the audit write fails, the read fails. One named opt-out exists (`storage.database.insecure_audit_skip_durable_sync`, default off) which skips only the *wait for the disk sync*, not the write and not the fail-closed behaviour — see Amendment 1.
- Secret values never appear in logs, error messages, URLs or metrics. Enforced by a test oracle over all operations, not by review alone.
- The audit log is hash-chained with signed checkpoints and offline verification (exists).
- SQLite runs `synchronous=FULL`; Postgres runs with `fsync`, `synchronous_commit` and `full_page_writes` on (#2403). `storage.database.insecure_audit_skip_durable_sync` (default off) is the only setting that relaxes this, and only as described in Amendment 1.

**Keys**
- Scheduled KEK rotation on by default, with a configurable interval.
- HSM/KMS key protection available as an option (exists: `server/admin/encryption.go`).
- The recovery key can be split among several people (Shamir), so no single person can recover alone (exists: `internal/crypto/shamir_provider.go`).

**Supply chain and updates**
- Every binary is signed (Ed25519/cosign), with SBOM and SLSA provenance (exists).
- The connector host is signature- and version-verified before it runs, and only allowed connector types and destinations are reachable (ADR-111).
- Update bundles, including air-gapped ones, are signed and **cannot downgrade**: an older bundle is refused even with a valid signature, so an attacker can't "update" a server to a known-vulnerable version (exists, with tests).

### 4. Enforcement in CI

- A test per baseline item that fails if the default changes.
- A test that every config key weakening security uses the `insecure_` prefix, the start-up warning and the audit event.
- The posture command run against the default configuration must report zero deviations.

## Gap check results (2026-10-02)

9 of 22 items exist, 5 are partial and 8 are missing.

**Exists:** bootstrap-token-only admin creation (no default credentials); hash-chained, signed audit log with offline verification; key-material memory wiping; HSM/KMS key protection; Shamir recovery-key split; signed binaries with SBOM and SLSA provenance; signed update bundles with tested downgrade protection; deny-by-default authorization; a posture-report foundation (`admin validate`, `keyorix compliance report`).

**Inverted defaults (fix first):** `enable_file_permission_check` and `require_mfa` are off unless enabled, so the weak state is the default. Flip both; existing deployments get a grace period with a start-up warning and a posture deviation until they comply.

**Missing or partial, in priority order:**
1. Audit-before-disclosure: secret values are returned before a fire-and-forget audit write (`secrets_crud.go`). In progress (group commit, alongside the read-throughput work).
2. Fail-closed authorization on the MFA path: #2412. In progress.
3. The opt-out rule: only 4 of 32 security-weakening settings use the `insecure_` prefix; none warns consistently or is audited on change. Work: rename with deprecation aliases, start-up warnings, start-to-start settings diff audited, plus the structural CI test.
4. Posture report: `admin validate --posture` with a non-zero exit on deviations.
5. TLS: keep 1.2 as the floor, restrict it to forward-secret AEAD suites, add the TLS 1.3-only strict mode, and show the mode in the posture report.
6. Separate admin listener bound to localhost.
7. Scheduled KEK rotation (manual only today).
8. Break-glass: keep single-actor (decided 2026-10-02); add the mandatory post-activation review and its posture deviation.
9. Optional mutual TLS for machine identities.
10. CI enforcement: one test per baseline item and the zero-deviation posture gate.

## Amendment 1 (2026-10-05): fast audit mode, an `insecure_` opt-out for guaranteed-power deployments

Decision by Andrei, 2026-10-05. Spec: `docs/specs/fast-audit-mode.md`.

### Why an opt-out is warranted here specifically

PERF-2 measured Keyorix at ~10x Vault's single-client read latency on pve01
(8.36ms vs 1.30ms p50) **with Vault's own file audit device enabled**, and
confirmed that at c=1 essentially the entire 8.36ms is one durable Postgres
commit (the independently measured `fdatasync` floor on that disk is 9.33ms). A
source-verified read of each competitor's audit write path
(Vault, OpenBao, Conjur, Infisical) found that **none of them fsync audit before
answering**: Vault and OpenBao do one `write()` to an `O_APPEND` file with no
`fsync` anywhere, Conjur fires into syslog, Infisical queues to Redis and
swallows request-path errors. Their speed is not a technique Keyorix is missing;
it is the durability Keyorix declines to skip.

That makes audit-before-disclosure a genuine differentiator worth keeping as the
default — and it also makes "I have a UPS and a battery-backed write cache, give
me Vault's number" a legitimate operator request that the baseline should answer
with a named, loud, audited setting rather than with a fork or a patch.

### The opt-out

`storage.database.insecure_audit_skip_durable_sync`, boolean, default **false**,
settable from the config file only. When true:

- Postgres: the audit-commit transaction, and only that transaction, issues
  `SET LOCAL synchronous_commit = off`.
- SQLite: the DSN uses `_synchronous=NORMAL` instead of `FULL`, in the WAL mode
  that is already the default.

It carries the full §1 opt-out treatment: a `WARNING:` line at **every** start, an
`admin.audit_durable_sync_skipped_at_startup` audit event at every start (so the
tamper-evident chain itself records the window the install ran weakened), an entry
in the `insecure_` registry, a line in `admin validate`'s posture output, and a
boolean in `GET /system/info` so a buyer's auditor can see it without host access.

### What the mode does and does not change

Unchanged, and tested to stay unchanged:

- The audit row is still INSERTed and COMMITted in the same transaction/batch,
  before the secret value is returned. No background writer, no queue.
- If the audit row cannot be written, the request still fails. Only the *wait for
  the disk sync* is skipped.
- The hash chain can lose a **tail** of entries to an OS crash or power loss. It
  can never gap or fork: WAL (Postgres) and `-wal` frames (SQLite) are totally
  ordered and recovery accepts only a valid prefix, so a surviving row's
  `prev_hash` always points at a row that also survived. `verify-audit` must pass
  after a `kill -9` under load, on both backends, and there is a test for it.

Changed, and stated plainly rather than minimised:

- Postgres: up to ~600ms (3 × `wal_writer_delay`) of audit entries can be lost to
  an OS or database-server crash.
- SQLite: `PRAGMA synchronous` is per-connection and the pool is shared, so the
  relaxation is **database-wide**, not audit-only — a power loss can lose the last
  fraction of a second of secret writes too. The narrower alternative (flip the
  pragma per transaction, restore afterwards) was rejected because it fails open:
  a skipped restore leaves a connection permanently weakened with nothing
  reporting it.

This is Vault's guarantee, not a safe one, and the hardening guide says so in
those words.

## Consequences

- The baseline becomes part of the product's documentation and sales material: "here is the secure configuration, and here is how you prove you're running it."
- Some existing settings may need renaming to the `insecure_` form, with a migration note and a deprecation period for the old names.
- Every new feature carries a small extra cost: its defaults must meet the baseline, and any weaker option needs the opt-out plumbing.
- Some items (non-dumpable process, memory wiping) are best-effort in Go and are documented as such, not overclaimed.

## Open questions

1. Posture report: a new `admin posture` command, or extend `admin validate`? Proposal: extend `validate` with a `--posture` mode (the gap check found `admin validate` and `keyorix compliance report` already provide most of the foundation).
2. ~~TLS 1.2 default~~ Decided 2026-10-02: TLS 1.2 stays allowed by default with modern ciphers only; TLS 1.3-only is a strict-mode setting.
3. Admin MFA by default on fresh installs: also enforced on upgrades of existing deployments, with a grace period? Proposal: yes, with a grace period and a posture warning until enabled.
4. Shamir split of the recovery key: default or optional? Proposal: optional, recommended in the hardening guide.
5. Approval workflows (dual control on secret reads): include in the AGPL core as a differentiator, or make it a third gated feature? Today exactly two features are gated (`airgap_updates`, billing); either choice changes the licensing story. Decide before the feature is built.

## Decisions recorded (2026-10-02)

- Break-glass remains single-person, with mandatory alert, audit event and post-activation review. Two-person break-glass is rejected: an emergency path that needs a second person fails exactly when it's needed.
- TLS 1.2 remains allowed with forward-secret AEAD suites; TLS 1.3-only is available as strict mode.
- Approval workflows are deferred to a separate feature; licensing is open question 5.

## Decisions recorded (2026-10-05)

- Audit-before-disclosure stays the default. One named `insecure_` opt-out
  (`storage.database.insecure_audit_skip_durable_sync`) is added for deployments
  with guaranteed power, giving Vault-equivalent semantics and Vault-equivalent
  speed. See Amendment 1. Two sub-decisions are still open and are listed as
  **NEEDS ANDREI** in `docs/specs/fast-audit-mode.md` §4 and §6: whether the
  setting reports as in-effect on a `remote` backend, and whether the SQLite
  database-wide scope is accepted or the setting is restricted to Postgres.

## Definition of done

- The gap check is recorded, and every baseline item is either present with a test or scheduled.
- `insecure_` naming, start-up warnings and audit events are enforced by a test over all config keys.
- The posture report exists and reports zero deviations on a default install.
- The hardening guide in `docs/` lists the baseline, the posture command and every `insecure_` setting.
