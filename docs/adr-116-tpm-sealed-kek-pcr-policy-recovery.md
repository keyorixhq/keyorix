# ADR-116: TPM-sealed KEK: PCR policy, off-TPM recovery and fail-closed unseal

**Status:** Proposed (2026-10-23). Nothing here is accepted until Andrei approves it, and no
production key path changes before then.
**Date:** 2026-10-23
**Session:** RD-TPM-SEAL-1, against origin/main `760e92e32`.
**Design note:** [design-rd-tpm-seal.md](design-rd-tpm-seal.md) (formats, flows, CLI, test plan,
implementation plan). **Threat model:**
[security/threat-models/tpm-sealed-kek.md](security/threat-models/tpm-sealed-kek.md).
**Demo (not implemented):** [demo/tpm-sealed-kek.md](demo/tpm-sealed-kek.md).
**Builds on:** [ADR-038](adr-038-pluggable-key-providers.md) (key providers),
[ADR-041](adr-041-kms-key-provider.md) (wrapped-KEK providers),
[ADR-010](adr-010-kek-rotation-reencryption-sweep.md) (DEK rotation sweep),
[design-b2-recover-admin](design-b2-recover-admin.md) (the admin recovery key),
[design/recovery-options.md](design/recovery-options.md) (RECOVERY-OPTIONS-1). Cited read-only,
not built on: open PR #3662 (RD-PQWRAP-1, `docs/design/pq-key-wrapping.md`, keyset option R and its
decisions Q1 to Q9) and open PR #3607 (KEYSET-MANIFEST-1, key-set manifest).

## Context

Main already ships a `tpm` key provider (`internal/crypto/tpm_provider.go`, #241). It generates a
random 32-byte KEK on first use, seals it as a keyed-hash object under the TCG ECC-P256 storage
root key (SRK) of the owner hierarchy with `FixedTPM` and `FixedParent`, and stores the TPM2B
public and private areas as JSON at `key_provider.wrapped_key_path`. Its tests (INV-ENCRYPTION-27)
show, against the in-process reference TPM, that a copied blob does not unseal on another TPM.

The provider's own package comment records why boot-state binding was **deferred**, not forgotten.
A PCR policy without a recovery path turns a routine OS or firmware update into permanent loss of
the KEK, and so of every secret. `migrate-provider` cannot rescue it, because it needs `KEK()` from
the current provider first. That comment says to revisit PCR binding "only alongside a
reseal/recovery design". This ADR is that design.

What main does today, checked in code and with a throwaway simulator prototype (results in the
design note, §2):

| # | Fact on main | Consequence |
|---|---|---|
| 1 | Empty auth policy; unseal uses a password session (`PasswordAuth(nil)`) | Any code that can reach the TPM unseals, whatever booted the machine. Prototype: a main-shaped blob still unseals after PCR 7 changes |
| 2 | No off-TPM copy of the KEK | A failed motherboard, a cleared TPM, or an fTPM reset by a firmware update loses all data. Backups carry the sealed blob, which only that TPM can open. `docs/edge-deployment.md` already warns about this |
| 3 | A missing blob file makes `KEK()` mint and persist a **new** KEK | On server start, the key-file check in `internal/startup/validation.go` (`validateFilePermissions`, strict once some key files exist) refuses first. Any other caller of the provider mints silently (from code reading, not reproduced) |
| 4 | One error message for every unseal failure | "Wrong TPM", "TPM cleared" and "blob corrupt" look the same to an operator |
| 5 | Unseal response not parameter-encrypted | On a discrete TPM the KEK crosses the LPC/SPI bus in clear |

## Decisions

### D1. Harden the existing `tpm` provider; do not add a new provider type

`KeyProvider` (`KEK() ([]byte, error)`, `Name()`) does not change. The provider keeps its name,
its `TierHardware` rank and every fallback-downgrade rule (`DetectFallbackDowngrade`,
`AllowWeakerFallback`). New behaviour sits behind a new sealed-blob format version (D4).

*Why:* the tier table, the key-file registry (`internal/keyfiles`), `migrate-provider` and the
operator docs already know `tpm`. A second type would split them and invite a weaker one to stay
in use.

### D2. Optional PCR policy: PolicyPCR over the SHA-256 bank, PCR 7 by default

- `key_provider.tpm.pcr_policy`: `none` (today's behaviour), `secure-boot` (PCR 7), or an explicit
  list (`pcrs: [7, 11]`). The bank is fixed at SHA-256 and is not configurable.
- With a policy, the sealed object's `authPolicy` is the PolicyPCR digest and `UserWithAuth` is
  **false**, so the password path is closed. Prototype: a password-session unseal of such an
  object is refused with `TPM_RC_AUTH_UNAVAILABLE`.
- PCR 7 (Secure Boot state and the authorities that verified the boot chain [VERIFY: TCG PC
  Client Platform Firmware Profile]) is the default. Firmware updates normally move PCR 0 and 2,
  and kernel or initrd updates move PCR 4, 8, 9 or 11 [VERIFY], so those PCRs would turn every
  routine update into a recovery event. A custom list is allowed with a warning.
- When Secure Boot is off, `secure-boot` mode refuses to seal unless the operator explicitly allows
  it, because binding to "Secure Boot disabled" proves very little.

*Why:* PCR 7 changes rarely (Secure Boot toggled, db/dbx/KEK/PK updated, a boot chain signed by a
different authority) and is the selection other unattended-unlock tools default to [VERIFY:
systemd-cryptenroll, BitLocker]. **What it does not give** (Technical risks below): protection
against root on the running, correctly booted host, and against a different OS image signed under
the **same** authority chain.

### D3. A recovery slot outside the TPM, required whenever a PCR policy is on

- `admin encryption tpm init` (and `reseal` into PCR mode) creates a **recovery code**: 256 random
  bits, shown once on the TTY as 52 base32 characters in groups, plus a check value. It is never
  written to a log, never sent over the network and never stored on the host.
- The sealed-blob file carries a **recovery slot**:
  `AES-256-GCM(wk, KEK)`, `wk = HKDF-SHA256(code, salt, "keyorix/tpm-recovery/v1/wrap")`, with a
  random nonce from `NewGCMWithRandomNonce` (so it also works under `GODEBUG=fips140=only`, see
  PQWRAP §9). The AAD binds the slot header, the install id and the `kek_id`. No slow KDF: the code
  is a full-entropy key, not a password, the same reasoning design-b2 §2 applies to the admin
  recovery key.
- The slot wraps the **KEK**, not the DEK. After recovery, `admin encryption tpm recover` reseals
  **the same KEK** to the current TPM state. So `dek.key` and every KEK-derived key (audit
  checkpoint, evidence and backup-manifest keys) stay valid, with no rotate-kek and no
  audit key transition (#3648).
- The recovery code is **not** the admin recovery key (design-b2) and is never derived from it.
  That follows PQWRAP Q6 (decided): one secret must not both authenticate admin recovery and
  decrypt the data.
- `pcr_policy: none` installs may add a slot (recommended, because it covers TPM loss) but are not
  required to, which keeps existing installs working unchanged.
- When PQWRAP option R lands, its hybrid escrow recipient slot in the keyset (wrapping the DEK to
  an offline ML-KEM+X25519 key) is an accepted **alternative** recovery for PCR mode. It is not
  built here.

*Why outside the TPM:* an in-TPM alternative (PolicyOR of the PCR policy with a PolicyAuthValue or
PolicySecret password) survives a PCR change but not a dead board, a TPM2_Clear or an fTPM reset.
Prototype: after `TPM2_Clear` the old blob fails `Load` with `TPM_RC_INTEGRITY`. It also brings
back a TPM-side password with dictionary-attack lockout to manage. A symmetric slot adds no
public-key hop, so it adds no quantum exposure (PQWRAP §3).

### D4. Sealed blob v2: versioned and self-describing; v1 stays readable for good

A JSON document with `format: "keyorix-tpm-seal/v2"`, the TPM2B public and private areas, the
parent description and the SRK name, the PCR bank, the selection, the PCR values at seal time,
the policy digest, `kek_id`, the recovery slot and `sealed_at`. Exact fields are in the design
note §4. The TPM enforces the policy digest inside the sealed object's public area, so the
metadata is advisory: editing it can only make unseal fail (closed), never weaken it. Recovery
results are checked against the KEK check value **and** a trial unwrap of `dek.key` before
anything is resealed.

A v1 blob (`{public, private}`) keeps unsealing as today. Moving to v2 is only the explicit
`admin encryption tpm reseal`, never a silent rewrite at boot.

### D5. Fail closed, classify the failure, never mint over existing data

| Observed | Class | Operator message (shape) |
|---|---|---|
| Device absent (`ENOENT`), `EACCES`, busy | `tpm-unavailable` | "no TPM at /dev/tpmrm0 (VM without a vTPM? container without the device? not in the tss group?)" |
| `Load` returns `TPM_RC_INTEGRITY` | `not-this-tpm` | "this blob was not sealed by this TPM, or the TPM was cleared or reset (a firmware update can reset an fTPM). Use the recovery code: `admin encryption tpm recover`" |
| `Unseal` returns `TPM_RC_POLICY_FAIL` | `boot-state-changed` | "PCR 7 is X, was Y at seal time (Secure Boot state or db/dbx changed). If you expected this, run `admin encryption tpm recover`" |
| JSON or TPM2B decode fails | `blob-corrupt` | names the file and suggests restoring it from backup |
| Blob missing and `dek.key` present | `blob-missing` | refuses. **Never** generates a new KEK |

The prototype confirms that the two TPM response codes come out of go-tpm and can be told apart
with `errors.Is(err, tpm2.TPMRCPolicyFail)` / `tpm2.TPMRCIntegrity`. "Another TPM" and "this TPM
after Clear" both give `TPM_RC_INTEGRITY`, and the design does not pretend to separate them. No
class falls back to another provider unless the existing `AllowWeakerFallback` rules allow it.

### D6. Loud alerting without a running server

On a refusal the server cannot start, so the alert is: the classified message on stderr, a
non-zero exit (container restart loops and systemd units show it), and
`keyorix_kek_unseal_failures_total{class}` when metrics are up. On recovery, the offline host
command (ADR-108 style; not a network endpoint) writes the audit event
`encryption.tpm_recovery_used` (actor, class, PCR diff) through the normal chain once the KEK is
back. It also sets a **sticky posture warning** ("TPM recovery used on <date>; rotate the recovery
code") until `admin encryption tpm recovery-code rotate` runs. `admin encryption tpm status`
shows the device, the Secure Boot state and the PCR values now versus at seal time. It predicts
the policy digest in software, so drift is visible before a reboot fails. The prototype checks
that the software prediction equals the TPM's trial digest.

### D7. Parameter encryption on unseal; pin the SRK

Unseal runs in a policy session salted to the SRK, with response encryption (`EncryptOut`,
AES-128-CFB). The prototype shows this flow works against the reference TPM. v2 records the SRK
name at seal time and refuses when the regenerated SRK name differs, before any secret moves, so
a swapped or impersonated parent is detected. *Why:* passive bus sniffing of discrete TPMs is a
published attack on TPM-only disk encryption [VERIFY].

### D8. Test strategy: reference simulator for logic, swtpm for the device path, lab on hardware

- Unit and property tests stay on `go-tpm-tools/simulator` (the TCG reference implementation, cgo,
  test-only). That is where the existing INV-ENCRYPTION-27 tests run.
- A CI job with **swtpm** exercises the real device-open path and a separate TPM process (design
  note §8). This is a `.github` change and belongs to a later session with `.github` rights.
- Lab: swtpm on the e2e VM, and one machine with a physical TPM 2.0 and Secure Boot on: **pending
  e2e VM / pending hardware**. Nothing in this ADR claims hardware behaviour beyond what the
  reference implementation shows.

### D9. Upgrading an existing install into PCR mode: the old blob cannot be revoked

A TPM object cannot be revoked. A v1 blob in an old backup still unseals on the same TPM with no
PCR check, and `rotate-kek` re-wraps the **same** DEK. `admin encryption tpm reseal --pcr-policy
secure-boot` therefore prints this, and the runbook recommends `admin encryption rotate` (ADR-010
DEK sweep) after enabling PCR mode, for installs whose old backups are not under the same
protection. The same rule applies after rotating a recovery code. General statement: **a DEK is
only as protected as the weakest wrap of it that was ever written.**

## Consequences

- PCR binding becomes possible without the data-loss trap the provider comment describes. The
  price is a recovery code the operator must keep offline, and a recovery step after a Secure Boot
  db/dbx update.
- Existing `tpm` installs see no change until they opt in.
- Restore onto replacement hardware becomes possible with the recovery code (`tpm recover`
  reseals onto the new TPM; prototype covered).
- New config keys, five new admin subcommands, one audit event type, one metric and one posture
  item. The surface is in design note §6.

## New vs state of the art

Sealing a key to a TPM with a PCR policy and a recovery key is **established practice, not new**:
BitLocker (TPM plus PCR 7/11 with a 48-digit recovery password), Linux clevis/tang tpm2 pins,
`systemd-cryptenroll --tpm2-pcrs` with a recovery key, and `systemd-creds` [VERIFY all four, not
read this session]. Among secret managers, HashiCorp Vault and OpenBao auto-unseal through cloud
KMS, HSM (PKCS#11) or Transit, with no native TPM seal that we know of [VERIFY].

What this design adds, stated modestly:

1. TPM sealing of an **application-level** KEK with a PCR-mismatch path that restores the **same**
   KEK. A hash-chained audit trail (ADR-029) and its KEK-derived checkpoint keys therefore survive
   a recovery with no key transition. Disk-encryption tools have no audit chain to keep.
2. Recovery use is itself an audited, sticky security event, not a silent unlock.
3. A failure taxonomy that maps TPM response codes to operator actions, plus software PCR-policy
   prediction to show drift before a reboot fails.
4. A written statement of what PCR 7 binding does **not** stop (next section), which is evidence
   in its own right for an assessor.

This is incremental engineering, not a research result. It should be presented that way in
funding or certification material.

## Technical risks

| Risk | Effect | Mitigation / status |
|---|---|---|
| Root on the running, correctly booted host | Unseals: PCRs are correct at runtime | **Not addressed by TPM sealing at all**, same as today. Needs remote attestation (R10 Keylime) or an operator factor at boot |
| Another OS signed under the same authority (same distro's live image via shim) | PCR 7 can be identical, so it unseals | Stated limit. PCR 4/11 or signed-policy (PolicyAuthorize) designs narrow it at the cost of more recovery events; deferred |
| vTPM state copied with the VM image (hypervisor or backup level) | "Stolen VM image" claim fails | Holds only if the vTPM state is not taken with the disk [VERIFY per hypervisor/cloud]. Documented as a limit |
| fTPM reset by a firmware update; board swap | Blob dead | Recovery slot (D3); runbook step "have the recovery code before updating firmware" |
| Recovery code leaked | Anyone with the data dir decrypts anywhere | Shown once, TTY only, rotate command, sticky posture after use; D9 for old copies |
| Recovery code lost and the PCR state changed | Data loss, by design | `init` refuses PCR mode without a confirmed code (re-type check); `status` warns if the slot is missing |
| dbx updates pushed by the OS vendor move PCR 7 unexpectedly | Unplanned recovery events | `status` drift check; documented. A "suspend for one reboot" mode is deferred (NEEDS ANDREI) |
| go-tpm is pre-1.0 (v0.9.8, 2025-12-29; last commit 2026-10-01; Apache-2.0) | API churn | Pinned; wrapper kept small. The simulator needs cgo (test-only) |
| Discrete-TPM bus interposer (active) | MITM of the session salt | SRK-name pin (D7) detects a swapped parent; a full active attacker on the bus is out of scope |
| Simulator is not hardware | Claims could overreach | D8: lab validation pending; nothing claimed beyond the reference implementation |

## Open decisions (NEEDS ANDREI)

Listed with recommendations in the session report and in design note §11: default `pcr_policy`
for new installs; whether the recovery slot is mandatory without a PCR policy; whether to build a
"suspend for one reboot" mode; whether PQWRAP's escrow slot replaces or complements the recovery
code; and whether `tpm reseal` into PCR mode should run the DEK sweep automatically.
