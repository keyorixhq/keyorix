# ADR-117: TPM-sealed KEK: PCR policy, off-TPM recovery and fail-closed unseal

**Status:** Proposed (2026-10-23). Andrei approved it as Proposed on 2026-10-23, with the answers
recorded under "Decisions (Andrei, 2026-10-23)" below, so the implementation sessions (PR A and
PR B of the design note) may start. It is not Accepted, and no production key path changes before
the implementation PRs merge. **Amendment A (2026-10-27, RD-TIER-ADR117-1, Proposed, not yet
approved):** D10 to D13 below. Signed PCR policy is preferred over raw PCR binding, plus the update
and recovery flow, the fail-closed principle and the claims-vs-evidence table. Until Andrei
approves the amendment, D2 and Decision 2 stand as written.
**Date:** 2026-10-23 (amended 2026-10-27)
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
  list (`pcrs: [7, 11]`). The bank is fixed at SHA-256 and is not configurable. The default for
  new installs is `secure-boot` when Secure Boot is on, else `none` with a posture note
  (Decision 2); existing installs stay `none`.
- With a policy, the sealed object's `authPolicy` is the PolicyPCR digest and `UserWithAuth` is
  **false**, so the password path is closed. Prototype: a password-session unseal of such an
  object is refused with `TPM_RC_AUTH_UNAVAILABLE`.
- PCR 7 (Secure Boot state and the authorities that verified the boot chain, per the
  systemd-cryptenroll PCR table [S2]) is the default. Firmware updates normally move PCR 0 and 2,
  and kernel or initrd updates move PCR 4, 9 or 11; PCR 8 is still `[VERIFY]`. Those PCRs would
  turn every routine update into a recovery event. A custom list is allowed with a warning.
- When Secure Boot is off, `secure-boot` mode refuses to seal unless the operator explicitly allows
  it, because binding to "Secure Boot disabled" proves very little.
- *Amendment A:* D10 proposes ranking a signed policy (`signed-uki`, `pcrlock`) above `secure-boot`.
  Under D10, raw PCR 7 becomes the fallback for hosts without a UKI PCR signature or a pcrlock
  policy.

*Why:* PCR 7 changes rarely (Secure Boot toggled, db/dbx/KEK/PK updated, a boot chain signed by a
different authority) and is the selection other unattended-unlock tools default to, per the
systemd-cryptenroll PCR table ([S2]; also BitLocker's choice). **What it does not give** (Technical
risks below): protection against root on the running, correctly booted host, and against a
different OS image signed under the **same** authority chain.

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
- `pcr_policy: none` installs are offered a slot by default at `init` (it covers TPM loss) and can
  skip it with `--no-recovery-slot`; it is not mandatory, which keeps existing installs working
  unchanged (Decision 3).
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
secure-boot` therefore prints this and offers `admin encryption rotate` (ADR-010 DEK sweep)
interactively, default yes on a TTY, never silently; `--no-dek-rotate` skips it (Decision 6). The
runbook recommends the sweep for installs whose old backups are not under the same protection. The same rule applies after rotating a recovery code. General statement: **a DEK is
only as protected as the weakest wrap of it that was ever written.**

## Amendment A (2026-10-27): signed PCR policy, update and recovery flow, claims

Session RD-TIER-ADR117-1, against origin/main `6144d535f`. Status: **Proposed**. Andrei has not
approved it (asks listed in the session report). It changes no code. The step-by-step operator
procedures are in [design/tpm-signed-pcr-policy.md](design/tpm-signed-pcr-policy.md).

### Sources read for this amendment

These sources were read on 2026-10-27. A claim below that cites none of them still carries
`[VERIFY]`.

| Tag | Source |
|---|---|
| [S1] | Flatcar, "Setting up LUKS disk encryption", <https://www.flatcar.org/docs/latest/security/encryption/luks/> |
| [S2] | systemd-cryptenroll(1), <https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html> |
| [S3] | systemd-measure(1), <https://www.freedesktop.org/software/systemd/man/latest/systemd-measure.html> |
| [S4] | systemd-pcrlock(8), <https://www.freedesktop.org/software/systemd/man/latest/systemd-pcrlock.html> |
| [S5] | systemd.io, "TPM2 PCR Measurements Made by systemd", <https://systemd.io/TPM2_PCR_MEASUREMENTS/> |

**What [S1] documents about raw PCR binding.** Flatcar says that binding a secret against the full
TPM PCR state "only works realible [sic] when auto updates are disabled". It says you "have to
prevent locking yourself out by removing the PCR binding before updating", and warns that "you
might easily get locked out if you don't enroll a passphrase". About PCR 7 alone it says the
binding "is probably not so brittle but doesn't offer much protection anyway". Flatcar's GRUB
measures configuration that changes with every update, and so on Flatcar raw PCRs force a choice:
give up auto-update, or open an unbound window at every update. ADR-117's own `secure-boot` mode
(D2) inherits the "not much protection" half of that statement, which is why D10 ranks it last
among the bound modes.

### D10. Prefer a signed (authorized) PCR policy over raw PCR values

Proposed modes for `key_provider.tpm.pcr_policy`, in order of preference:

| Mode | TPM policy on the sealed object | Who decides which boot states unseal |
|---|---|---|
| `signed-uki` (preferred) | PolicyAuthorize against the UKI PCR public key, over PCR 11 | The holder of the private key that signs UKI PCR 11 predictions (systemd-measure / ukify, [S3]) |
| `pcrlock` (alternative) | PolicyAuthorizeNV on the host's systemd-pcrlock NV index ([S4]) | Whoever can update that NV index on the host (see D10.3) |
| `secure-boot` (fallback, D2) | PolicyPCR over PCR 7 | Nobody after sealing. The value at seal time is fixed in the object |
| `custom` | PolicyPCR over an explicit list | As above. A list that includes 0, 2 or 4 gets a warning (D10.4) |
| `none` | no policy (today) | n/a |

1. **`signed-uki`.** systemd-measure precalculates the PCR 11 values that a systemd-stub UKI
   produces at each boot phase and signs them. The signature ships in the UKI's `.pcrsig` section
   and the public key in `.pcrpkey`. A TPM2 PolicyAuthorize assertion accepts any PolicyPCR digest
   the key has signed ([S3]). systemd-cryptenroll describes the effect as binding to "any unified
   kernel image for which a PCR signature can be provided", which suits systems that receive
   software updates ([S2]). The sealed object stores only the key's name, so a kernel update that
   ships a new signed UKI unseals with no Keyorix action. Keyorix reads the public key and the
   signature JSON that systemd provides on the booted host [VERIFY exact runtime paths, e.g. under
   `/run/systemd/`]. It tries each signature entry whose `pol` matches the current PCR 11 and the
   bank. If none matches, the class is `boot-state-changed` with the reason "no signature for the
   current PCR 11". By default the signed phases go up to `enter-initrd:leave-initrd:sysinit:ready`
   ([S3]). A Keyorix service normally starts late in boot, so its unseal matches one of the later
   phase entries [VERIFY at which unit ordering point `ready` is extended, and order the unit
   after it]. Restricting the unseal to one phase (a `--policyref`, [S3]) is left for a later
   revision. Note the asymmetry: a key signed for the `enter-initrd` phase only (Example 3 in
   [S3]) would deliberately **not** unseal for Keyorix.
2. **What `signed-uki` gives up, and the Secure Boot condition (D10.5).**
   PCR 11 covers the UKI's sections and the boot-phase strings ([S5]). It does not cover PCR 12
   (kernel command line overrides, add-ons, credentials, [S5]): with Secure Boot off,
   systemd-stub accepts an overridden command line, measures it into PCR 12 (not PCR 11), and a
   genuine, same-authority UKI booted that way still unseals under a PCR-11-only policy. So
   `signed-uki` also binds PCR 7 (Secure Boot state, D2) alongside the PolicyAuthorize term over
   PCR 11 — TPM-enforced, not a software check — and is only offered when Secure Boot is on; a
   host with a signed UKI but Secure Boot off does not get `signed-uki` (D10.5). This reintroduces
   the db/dbx recovery event on Secure Boot certificate changes, the same cost `secure-boot` mode
   already carries, which Amendment A accepts to close the override path. `signed-uki+pcr7` is the
   default, not deferred. The PCR 12 gap itself is closed by this Secure Boot condition rather than
   by binding PCR 12 directly (binding PCR 12 would break on every command-line change, including
   legitimate ones).
3. **`pcrlock`.** systemd-pcrlock predicts PCR values from the event log and `.pcrlock` component
   files. Each component may list alternative variants, for example the old and the new kernel.
   It writes the resulting policy into a TPM NV index, and secrets bind to it through
   PolicyAuthorizeNV ([S4]). Keyorix would only **consume** that policy and never write the NV
   index: the host's pcrlock owns it. The page states that the NV index "may be changed … by
   providing an access PIN". That PIN is stored encrypted in `/var/lib/systemd/pcrlock.json`, and an
   optional recovery PIN regains write access when the policy is out of date ([S4]). In practice
   the authority is therefore the host's administrator, not an off-host signer [VERIFY whether
   decrypting the access PIN is itself bound to the current PCR state]. The PCRs it locks by
   default are 0-5, 7, 11 and 13-15 ([S4]). It needs TPM 2.0 library version 1.38 or later ([S4])
   and systemd 255 or later ([S4]).
4. **Raw multi-PCR presets are not offered.** systemd-cryptenroll says it "is typically not
   advisable to use PCRs such as 0 and 2", because PCR 7 already covers their code through
   certificates, and it calls certificate-based validation generally preferable to measurements
   ([S2]). A raw `0,2,4,7` binding breaks on every firmware update (PCR 0) and boot loader update
   (PCR 4) ([S2]), which is the Flatcar failure ([S1]). It stays reachable only through `custom`,
   with a warning that names the PCRs and the updates that move them.
5. **Default (changes Decision 2; resolved 2026-10-28, Andrei).** For new installs: `signed-uki`
   when the host booted a UKI with a PCR signature and public key **and Secure Boot is on**
   (D10.2); else `pcrlock` when an initialised pcrlock policy exists; else `secure-boot` when
   Secure Boot is on; else `none` with a posture note. A host with a signed UKI but Secure Boot
   off does not get `signed-uki` — it falls through to `pcrlock` or `secure-boot` by the same
   rule, same as any other host without it. Existing installs keep their mode. Every mode other
   than `none` requires the recovery slot (D3, unchanged).

#### Comparison: raw PCR set, PCR 7 only, signed policy

The TPM mechanics follow [S2] to [S5]. Rows marked [VERIFY] are reasoned from those texts and
still need lab confirmation (D8).

| Aspect | Raw 0, 2, 4, 7 | PCR 7 only (`secure-boot`) | Signed PCR 11+7 (`signed-uki`, D10.2) | `pcrlock` |
|---|---|---|---|---|
| Firmware update | PCR 0 changes: refused, recovery event ([S2]) | Usually no change, unless the update also changes Secure Boot certificates ([S2]) | No effect on PCR 11; same PCR 7 exposure as `secure-boot` (previous column) | `unlock-firmware-code` before the update, then `make-policy` ([S4]) |
| Boot loader or kernel update | PCR 4 changes: refused ([S2]). Flatcar: remove the binding before updating ([S1]) | No change while the same authority signs the new binary [VERIFY] | The new UKI carries its own signature, so it unseals. No Keyorix step | The new kernel is added as a variant and the policy is updated ([S4]) |
| Rollback to an older, still trusted image | Refused: PCR 4 differs | **Unseals**: same authority, same PCR 7 | **Unseals for every UKI ever signed with the key.** systemd-measure documents no revocation ([S3]). Needs a key rotation or dbx/SBAT revocation of the old binary [VERIFY] | Refused once the old variant is dropped and `make-policy` rewrites the NV index (TPM-enforced) [VERIFY] |
| Dual-boot: another OS on the same machine | Its boot loader gives a different PCR 4: refused | **Unseals if that OS is verified by the same authority** (existing risk row) | Refused unless it boots a UKI signed by the same key | Refused when its measurements are not in the locked set [VERIFY] |
| Secure Boot db/dbx/KEK/PK change | PCR 7 changes: refused | PCR 7 changes: refused ([S2]). This is the main recovery trigger | PCR 7 changes: refused, same recovery event as `secure-boot` (D10.2) | `unlock-firmware-config` before the change, then `make-policy` ([S4]) |
| Signing key or pcrlock state lost | n/a | n/a | New UKIs signed with a new key do not unseal: recovery code (D3), then reseal to the new key | Recovery PIN for the NV index ([S4]). If that fails, the Keyorix recovery code |
| Offline attacker: disk or data dir copied, boot chain modified | Refused | Refused for an unsigned or other-authority chain. **Unseals** for a same-authority OS | Refused: no signature from the key refuses an unsigned/other image; Secure Boot off refuses on the PCR 7 term; with Secure Boot on, systemd-stub itself refuses a command-line override, so the genuine UKI cannot be rebooted into a debug shell either | Refused for measurements outside the policy |
| Root on the running, correctly booted OS **can** | Unseal now, read the KEK from process memory, extend a PCR to block unseal until reboot (DoS), run Keyorix `reseal` as the service user | Same | Same | Same, and also re-run `make-policy` to bless new boot states [VERIFY: access-PIN protection, D10.3] |
| Root on the running OS **cannot** | Make the blob unseal on another TPM; reset a PCR without a reboot; change the policy of an existing sealed object | Same | Same, and authorise a new PCR 11 value **if the signing key is kept off the host** | Same as raw, except changing the policy (pcrlock policy is host-owned) |

The bottom two rows are the point of the comparison. **No mode protects against root on the
running host**, because the TPM sees a correct boot and answers. A signed policy moves the trust
from "these exact measurements" to "whatever this key signs". That fixes the update problem and
dual-boot. It makes rollback worse unless signing keys are rotated or old binaries are revoked.

### D11. Planned updates, unplanned refusals and recovery (fail closed)

The full procedures are in the design note. The decisions:

1. **Planned update.** `admin encryption tpm status` predicts whether the next boot unseals: for
   `signed-uki` a signature exists for the PCR 11 the new UKI will produce, for the PCR modes the
   predicted digest matches, and for `pcrlock` the NV policy covers the update. It runs before
   any update that touches firmware, Secure Boot variables, the boot loader or the kernel. Where
   the prediction says "will refuse", the operator either does the host-side step first
   (`pcrlock make-policy`, or a vendor UKI that carries a signature) or confirms that the
   recovery code is at hand. The "suspend for one reboot" mode stays out (Decision 5). A reseal
   **after** the update and reboot is the only Keyorix step, and it uses the recovery code.
2. **Unplanned refusal.** The server refuses to start. It prints the class and, for
   `boot-state-changed`, the PCR diff or the missing signature. It exits non-zero and increments
   the metric if the listener came up (D5, D6). The operator then: (a) treats the refusal as a
   possible incident until the diff is explained (a firmware, dbx or kernel change from a
   known update); (b) if it is explained, runs `admin encryption tpm recover` with the recovery
   code, which reseals the same KEK and writes the audit event; (c) if it is not explained, does
   not recover on that host. They restore onto known-good hardware with the recovery code and
   handle it as a compromise (rotate the recovery code, ADR-010 DEK sweep).
3. **Offline recovery material.** ADR-117 already names two kinds: the recovery code (D3) and the
   PQWRAP escrow slot (Decision 4). The brief also asked for a Shamir path. **ADR-117 as merged
   does not name one**, so this amendment adds it as a custody option for the recovery code. The
   operator may split the 256-bit code K-of-N with the existing Shamir code
   (`internal/crypto/shamir.go`, used by `encryption shamir-split`). The shares are recombined
   only on the offline host during `tpm recover`. The check that a recombination is right must
   come from outside the shares (the #429 lesson in `shamir_provider.go`). Here the slot's GCM tag
   and the `kek_id` check (D4) do that. This option is design only, and it needs Andrei to
   approve it.
4. **Fail closed.** No mode, class or flag falls back to a weaker policy (`signed-uki` to
   `secure-boot` to `none`) or to another provider, beyond the existing `AllowWeakerFallback`
   rules, which stay off by default and audited. A missing signature file, a missing pcrlock NV
   index or an unreadable public key is a refusal, never "seal without policy". Recovery is only
   the explicit, offline, audited command. The server never recovers on its own. The D10.5 chain
   is evaluated once, at `init`; `reseal` and `recover` use the mode recorded in config/the blob,
   never re-detecting it, so a missing input at `reseal`/`recover` time is a refusal under this
   rule rather than a silent downgrade to whatever the chain would now pick.

### D12. Principle: Keyorix never claims to detect a compromised OS

Keyorix makes one of three statements about host integrity, and no others:

1. **It fails closed.** TPM sealing (D2, D10) refuses to release the KEK when the boot state is
   not one the policy accepts. That is a statement about the **boot chain**, checked by the TPM.
   It says nothing about what happened after boot.
2. **It relies on kernel enforcement it does not perform.** IMA appraisal, dm-verity or composefs
   integrity are enforced by the kernel. Keyorix can document that a deployment uses them, and
   under `signed-uki` the verity root hash is bound to PCR 11 if it is carried in the UKI's command
   line section [VERIFY]. It never claims to check them itself.
3. **It proves integrity to a third party by remote attestation.** That is ADR-119 (Keylime as
   verifier, Keyorix as relying party), still Proposed. Until it ships, no Keyorix text uses
   "attested".

#### Claims vs evidence (docs, ENISA, ENS, CRA and investor text)

| Statement | Allowed? | Evidence that must exist |
|---|---|---|
| "A copied data directory does not unseal on another TPM (without the recovery code)." | **Allowed now** | `TestTPMBinding_BlobCopiedToOtherHostDoesNotUnseal` (reference TPM). Add "hardware validation pending" until the D8 lab runs |
| "Keyorix never falls back to a weaker key provider silently." | **Allowed now** | `TestNewKeyProviderFromConfig_WeakFallback_RejectedWithoutOptIn`, `…_RuntimeAuditEvent` |
| "Keyorix refuses to start when the measured boot state is not one its policy accepts, and says why." | Only in future tense ("designed to") until PR A merges | The D5/D10 tests named in the design note §8, green on main |
| "Kernel updates do not need a Keyorix step under a signed policy." | Future tense until built; never for raw PCR modes | `signed-uki` tests plus one lab run on a signed-UKI host |
| "Recovery after a board or TPM loss uses an offline code, and its use is an audited event." | Future tense until PR B merges | `TestTPMRecovery_*`, `TestTPMRecoveryAudit_EventAndStickyPosture` |
| "Sealing to a TPM with a recovery key is established practice; Keyorix applies it to an application KEK with audited recovery." | **Allowed** (it is the "New vs state of the art" wording) | This ADR |
| "Keyorix detects a compromised, rooted or tampered OS." | **Never** | None can exist (D12) |
| "Protects secrets against root on the host" / "tamper-proof" / "unbreakable" | **Never** | Contradicted by the comparison table |
| "Prevents rollback to older software" | **Never** for `signed-uki` or `secure-boot` | Only `pcrlock` with a dropped variant, after a lab run |
| "Survives any update without operator action" | **Never** | Signing-key changes, fTPM resets and db/dbx changes (PCR modes) still need recovery |
| "Remotely attested" / "zero-trust host verification" | Only after ADR-119 ships and the verdict is in the audit record | ADR-119 tests |
| "Compliant with / certified for ENS, CRA, ISO 27001" | **Never** in this form; "maps to control X" with the mapping cited | design-rd-tpm-seal.md §9 mapping, which is still [VERIFY] |
| "Hardware-validated" / "tested on physical TPMs" | Only after the D8 lab runs, naming the machines | Lab report |

### D13. What stays out of this amendment

No code, no CI, no config keys and no measurements. The swtpm CI job (D8) and the lab runs stay
pending: e2e VM and hardware. `signed-uki` and `pcrlock` need a host that boots a systemd-stub
UKI or runs systemd-pcrlock, and neither exists in the lab today [VERIFY]. That is a lab
prerequisite, recorded in the session report.

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
4. A written statement of what each mode (`none`/`secure-boot`/`signed-uki`/`pcrlock`) does
   **not** stop (next section), which is evidence in its own right for an assessor.

This is incremental engineering, not a research result. It should be presented that way in
funding or certification material.

*Amendment A.* Signed PCR policies are also **established, not new**. systemd-cryptenroll binds
LUKS slots to a UKI PCR public key over PCR 11 ([S2]). systemd-measure and ukify produce the
signatures ([S3]), and systemd-pcrlock produces NV-index policies for PolicyAuthorizeNV ([S4]).
What Keyorix would add is narrow: it consumes the host's existing UKI signature or pcrlock policy
for an **application** KEK, rather than for a disk, with the same classified fail-closed refusal
and audited recovery as the PCR modes. It also publishes the comparison and the claims table
(D10, D12) as assessor evidence. Item 4 above already covers all four modes, not only PCR 7.

## Technical risks

| Risk | Effect | Mitigation / status |
|---|---|---|
| Root on the running, correctly booted host | Unseals: PCRs are correct at runtime | **Not addressed by TPM sealing at all**, same as today. Needs remote attestation (a separate R&D item, e.g. Keylime) or an operator factor at boot |
| Another OS signed under the same authority (same distro's live image via shim) | PCR 7 can be identical, so it unseals | Stated limit of `secure-boot`. `signed-uki` (D10.2) refuses it only if the operator's signing key signs the one production UKI and never a shared distro/live-image key — PolicyAuthorize accepts any PCR 11 digest that key has signed (D10.1), so a shared key would not refuse it; this is a key-management requirement, not automatic. `pcrlock`'s per-host NV index is unaffected either way and still refuses it |
| vTPM state copied with the VM image (hypervisor or backup level) | "Stolen VM image" claim fails | Holds only if the vTPM state is not taken with the disk [VERIFY per hypervisor/cloud]. Documented as a limit |
| fTPM reset by a firmware update; board swap | Blob dead | Recovery slot (D3); runbook step "have the recovery code before updating firmware" |
| Recovery code leaked | Anyone with the data dir decrypts anywhere | Shown once, TTY only, rotate command, sticky posture after use; D9 for old copies |
| Recovery code lost and the PCR state changed | Data loss, by design | `init` refuses PCR mode without a confirmed code (re-type check); `status` warns if the slot is missing |
| dbx updates pushed by the OS vendor move PCR 7 unexpectedly | Unplanned recovery events | `status` drift check; documented. A "suspend for one reboot" mode is deferred (Decision 5: not now) |
| go-tpm is pre-1.0 (v0.9.8, 2025-12-29; last commit 2026-10-01; Apache-2.0) | API churn | Pinned; wrapper kept small. The simulator needs cgo (test-only) |
| Discrete-TPM bus interposer (active) | MITM of the session salt | SRK-name pin (D7) detects a swapped parent; a full active attacker on the bus is out of scope |
| Simulator is not hardware | Claims could overreach | D8: lab validation pending; nothing claimed beyond the reference implementation |
| `signed-uki`: rollback to an older signed UKI (Amendment A) | An old, vulnerable kernel signed with the same key still unseals | Stated limit (D10 table). Mitigation outside Keyorix: rotate the signing key per release line, or revoke old binaries through dbx/SBAT [VERIFY]. `pcrlock` is the mode that revokes |
| `signed-uki`: UKI signing key compromised | The attacker signs a PCR 11 value for their own UKI, and it unseals | The key belongs to the OS vendor or the operator's build system, not Keyorix. Recovery: reseal to a new key, then rotate the recovery code and run the DEK sweep (D9) |
| `signed-uki`: PCR 12 not bound (command line overrides, add-ons, credentials, [S5]) | Boot inputs outside the UKI sections are not covered | Stated limit. A combined policy is deferred. Lab check of what systemd-stub accepts under Secure Boot [VERIFY] |
| `pcrlock`: the authority is the host administrator (D10.3) | Root can bless new states for future boots | No change to the root-on-host row (root can unseal anyway). It is a weaker statement than `signed-uki` with an off-host key; documented |
| systemd file formats (`.pcrsig` JSON, `pcrlock.json`) change; systemd-measure is marked experimental ([S3]) | Parsing breaks, so unseal refuses (closed) | Pin the parser to the documented fields; a format mismatch is class `blob-corrupt`-like, never a downgrade. Lab run per supported systemd version [VERIFY] |
| A host without a UKI or pcrlock (most current lab and customer hosts [VERIFY]) | Only `secure-boot` or `none` are available there | D10.5 default chain. `status` reports the mode actually in use and why |

## Decisions (Andrei, 2026-10-23)

Andrei approved this ADR as Proposed and chose the recommended option for each open question
(asks #3667, answered 2026-10-23 21:34). The answers carried no conditions beyond the option
chosen; the obligations below follow from those options and bind the implementation PRs.

1. **Approval.** Approved as Proposed with the recommended answers to the five questions below,
   so the next session may implement PR A and PR B. Status stays Proposed.
2. **Default `pcr_policy` for new installs: `secure-boot` when Secure Boot is on, else `none`
   with a posture note.** *Reason:* PCR 7 binding is the useful default only where Secure Boot
   gives it meaning (D2), and it needs a recovery code to be safe. *Obligations:* `init` under
   `secure-boot` requires a confirmed recovery code (D3); with Secure Boot off it seals with
   `none` and records a posture note; existing installs stay `none` until they opt in.
3. **Recovery slot for `pcr_policy: none` installs: offered by default at init, skippable with
   `--no-recovery-slot`; not mandatory.** *Reason:* it covers board swap, TPM clear and fTPM
   reset, which `none` installs face today with total data loss, without breaking existing
   installs. *Obligations:* skipping must be an explicit flag; `status` warns when no slot
   exists; a PCR policy still requires the slot (D3).
4. **PQWRAP escrow slot complements the recovery code; it does not replace it.** *Reason:* the
   code wraps the KEK, so the same KEK comes back and no audit key transition is needed; the
   escrow slot wraps the DEK to an offline ML-KEM + X25519 key. The code is the simple default;
   the escrow slot is the alternative for organisations with an offline key ceremony.
   *Obligations:* PCR mode must keep working with the code alone when option R ships.
5. **"Suspend PCR policy for one reboot": not now.** *Reason:* recovery plus the `status` drift
   check come first, and the unbound window needs lab data on how often dbx updates move PCR 7.
   *Obligations:* do not build it in phase 1; revisit with lab data.
6. **DEK sweep on entering PCR mode: offered interactively (default yes on a TTY), never silent;
   `--no-dek-rotate` skips it.** *Reason:* old v1 blobs in backups still unseal on the same TPM
   without PCR checks, and `rotate-kek` keeps the same DEK (D9). *Obligations:* `reseal` prints
   the D9 statement whenever the sweep is skipped, and never runs the sweep without the prompt
   or an explicit flag.

## Open questions for Amendment A (NEEDS ANDREI; status stays Proposed)

1. **Approve Amendment A (D10 to D13) as Proposed?** Recommended: yes. PR A of the design note
   then builds `secure-boot` first as already planned and leaves room for `signed-uki` and
   `pcrlock` in the blob v2 `pcr_policy` object. A later PR adds them after a lab host with a
   signed UKI exists.
2. **Default chain for new installs (D10.5, replaces Decision 2):** `signed-uki` → `pcrlock` →
   `secure-boot` → `none`. Recommended: yes. Alternative: keep Decision 2 (`secure-boot` first)
   and make the signed modes opt-in.
3. **Shamir K-of-N custody of the recovery code (D11.3).** Recommended: allow it as an option for
   offline custody, never as the default. It reuses the existing Shamir code, with the
   check kept outside the shares.
