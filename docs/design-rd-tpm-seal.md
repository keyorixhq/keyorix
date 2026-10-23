# Design: TPM-sealed KEK with PCR policy and off-TPM recovery (RD-TPM-SEAL-1)

Status: **design for decision, no product code.** The decisions are in
[ADR-116](adr-116-tpm-sealed-kek-pcr-policy-recovery.md) (Proposed). Every trust, crypto or
authorization item waits for Andrei's approval of that ADR. Session RD-TPM-SEAL-1, 2026-10-23,
origin/main `760e92e32`.

Inputs read: `internal/crypto/tpm_provider.go`, `tpm_provider_test.go`, `tpm_binding_test.go`,
`keyprovider.go`, `provider_tier.go`, `internal/encryption/key_provider_downgrade.go`,
`internal/encryption/INVARIANTS.md` (INV-ENCRYPTION-27), `internal/startup/validation.go`,
`internal/keyfiles/registry.go`, ADR-038, `docs/edge-deployment.md`,
`docs/design/recovery-options.md`, `docs/design-b2-recover-admin.md`, and, read-only from open
PR #3662, `docs/design/pq-key-wrapping.md` (RD-PQWRAP-1).

Marking rule: a claim about an external standard or product carries **[VERIFY]** unless its text
was read in this session. Behaviour of the TPM itself is stated only as observed in the TCG
reference implementation (the go-tpm-tools simulator), never as "a real chip does X".

## 1. Scope

In: the `tpm` key provider. Optional PCR policy, an off-TPM recovery slot, a fail-closed and
classified unseal, recovery and reseal commands, alerting, a swtpm-based test plan, and docs.

Out: remote attestation (R10, Keylime comparison); signed or authorized PCR policies
(PolicyAuthorize); TPM-backed audit signing; NV-index rollback counters; Windows TPM (TBS).
Where they would plug in is noted in §12.

## 2. What main does, and what a throwaway prototype showed

The prototype was a separate Go module outside the repo (not committed), using go-tpm v0.9.8 and
go-tpm-tools v0.4.10 (the versions in `go.mod`) against the in-process reference TPM. 13 tests,
all green. Behaviour only, no timings:

| Check | Result in the reference TPM |
|---|---|
| Seal with PolicyPCR(SHA-256, PCR 7), same state | unseals |
| Extend PCR 7, then unseal | refused: `TPM_RC_POLICY_FAIL (session 1)`; `errors.Is(err, tpm2.TPMRCPolicyFail)` is true |
| "Reboot" (same seed, PCRs re-measured to the same values) | unseals; a different measurement gives `TPM_RC_POLICY_FAIL` |
| Policy-sealed object (`UserWithAuth=false`), password-session unseal | refused: `TPM_RC_AUTH_UNAVAILABLE` |
| Blob loaded on a TPM with another seed | `Load` fails: `TPM_RC_INTEGRITY (parameter 1)` |
| `TPM2_Clear` (lockout auth), then load the same blob | `Load` fails: `TPM_RC_INTEGRITY` (the same code as another TPM) |
| Recovery slot (HKDF-SHA256 + AES-256-GCM, random nonce) after a PCR change | the right code returns the same KEK; a wrong code or another install context fails; resealing the same KEK to the new state unseals; the old blob stays dead |
| Recovery onto a TPM with another seed (replacement board) | works; the reseal unseals |
| Policy session salted to the SRK, response encryption (`EncryptOut`, AES-128) | unseals |
| Software PolicyPCR digest from PCR values vs TPM trial session (PCR 7; PCR 7+11) | equal |
| `transport.OpenTPM` on a missing path | `stat …: no such file or directory` |
| **Control: main's blob shape** (no policy, password session) after a PCR 7 change | **still unseals**: no boot-state binding on main today |
| Simulator quirk: `Simulator.Reset()` | regenerates the SRK, so a reboot is modelled as close and reopen with the same fixed seed, as the repo's tests already do |

Format facts (not performance): a SHA-256 policy-sealed object marshals to an 80-byte TPM2B public
and a 160-byte TPM2B private. The recovery slot is 97 bytes (4 magic, 1 version, 32 salt, 12 nonce,
32 ciphertext, 16 tag). The recovery code is 52 base32 characters for 256 bits.

## 3. Acceptance criteria (restated honestly)

| Brief | Restated | Evidence now | Still owed |
|---|---|---|---|
| Data dir copied to another host cannot unseal | …cannot unseal **without the recovery code**. With it, recovery onto new hardware is the intended DR path | `TestTPMBinding_BlobCopiedToOtherHostDoesNotUnseal` (main); prototype `TestOtherTPMRefuses` | swtpm and physical TPM (pending e2e VM / hardware) |
| Same host starts | Same TPM, same PCR 7 → starts, no prompt | `TestTPMKeyProvider_SealsThenUnsealsAcrossRestarts` (main); prototype reboot test | same |
| PCR mismatch refuses and recovery works | Refuses with class `boot-state-changed` and a PCR diff; `tpm recover` with the code reseals the **same** KEK; an audit event is written; the posture stays warned until the code is rotated | prototype only | product tests (§8), lab |

Two limits apply to all three: the claims hold against someone holding the data dir (or a disk or
image **without** the TPM). They do not hold against root on the running host, and PCR 7 does not
tell apart two OS images signed under the same authority (ADR-116 Technical risks).

## 4. Sealed blob v2

```json
{
  "format": "keyorix-tpm-seal/v2",
  "public": "<base64 TPM2B_PUBLIC>",
  "private": "<base64 TPM2B_PRIVATE>",
  "parent": {"hierarchy": "owner", "template": "tcg-ecc-p256-srk", "name": "<hex SRK name at seal>"},
  "pcr_policy": {"bank": "sha256", "pcrs": [7], "values_at_seal": {"7": "<hex>"},
                  "policy_digest": "<hex>"},
  "kek_id": "<hex, 16 bytes>",
  "recovery": {"type": "code-v1", "slot": "<base64 97-byte slot>", "created_at": "<RFC 3339>"},
  "sealed_at": "<RFC 3339>"
}
```

- `pcr_policy` is absent for `pcr_policy: none`. `recovery` is absent when no slot exists.
- `kek_id = HKDF-SHA256(KEK, salt "keyorix/tpm/v2/kek-id", info "")[:16]`. It tells a recovered or
  resealed KEK apart from a wrong one before anything is written. It is not secret material
  beyond a 128-bit check value. Final names will follow PQWRAP's string table if that lands first.
- Recovery slot: `"KXTR" ‖ 0x01 ‖ salt[32] ‖ nonce[12] ‖ ct[32] ‖ tag[16]`, key
  `HKDF-SHA256(code, salt, info "keyorix/tpm-recovery/v1/wrap")`, AAD `header ‖ install_id ‖ kek_id`.
  `install_id`: main has no per-install identifier today (searched `internal/`), so init
  generates a random 16-byte id. Whether it lives in the blob header or in the database is
  pinned in commit 2. Binding it to the database is stronger, because it stops a slot being
  transplanted between two installs that share a recovery code.
- **Integrity of the metadata.** The TPM enforces `authPolicy` inside the sealed public area, so
  editing `pcrs` or `policy_digest` only produces `TPM_RC_POLICY_FAIL` (closed). Replacing the slot
  with one an attacker made gives, at worst, a wrong KEK. That fails the `kek_id` check **and** a
  trial unwrap of `dek.key` before reseal (denial of service only; the attacker could delete the
  file anyway).
- Reader: v1 (`{public, private}` only) is accepted for good. An unknown `format` value is refused
  (no guessing).
- Writes go through `securefiles.SecureWriteFileSync` (0600) as now. Once #3607 merges, they take
  part in its key-set manifest and two-phase commit like every other key file.

## 5. Flows

**Init** (`admin encryption tpm init`, or the first `KEK()` on a fresh install, which keeps
today's first-boot behaviour for `pcr_policy: none` only):
1. Open the device (class `tpm-unavailable` on failure). Read the Secure Boot state and PCR 7.
2. With a PCR policy and Secure Boot off: refuse unless `--allow-secure-boot-off`.
3. Generate the KEK and recovery code. Show the code once on the TTY. Ask for it to be typed back
   (or `--recovery-code-out FILE` at 0600 for automation, with a warning).
4. Seal (trial session → digest → Create), build the slot, write v2, then read it back and unseal
   once before reporting success.

**Boot** (`KEK()`):
1. Blob missing: if `dek.key` exists, class `blob-missing`, refuse. Otherwise first boot (as now,
   `none` only; PCR mode needs `init`).
2. Decode (class `blob-corrupt`). Open the device. CreatePrimary and compare the SRK name with
   `parent.name` (refuse on mismatch, before any secret moves). Load (`TPM_RC_INTEGRITY` gives
   `not-this-tpm`).
3. Policy session salted to the SRK, `EncryptOut`, PolicyPCR, Unseal (`TPM_RC_POLICY_FAIL` gives
   `boot-state-changed`; read the PCRs and print the diff against `values_at_seal`).
4. `validateKEK`, check `kek_id`, return. No fallback beyond the existing `AllowWeakerFallback`
   rules.

**Recover** (`admin encryption tpm recover`, an offline host command run as the service user,
like `recover-admin`):
1. Read the code from the TTY (or `--recovery-code-file`). Open the slot. Check `kek_id`.
   Trial-unwrap `dek.key`.
2. Reseal the same KEK to the current TPM and PCR state. Write v2 atomically, keeping the same
   slot.
3. Write the audit event `encryption.tpm_recovery_used` and set the sticky posture flag. Print
   "rotate the recovery code now".
4. A failure at any step changes nothing on disk.

**Reseal** (`admin encryption tpm reseal [--pcr-policy …]`): needs a working unseal now. Used to
change the policy, to move v1 to v2, or to add a slot. Moving into PCR mode prints the D9 warning
(old blobs cannot be revoked) and offers the DEK sweep.

**Rotate the recovery code** (`admin encryption tpm recovery-code rotate`): needs a working
unseal. Writes a new slot and clears the posture flag. Prints the D9 rule for old copies.

**Status** (`admin encryption tpm status [--json]`): device, manufacturer and firmware
(GetCapability), Secure Boot state, sealed vs current PCR values, the predicted policy digest vs
the stored one, slot present yes/no, and the posture flag. It is read-only and never unseals.

## 6. Configuration and CLI surface (future; NOT implemented)

```yaml
storage:
  encryption:
    key_provider:
      type: tpm
      tpm_device: /dev/tpmrm0          # existing
      wrapped_key_path: keys/kek.tpm   # existing
      tpm:
        pcr_policy: secure-boot        # none | secure-boot | custom
        pcrs: [7]                      # only with custom
        allow_secure_boot_off: false
```

Commands: `admin encryption tpm init | status | recover | reseal | recovery-code rotate`. All are
host-local (ADR-108): no HTTP or gRPC route reaches recovery. Each prints what it is about to do,
shows progress for TPM calls, and ends with what changed and what to do next (customer-journey
rule). The config keys go into `internal/config` with the surface-leaf list; that edit touches a
hot file (`config.go`) and goes last in its PR.

## 7. Alerting, audit and posture

- On a boot refusal: one stderr line `SECURITY: tpm key provider: <class>: <message>`, then exit
  non-zero; `keyorix_kek_unseal_failures_total{class}` if the metrics listener came up.
- Audit events: `encryption.tpm_recovery_used`, `encryption.tpm_resealed`,
  `encryption.tpm_recovery_code_rotated`. Each carries the actor, the class or reason, and the PCR
  diff. No key material and no code.
- Posture items (compliance view): "TPM recovery used, code not rotated" (warning, sticky);
  "TPM sealed without PCR policy" (info); "PCR mode without recovery slot" (cannot happen through
  init; flagged if a hand-edited blob shows it).

## 8. Test plan (red first)

Each product commit lands its tests first: red against the code before it, green after
(`~/.claude/scripts/redproof.sh`).

| Test (planned name) | Proves |
|---|---|
| `TestTPMPCR_MismatchRefusesWithClass` | PCR 7 extended → `boot-state-changed`, no key returned, blob unchanged |
| `TestTPMPCR_PasswordPathClosed` | policy-sealed object refuses a password-session unseal |
| `TestTPMPCR_RebootSameChainStarts` | same seed and same measurement → same KEK |
| `TestTPMRecovery_RestoresSameKEKAndReseals` | code → same `kek_id`; resealed blob unseals; old blob refused |
| `TestTPMRecovery_WrongCodeOrContextChangesNothing` | wrong code or install id → error, files byte-identical |
| `TestTPMRecovery_ReplacementTPM` | slot opens on another seed; reseal works there |
| `TestTPMRecovery_AfterClear` | TPM2_Clear → `not-this-tpm` → recovery works |
| `TestTPMBoot_BlobMissingWithDEKRefuses` | no mint when `dek.key` exists (red on main: main mints) |
| `TestTPMBoot_SRKNameMismatchRefuses` | a changed parent is refused before Unseal |
| `TestTPMBlobV1_StillUnseals` / `TestTPMBlobUnknownFormatRefused` | legacy reader; no guessing |
| `TestTPMStatus_PredictedDigestMatchesTrial` | software prediction equals the TPM |
| `FuzzTPMBlobV2Parse` | the parser never panics, and never accepts a v2 without its required fields |
| `TestTPMRecoveryAudit_EventAndStickyPosture` | the recovery command writes the event and the flag; rotate clears it |

**swtpm in CI** (a later `.github` PR): Ubuntu `swtpm` and `swtpm-tools` packages [VERIFY package
names]. Start `swtpm socket --tpm2 --server type=tcp,port=… --ctrl type=tcp,port=… --flags
not-need-init,startup-clear` [VERIFY flags], and run the provider through a TCP transport in a
build-tagged test (`//go:build tpm_swtpm`). That exercises a TPM in a separate process with
persistent state across restarts (the simulator cannot), and TPM2_Clear through the control
channel. The real `/dev/tpmrm0` open path needs `swtpm chardev --vtpm-proxy` and the
`tpm_vtpm_proxy` kernel module [VERIFY on runners]: the e2e VM first, then CI if the runner
allows it.

**Lab** (pending e2e VM; pending hardware): (1) e2e VM with swtpm: the three acceptance cases end
to end through the real binary. (2) One physical TPM 2.0 machine with Secure Boot on: seal,
toggle a db/dbx change (or Secure Boot off), confirm `boot-state-changed`, recover, reseal; copy
the data dir to a second machine, confirm `not-this-tpm`. (3) Repeat once on a cloud vTPM
[VERIFY which provider is available].

## 9. Field and standard mapping (all [VERIFY]; none of these texts were read this session)

| Source | Item | How this design relates |
|---|---|---|
| TCG TPM 2.0 Library, Part 3 | TPM2_PolicyPCR, TPM2_Create/Load/Unseal, sessions with salt and parameter encryption | Mechanisms used. The PolicyPCR digest formula was checked by experiment (software prediction = TPM trial digest), not by reading the text |
| TCG PC Client Platform Firmware Profile | PCR 7 = Secure Boot policy and authorities | Default selection [VERIFY] |
| NIST SP 800-57 Part 1 | key backup and recovery, compromise handling | Recovery slot, rotation after use, D9 [VERIFY] |
| NIST SP 800-56C Rev. 2 / RFC 5869 | HKDF two-step derivation | Slot wrap key and `kek_id` (same as PQWRAP §4) [VERIFY] |
| NIST SP 800-38D | AES-GCM, nonce rules | Random 96-bit nonce via `NewGCMWithRandomNonce` [VERIFY] |
| EU CRA, Annex I | protect confidentiality of stored data | At-rest key protection evidence [VERIFY wording] |
| ENS (RD 311/2022) op.exp.11 | protection of cryptographic keys | Hardware-bound KEK plus custody of the recovery code; already the control ADR-051 maps for keys [VERIFY] |
| ISO/IEC 27001:2022 A.8.24 | use of cryptography, key management | Same [VERIFY] |
| BSI APP.bd.6 (repo mapping) | master key protection and rotation | Complements the existing A17 row [VERIFY] |

## 10. Implementation plan for the next session (after ADR approval)

One PR per session (COMMON-RULES). Size target about 400 lines per PR, so two PRs:

**PR A: provider hardening (`internal/crypto`, `internal/encryption`, tests)**
1. `item 1: tests: red tests for blob-missing, classes, v1 legacy and unknown format`, then the
   fix: refuse to mint when `dek.key` exists (provider gets the DEK path or a "has data" probe);
   error classes with `errors.Is` on the TPM RCs.
2. `item 2: blob v2 reader/writer + kek_id + SRK-name pin` with `FuzzTPMBlobV2Parse` (target
   fragment under `scripts/fuzzing/targets.d/`).
3. `item 3: PCR policy sealing + salted, encrypted unseal session` behind
   `key_provider.tpm.pcr_policy` (config keys last; hot file).
4. `item 4: recovery slot (seal-side only) + recovery package` with its tests.
5. INVARIANTS fragments: `internal/encryption/INVARIANTS.d/INV-ENCRYPTION-tpm-pcr-policy-closed.md`,
   `INV-ENCRYPTION-tpm-no-mint-over-data.md` and `INV-ENCRYPTION-tpm-recovery-same-kek.md`;
   `docs/adr-conformance-enforced.d/` rows for D2, D3 and D5; a changelog fragment (Security).

**PR B: operator surface (`server/admin`, docs)**
6. `admin encryption tpm init | status | recover | reseal | recovery-code rotate`, with CLI
   journey tests (definition of done: driven like a user).
7. Audit events, metric, posture items, and the runbook (`docs/operator/tpm-recovery-runbook.md`).
   `docs/CONFIGURATION.md` and `docs/edge-deployment.md` updates, threat-model rows moved from GAP
   to mitigated with their tests.

**Later, separate sessions:** the swtpm CI job (`.github`), lab runs on the e2e VM and on
hardware, PQWRAP escrow slot integration once #3662's option R ships.

## 11. Open decisions (NEEDS ANDREI), with recommendations

1. **Default `pcr_policy` for new TPM installs.** Recommend `secure-boot` when Secure Boot is on
   (init then requires the recovery code); otherwise `none` with a posture note. Existing installs
   stay `none`.
2. **Recovery slot without a PCR policy.** Recommend: offered by default at init, skippable with
   `--no-recovery-slot` (it covers board loss, which `none` installs face too).
3. **"Suspend for one reboot" before planned updates** (seal without policy for one boot, then
   reseal; BitLocker-like [VERIFY]). Recommend: not now. The recovery flow plus `status` drift
   checks first; revisit after lab data on how often dbx updates move PCR 7.
4. **PQWRAP escrow slot vs recovery code.** Recommend: complements, not replaces. The code is the
   simple default for SMEs; the hybrid escrow slot is the option for organisations with an
   offline key ceremony.
5. **Automatic DEK sweep when entering PCR mode.** Recommend: offer it interactively (default yes
   on a TTY), never silently; `--no-dek-rotate` to skip, with D9 printed.

## 12. Not in this design

Root on the running host (needs attestation, R10), signed PCR policies (PolicyAuthorize; would
cut recovery events after kernel updates), anti-rollback of the data dir with a TPM NV counter,
TPM-held audit signing keys, and Windows support (`transport.OpenTPM` path).
