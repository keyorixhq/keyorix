# Threat Model: TPM-sealed KEK (`tpm` key provider)

> Part of [`docs/security/threat-models/`](README.md). Narrows
> [`secret-storage-key-hierarchy.md`](secret-storage-key-hierarchy.md) to the `tpm` provider.
> §3 is what main does today. §4 lists the threats that
> [ADR-117](../../adr-117-tpm-sealed-kek-pcr-policy-recovery.md) (Proposed) would change or
> introduce; those rows are design, not mitigations, until the tests named there exist.

## 1. System context

```mermaid
flowchart LR
    subgraph Host
        SRV[keyorix-server\nKEK() at start]
        BLOB[(wrapped_key_path\nsealed blob JSON)]
        DEK[(dek.key\nDEK wrapped by KEK)]
        DEV[/dev/tpmrm0/]
    end
    subgraph TPM["TPM 2.0 (chip, fTPM or vTPM)"]
        SRK[SRK: ECC-P256, owner hierarchy\nfrom the storage primary seed]
        OBJ[sealed keyed-hash object\nFixedTPM, FixedParent]
    end
    SRV -->|read| BLOB
    SRV -->|CreatePrimary, Load, Unseal| DEV --> SRK --> OBJ
    OBJ -->|KEK over the bus| SRV
    SRV -->|unwrap| DEK
```

## 2. Trust boundaries

| Actor | What they hold | Outcome on main |
|---|---|---|
| Thief of the disk, data dir or a backup archive (no TPM) | blob, `dek.key`, database | Cannot unseal: the blob only loads under the sealing TPM's SRK |
| Root on the running host | the TPM device | **Unseals.** TPM sealing does not defend against this actor |
| Attacker who boots other software on the genuine machine | the TPM, physical access | **Unseals on main** (no PCR policy); ADR-117 D2 narrows this |
| Hypervisor admin, or whoever copies a VM together with its vTPM state | the whole TPM state | Unseals: the TPM moved with the image |
| Passive probe on a discrete TPM's bus | bus traffic | Reads the KEK on main (no parameter encryption) |

## 3. Threat table (main today)

| ID | STRIDE | Description | Mitigation | Evidence link | Residual risk / GAP |
|---|---|---|---|---|---|
| TPMK-1 | Information disclosure | The data dir or a backup is copied to another host and the KEK is unsealed there. | The KEK is sealed under the sealing TPM's SRK with `FixedTPM` and `FixedParent`; another TPM fails to load it, and a failed unseal never re-seals or overwrites. | `TestTPMBinding_BlobCopiedToOtherHostDoesNotUnseal`, `TestTPMSeal_ObjectIsFixedToTPMAndParent`, `internal/crypto/tpm_binding_test.go` | Shown against the reference TPM only; swtpm and physical TPM pending (e2e VM / hardware). |
| TPMK-2 | Information disclosure | The persisted blob file contains the KEK in some encoding. | Only TPM2B public and private areas are stored; no raw, base64 or hex KEK appears. | `TestTPMBinding_DiskBlobDoesNotContainKEK` | None identified. |
| TPMK-3 | Tampering | A modified sealed private area is accepted. | The TPM's integrity check rejects every single-byte flip. | `TestTPMBinding_TamperedPrivateDoesNotUnseal` | None identified. |
| TPMK-4 | Elevation of privilege | A tampered or alternative boot chain on the genuine machine unseals the KEK. | None on main: empty auth policy, password session. The error never claims PCR enforcement. | `TestTPMKeyProvider_DifferentTPMCannotUnseal`, `internal/crypto/tpm_provider.go` | **GAP (design):** no boot-state binding. ADR-117 D2 (PolicyPCR, PCR 7). |
| TPMK-5 | Denial of service | A board swap, a TPM2_Clear or an fTPM reset makes the KEK unrecoverable, and so all data and every backup. | None: there is no off-TPM copy of the KEK. Documented in `docs/edge-deployment.md`. | `TestTPMBinding_BlobCopiedToOtherHostDoesNotUnseal`, `docs/edge-deployment.md` | **GAP (design):** ADR-117 D3 recovery slot. |
| TPMK-6 | Tampering | The blob file is deleted and the provider mints a new KEK over existing data. | Server start refuses earlier when some key files exist but others are missing (strict key-file check). The provider itself mints whenever the blob path is absent. | `TestTPMKeyProvider_SealsThenUnsealsAcrossRestarts`, `internal/startup/validation.go`, `internal/crypto/tpm_provider.go` | **GAP (code):** from code reading, not reproduced; no test pins the refusal for non-server callers. ADR-117 D5 `blob-missing`. |
| TPMK-7 | Information disclosure | A TPM outage silently falls back to a weaker, software-derivable provider. | A weaker fallback is a startup error unless explicitly opted in; a runtime downgrade writes an audit event. | `TestNewKeyProviderFromConfig_WeakFallback_RejectedWithoutOptIn`, `TestNewKeyProviderFromConfig_WeakFallback_RuntimeAuditEvent`, `TestDetectFallbackDowngrade_KMSPrimary_PasswordFallback_Downgrades` | None identified. |
| TPMK-8 | Information disclosure | A probe on a discrete TPM's LPC/SPI bus reads the unseal response. | None: the unseal session is not salted and the response is not encrypted. | `TestTPMKeyProvider_SealsThenUnsealsAcrossRestarts`, `internal/crypto/tpm_provider.go` | **GAP (design):** ADR-117 D7 (salted session, `EncryptOut`, SRK-name pin). |
| TPMK-9 | Information disclosure | Root on the running host asks the TPM to unseal. | Out of scope for sealing; the same TPM unseals for any caller with device access. | `TestTPMKeyProvider_SealsThenUnsealsAcrossRestarts` | **Accepted, stated:** needs remote attestation or an operator factor at boot. Unchanged by ADR-117. |
| TPMK-10 | Information disclosure | A VM image is copied together with its vTPM state and started elsewhere. | None possible in Keyorix: the binding is to the TPM state, which moved. | `TestTPMBinding_BlobCopiedToOtherHostDoesNotUnseal` | **Accepted, stated:** depends on the hypervisor or cloud keeping the vTPM state separate [VERIFY per platform]. |

## 4. Threats ADR-117 would change or introduce (design; not on main)

Not checked by `internal/threatmodelcheck` because no test exists yet. Each row moves into §3
with its test when the implementation lands (design note §8).

| ID | STRIDE | Description | Planned mitigation | Planned test |
|---|---|---|---|---|
| TPMK-P1 | Elevation of privilege | Boot-state change unseals (TPMK-4) | PolicyPCR over PCR 7, `UserWithAuth=false` | TestTPMPCR_MismatchRefusesWithClass, TestTPMPCR_PasswordPathClosed |
| TPMK-P2 | Information disclosure | Recovery code leaked; slot opened anywhere | Code shown once on the TTY, never logged or stored; rotate command; sticky posture after use | TestTPMRecoveryAudit_EventAndStickyPosture |
| TPMK-P3 | Tampering | Attacker replaces the recovery slot with one for their own KEK | `kek_id` check plus a trial unwrap of `dek.key` before any reseal; only denial of service remains | TestTPMRecovery_WrongCodeOrContextChangesNothing |
| TPMK-P4 | Spoofing | An interposer substitutes the SRK so it can learn the session salt | SRK name pinned in the v2 blob; mismatch refused before unseal | TestTPMBoot_SRKNameMismatchRefuses |
| TPMK-P5 | Information disclosure | An old v1 blob (no policy) in a backup bypasses PCR mode on the same TPM | Cannot be revoked; reseal into PCR mode warns and offers the DEK sweep (D9) | none possible; runbook and posture |
| TPMK-P6 | Denial of service | PCR 7 moves after a vendor dbx update; unplanned recovery | `status` drift check with software policy prediction; runbook | TestTPMStatus_PredictedDigestMatchesTrial |
| TPMK-P7 | Repudiation | Recovery used silently | Audit event `encryption.tpm_recovery_used` from the host command; sticky posture | TestTPMRecoveryAudit_EventAndStickyPosture |
| TPMK-P8 | Information disclosure | Same-authority signed OS (same distro's live image) gives the same PCR 7 | Stated limit of `secure-boot`; ADR-117 Amendment A (D10, Proposed): `pcrlock` refuses it via its per-host NV index; `signed-uki` (also PCR 7-bound, D10.2) refuses it only if the operator's signing key signs the production UKI alone, not a key shared with the live image | none; documented |
| TPMK-P9 | Elevation of privilege | `signed-uki`: an older signed UKI (vulnerable kernel) still unseals | Stated limit (ADR-117 D10 table); key rotation or dbx/SBAT revocation outside Keyorix; `pcrlock` revokes | none; documented |
| TPMK-P10 | Tampering | `signed-uki`/`pcrlock` input missing or unparsable leads to sealing without policy | Refusal with the file named; no downgrade (ADR-117 D11.4) | planned with the signed modes |
