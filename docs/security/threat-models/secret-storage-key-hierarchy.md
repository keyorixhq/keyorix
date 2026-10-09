# Threat Model: Secret Storage and Key Hierarchy

> Part of [`docs/security/threat-models/`](README.md). Derived from
> [`../architecture.md`](../architecture.md) §1-2 and
> [`../threat-model.md`](../threat-model.md) §2 (Assets) and §5.1
> (insider threat / host-root). This is the component most buyers and
> auditors scrutinize first — where the product's core confidentiality
> promise either holds or doesn't.

## 1. System context

Envelope encryption: every secret value is AES-256-GCM encrypted under a
per-install Data Encryption Key (DEK); the DEK is wrapped by a Key
Encryption Key (KEK) that can come from eight different sources. The
single most important fact to model here: **where the KEK lives
determines what host root can and cannot do.**

```mermaid
flowchart TB
    subgraph Client-facing
        REQ[Secret read/write\n(via core.Authorize)]
    end

    subgraph KeyHierarchy["Key hierarchy"]
        KEKSRC{{"KEK source\n(key_provider.type)"}}
        PW[password: PBKDF2-SHA256\n600k iterations]
        FILE[file: raw key material]
        ENVK[env: var value]
        EXEC[exec: operator command stdout]
        SHAMIR["shamir: K-of-N reconstruction\n+ HMAC commitment"]
        TPM[tpm: sealed to host TPM 2.0]
        KMS[aws/gcp/azure-kms:\nenvelope-wrapped by cloud KMS/HSM]
        KEK[("KEK\n(never persisted)")]
        DEK[("DEK\n(wrapped by KEK, on disk)")]
    end

    CIPHER[("secret ciphertext\nAES-256-GCM, AAD-bound\nto secretID:projectID:version")]

    REQ --> KEKSRC
    KEKSRC --> PW & FILE & ENVK & EXEC & SHAMIR & TPM & KMS
    PW & FILE & ENVK & EXEC & SHAMIR & TPM & KMS --> KEK
    KEK -->|unwraps| DEK
    DEK -->|encrypts/decrypts| CIPHER
```

## 2. Trust boundaries

| Actor | Local file-KEK install | KMS/HSM/TPM-backed install |
|---|---|---|
| Host root | **Has everything** — ciphertext, wrapped DEK, and KEK-derivation material are all local. No application-layer control changes this. | Can read ciphertext but **cannot unwrap secrets** without also compromising the external KMS/HSM boundary |
| DB-only actor (no host access) | Has ciphertext and the wrapped DEK, not the KEK-derivation material (e.g. the master passphrase) — cannot decrypt alone | Same |
| Network attacker (no credentials, no host access) | Cannot reach key material at all — there is no network path to the KEK | Same |

This is stated plainly rather than implied, per
`docs/design-b2-recover-admin.md` §1: *"this recovery key does not
protect your secrets from root — it protects your admin account from
anyone who is not you."*

## 3. Threat table

| ID | STRIDE | Description | Mitigation | Evidence link | Residual risk / GAP |
|---|---|---|---|---|---|
| KEY-1 | Tampering | A ciphertext from one secret/project/version is transplanted onto another, passing decryption as if it were the original. | AAD binds each ciphertext to `secretID:projectID:version` — a ciphertext cannot be transplanted. | `../architecture.md` §1 | None identified. |
| KEY-2 | Information disclosure | A transient KMS/TPM outage silently falls back to a weaker, software-derivable key source, downgrading the deployment's real security floor. | A `Fallbacks` chain to a weaker provider requires explicit `AllowWeakerFallback: true`; without it, `crypto.DetectFallbackDowngrade` makes such a chain a hard startup error. | `../architecture.md` §1 | None identified. |
| KEY-3 | Tampering | A threshold-1 attacker forges one additional Shamir share to reach the reconstruction threshold. | HMAC-SHA256 commitment (`shamir_commitment`) verified against the reconstructed secret. | `internal/crypto`, `#429` | None identified. |
| KEY-4 | Information disclosure | A wrapped-DEK blob is not bound to a specific install under a KMS mode that doesn't support a binding context (Azure's RSA wrap), allowing cross-install blob reuse. | Attempting `kms_encryption_context` against Azure is a hard startup error, not a silent downgrade — the primitive's own limitation is surfaced loudly. | `../architecture.md` §1 | None identified for Keyorix's handling; the underlying Azure primitive limitation itself is out of Keyorix's control. |
| KEY-5 | Information disclosure | Key material (secret values, key bytes, passphrases, raw tokens) is written to a log sink. | Audited across every sink — none of the above is ever logged. | [`../SECURE-CODING.md`](../SECURE-CODING.md) §5 | None identified. |
| KEY-6 | Information disclosure | A key-rotation sweep silently skips rows (unordered pagination) or omits a newly-added encrypted field, leaving some secrets under the old key while reporting rotation complete. | Sweep ordered by primary key; sweep *completeness* enforced by a structural AST-parsing guard, not a hand-maintained list. | `internal/encryption/sweep_completeness_test.go`; ADR-010 | None identified. |
| KEY-7 | Information disclosure | Key-derived material (KEK, evidence-signing key, audit-checkpoint key) survives in process memory after it's no longer needed, recoverable by a later memory capture. | Wiped on graceful shutdown and DEK rotation via a real byte-by-byte overwrite, confirmed at the compiler level (`runtime.memclrNoHeapPointers`, not eliminated as dead code). | `security-review-2026-09.md` "Memory zeroization" | **Open, stated honestly.** `KEYORIX_MASTER_PASSWORD` itself cannot be wiped (string-shaped from `os.Getenv`, and Go strings can't be zeroed once created). The *sourcing* half is fixed (ADR-099 gives a wipeable `[]byte` alternative); the env var remains the documented weakest, last-resort fallback. |
| KEY-8 | Information disclosure | Secret-value plaintext accumulates unwiped heap copies between decryption and the wire. | None — structural to Go strings' immutability and `encoding/json`'s API, not a missed call site. | `../threat-model.md` §6 | **Open design gap, not a code defect.** At least three unwiped copies per read (the `gcm.Open` output, a `string()` conversion, a JSON/protobuf buffer). Closing it would mean threading `[]byte`-only plaintext through the entire read path — not attempted. |

## 4. Residual risks, stated honestly

Both items above marked "not fixed" are carried forward here rather than
re-litigated, matching `../threat-model.md` §6's own framing: the
transient in-process exposure and the `KEYORIX_MASTER_PASSWORD` wipe gap
are structural, acknowledged, and not claimed as closed.
