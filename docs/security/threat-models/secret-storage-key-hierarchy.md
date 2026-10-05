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

## 3. STRIDE

- **Information disclosure — ciphertext substitution between
  secrets.** AAD binds each ciphertext to `secretID:projectID:version`
  — a ciphertext cannot be transplanted between secrets or projects.
  *Residual*: none identified.
- **Information disclosure — fallback-chain downgrade.** A `Fallbacks`
  chain from a hardware/HSM/cloud-KMS-backed provider to a weaker
  software-derivable one requires explicit `AllowWeakerFallback: true`
  — without it, `crypto.DetectFallbackDowngrade` makes such a chain a
  hard startup error, so a transient KMS/TPM outage cannot silently
  downgrade the deployment's actual security floor with only a log line
  marking the moment.
- **Information disclosure — Shamir threshold-forgery.** A naive
  magic-byte check on Shamir shares is vulnerable to a threshold-1
  attacker forging one more share to reach the reconstruction threshold.
  Closed via an HMAC-SHA256 commitment (`shamir_commitment`) verified
  against the reconstructed secret (`internal/crypto`, `#429`).
- **Information disclosure — Azure KMS wrap context gap.** AWS
  EncryptionContext and GCP AAD let an operator bind a wrapped-DEK blob
  to one specific install; Azure's RSA wrap does not support an
  equivalent. Attempting `kms_encryption_context` against Azure is a
  hard startup error, not a silent downgrade — the gap in Azure's own
  primitive is surfaced loudly rather than papered over.
- **Information disclosure — key material in logs.** Audited across
  every sink — no secret values, key bytes, passphrases, or raw tokens
  are ever logged (see [`../SECURE-CODING.md`](../SECURE-CODING.md) §5).
- **Information disclosure — incomplete key rotation.** `keyorix
  encryption rotate`'s re-encryption sweep is ordered by primary key,
  closing a prior gap where unordered pagination could skip rows and
  report a rotation complete while some secrets remained under the old
  key. Sweep *completeness* (every DEK-encrypted model field has a
  corresponding sweep) is enforced by a structural AST-parsing guard
  (`internal/encryption/sweep_completeness_test.go`), not a
  hand-maintained list — closing the class of gap where a new encrypted
  field is added without updating the rotation sweep.
- **Information disclosure — key material surviving in process memory
  after use.** Three KEK-derived siblings besides the DEK (the master
  KEK itself, the evidence-signing key, the audit-checkpoint key) are
  wiped on graceful shutdown and DEK rotation via a real byte-by-byte
  overwrite, confirmed at the compiler level
  (`runtime.memclrNoHeapPointers`, not eliminated as dead code).
  *Residual, stated honestly, not fixed*: `KEYORIX_MASTER_PASSWORD`
  cannot be wiped (string-shaped from `os.Getenv` onward, and Go strings
  cannot be zeroed once created) — the *sourcing* half is fixed (ADR-099:
  `--passphrase-fd`/`--passphrase-file`/`--passphrase-stdin` all yield a
  wipeable `[]byte`; the env var is the documented weakest, last-resort
  fallback).
- **Information disclosure — transient in-process plaintext exposure.**
  Every secret-VALUE plaintext accumulates at least three unwiped heap
  copies between decryption and the wire (the `gcm.Open` output, a
  `string()` conversion, and a JSON/protobuf serialization buffer) —
  structural to Go strings' immutability and `encoding/json`'s API, not
  a missed call site. **Not fixed; recorded as an open design gap**, not
  a code defect — closing it would mean threading `[]byte`-only
  plaintext through the entire read path.

## 4. Residual risks, stated honestly

Both items above marked "not fixed" are carried forward here rather than
re-litigated, matching `../threat-model.md` §6's own framing: the
transient in-process exposure and the `KEYORIX_MASTER_PASSWORD` wipe gap
are structural, acknowledged, and not claimed as closed.
