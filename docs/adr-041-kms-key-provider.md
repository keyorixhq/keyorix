# ADR-041: KMS-backed KEK provider (KeyProvider Tier 2)

**Status:** Accepted
**Date:** 2026-06-12

## Context

ADR-038 made the KEK source pluggable (`crypto.KeyProvider`: password / file /
env). The Tier-2 follow-on, and a hard requirement for many enterprise / ENS /
CRA deployments, is to keep the **wrapping key in a cloud KMS / HSM** so the key
that protects everything at rest never exists in plaintext on the Keyorix host.
This was deferred because it adds a cloud SDK to the **server** binary (Keyorix
had deliberately kept cloud SDKs in the CLI only); that trade-off is now
explicitly accepted for this provider.

## Decision

Add an **`aws-kms`** key provider using **KMS envelope encryption**.

- The KEK is a random 32-byte key, **wrapped by a KMS key (CMK)**; only the
  *wrapped* blob is stored on disk (`wrapped_key_path`). At startup the provider
  calls **KMS Decrypt** to unwrap it into memory. The CMK never leaves the KMS,
  and a host-disk read yields only ciphertext.
- **First run** generates the KEK, calls **KMS Encrypt**, and persists the wrapped
  blob (0600); **subsequent runs** decrypt the stored blob. This mirrors the
  password provider's ensure-salt-then-derive, with KMS encrypt/decrypt instead of
  PBKDF2.
- Everything below the KEK is unchanged — the KEK still unwraps the on-disk DEK,
  which still encrypts the data. Only the *KEK source* is the KMS.

### Cloud-SDK isolation

`internal/crypto` stays **SDK-free**: it defines a small `KMSClient` interface
(`Encrypt` / `Decrypt`) and the generic `KMSKeyProvider` (the envelope logic). The
AWS KMS SDK is imported only in `internal/crypto/awskms`. GCP KMS / Azure Key Vault
are future backends implementing the same `KMSClient` — no change to the provider
or the data path. Region and credentials come from the standard AWS chain (env,
instance profile, IRSA), never from Keyorix config; `Decrypt` pins the `KeyId` so
the blob is only decryptable by the expected CMK.

### Config

```yaml
storage:
  encryption:
    enabled: true
    dek_path: keys/dek.key
    key_provider:
      type: aws-kms
      kms_key_id: arn:aws:kms:eu-west-1:123456789012:key/abcd-…   # ID, ARN, or alias
      wrapped_key_path: keys/kek.kms                               # the KMS-wrapped KEK
```

`KEYORIX_MASTER_PASSWORD` is **not** required with `aws-kms` (as with file/env);
the server and the `keyorix encryption` CLI start without it.

## Consequences

- **Wrapping key in the HSM.** A compromised Keyorix host disk reveals only the
  KMS-wrapped KEK and the wrapped DEK — neither is usable without the CMK, and the
  CMK is gated by KMS IAM (and KMS audit/CloudTrail).
- **The server binary now links the AWS KMS SDK** (accepted). `internal/crypto` is
  unaffected; non-KMS deployments pay only binary size.
- **Switching providers is a migration**, not automatic: an existing DEK wrapped by
  a password/file KEK is not unwrappable by a fresh KMS KEK. `aws-kms` is for new
  installs (or a deliberate re-wrap). Same caveat as file/env (ADR-038).
- **Startup depends on KMS reachability** — a 30 s timeout bounds the call; if KMS
  or IAM is down, the server fails to start (fail-closed, correct for an
  encryption root of trust).

## Verification

Provider logic is proven against a fake `KMSClient`: first-run generate-and-wrap
persists a *ciphertext* blob (not the raw KEK); a restart unwraps the identical
KEK; a different CMK cannot unwrap; nil-client / empty-path / KMS-encrypt-failure
(no blob persisted) / KMS-decrypt-failure / wrong-size-KEK are all rejected. An
encryption-level round-trip shows a KMS-provider `KeyManager` wraps and unwraps the
DEK end-to-end. The AWS glue (`awskms.New`) is thin and exercised against real KMS
only in a live environment. `make build` + full suite + `go vet` + golangci-lint +
gitleaks green.

## Deferred

GCP KMS and Azure Key Vault backends (same `KMSClient` interface); AWS
`GenerateDataKey` as an optimisation; KMS-key rotation runbook; a re-wrap
("migrate KEK provider") tool so an existing install can move to KMS without a
manual DEK re-encryption.
