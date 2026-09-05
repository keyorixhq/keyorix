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

## Addendum (2026-06-12): GCP KMS backend

A second backend, **`gcp-kms`**, ships behind the same `KMSClient` interface
(`internal/crypto/gcpkms`, the only place the GCP KMS SDK is imported). It uses the
identical envelope flow and the generic `KMSKeyProvider` — no change to the
provider logic or the data path. `kms_key_id` holds the GCP crypto-key resource
name (`projects/P/locations/L/keyRings/R/cryptoKeys/K`); credentials come from
Application Default Credentials. GCP KMS decrypts with the *named* key, so the key
is inherently pinned (the ciphertext cannot select a different key — the same
property AWS gets via explicit `KeyId` pinning). Keyorix now offers AWS **or** GCP
KMS for the wrapping key.

## Addendum (2026-06-12): Azure Key Vault backend

A third backend, **`azure-kms`**, ships behind the same `KMSClient` interface
(`internal/crypto/azurekms`, the only place the Azure Key Vault SDK is imported).
It uses the identical envelope flow and the generic `KMSKeyProvider` — no change to
the provider logic or the data path. The KEK is wrapped/unwrapped with the vault
key's `wrapKey`/`unwrapKey` operations (RSA-OAEP-256) rather than encrypt/decrypt,
but the `Encrypt`/`Decrypt` interface is unchanged. `kms_key_id` holds the Key
Vault **key identifier URL**
(`https://{vault}.vault.azure.net/keys/{name}[/{version}]`; an omitted version uses
the key's current version); credentials come from `DefaultAzureCredential` (env,
managed identity, workload identity). Keyorix now offers AWS, GCP, **or** Azure for
the wrapping key.

## Addendum (2026-07-03): Azure key-version pinning (#346)

Unlike AWS/GCP, an Azure Key Vault wrap/unwrap operation targets a specific key
*version*, and an unversioned `kms_key_id` (the form described above) resolves to
whatever version is "current" **at call time**. Because `KMSKeyProvider.KEK()`
calls `Decrypt` with that same unversioned identifier on every server startup,
routine Key Vault key rotation — no attacker involved — would silently change
which version "current" resolves to between the wrap (first run) and a later
unwrap (any subsequent restart), and the new version cannot unwrap ciphertext
produced by the old one: total, self-inflicted master-DEK-unavailability.
`internal/crypto/azurekms.Encrypt` now captures the exact key version Key Vault
actually used (from the response `KID`, which is always fully versioned, even for
an unversioned request) and embeds it in the returned wrapped-key blob behind a
package-local magic prefix; `Decrypt` recognizes that prefix and targets the
pinned version instead of "current", making newly-wrapped KEKs immune to
rotation. Ciphertext wrapped before this change (no prefix) is unaffected and
still decrypts via the old "current"/configured-version resolution — a config
already pinned to an explicit version, or freshly re-wrapped data, is unaffected
either way.

## Addendum (2026-06-12): KEK-provider migration tool

Switching providers used to be a manual DEK re-encryption (see Consequences). It is
now a single command: **`keyorix encryption migrate-provider --to-type … --confirm`**
**re-wraps the DEK under a KEK from the target provider without re-encrypting any
data.** Because the DEK is unchanged — only the key that *wraps* it on disk changes —
the operation is fast and takes no database lock, unlike `encryption rotate`
(ADR-010), which generates a new DEK and re-encrypts every row.

Flow: open the on-disk DEK with the **current** provider (from config); build the
**target** provider from the `--to-*` flags; back up the current wrapped DEK; re-wrap
the DEK under the target KEK and atomically replace it (write-pending-then-rename);
then **verify** a fresh service on the target config round-trips a probe value and, on
any mismatch, **restore the backup** and abort. The target provider's own key
material (a fresh salt for `password`, the KMS-wrapped KEK blob for the `*-kms`
providers) is persisted before the DEK file is touched, so a failure leaves the
active DEK intact. After success the operator updates
`storage.encryption.key_provider` to the target before the next restart (the command
prints the exact block). Migrating *to* `password` reads the new passphrase from
`KEYORIX_NEW_MASTER_PASSWORD`; this also doubles as a master-passphrase rotation
(same salt, new passphrase) with no data re-encryption.

The re-wrap core (`KeyManager.RewrapDEK`) and the provider builder
(`encryption.NewKeyProviderFromConfig`, shared with service startup) carry no cloud
dependency. Verified by unit tests (DEK preserved across re-wrap; the new provider
unwraps it; the old provider no longer does; a failing provider leaves the active DEK
intact) and an end-to-end CLI test (password → env migration round-trips a secret and
keeps a backup).

### Crash-durable key writes (hardening, 2026-06-12)

Every write of unrecoverable key material — the wrapped DEK (first run, rotation,
migration), the KMS-wrapped KEK blob, and the KEK salt — goes through
`securefiles.SecureWriteFileSync`, which `fsync`s the file before returning, and any
subsequent `rename` is followed by `securefiles.SyncDir` to flush the directory
entry. This closes a durability gap surfaced by an internal audit: `os.WriteFile`
leaves bytes in the page cache, so a power failure after the call returned (and
after the operator retired the old KEK, which `migrate-provider` explicitly invites)
could lose the new wrapped DEK while the old wrapping key is gone — orphaning all
ciphertext irreversibly. The migration backup copy is fsync'd for the same reason
(it is the rollback target). The standard write-temp → `fsync(file)` → `rename` →
`fsync(dir)` pattern now holds on every key-material path; the data path is
unchanged.

## Addendum (2026-09-05): encryption-context tenant binding — AWS/GCP have it, Azure cannot

`storage.encryption.key_provider.kms_encryption_context` (`kms_encryption_context`
in config) binds the wrapped KEK to an install: AWS passes it as the KMS
`EncryptionContext`, GCP as Additional Authenticated Data, on both wrap and unwrap.
If a different install's Keyorix server shares the same CMK/crypto-key (the same
IAM/service-account boundary reaching one key across multiple installs — not a
recommended topology, but not one anything else in this ADR prevents either) and
that install's own wrapped KEK blob is somehow presented to this install's
`Decrypt` call, the context mismatch makes decryption fail outright. An optional,
loudly-logged `kms_allow_context_fallback` supports migrating an existing
(pre-binding) install onto a newly configured context without lockout — see the
`KMSEncryptionContext`/`KMSAllowContextFallback` doc comments in
`internal/config/config.go` for the full mechanics.

**This binding has no Azure Key Vault equivalent, and cannot be added:** Key Vault
wrap/unwrap uses RSA-OAEP, which has no additional-authenticated-data input at
all — there is no field to bind an install identity into. Setting
`kms_encryption_context` for an `azure-kms` install is therefore a hard startup
error (not a silent no-op), so a misconfiguration is caught immediately rather than
producing a false sense of binding.

**What Azure has instead is a different mechanism solving a different problem.**
The key-version pinning above (2026-07-03 addendum) embeds the wrap-time key
version in the blob and verifies it (via an HMAC over the version and the
ciphertext/plaintext) on unwrap — this catches the blob being corrupted or rewritten
independent of the data it travels with, and protects against silent Key Vault
key-rotation lockout. It does **not** bind install identity: a wrapped-KEK blob
honestly produced by a *different* install sharing the same Key Vault key carries
its own internally-consistent version and HMAC, and unwraps cleanly for whichever
install presents it. AWS has a direct regression test for the cross-install case
this binding prevents; Azure has none, because there is nothing to test — the
property doesn't exist there.

**Operational consequence for Azure deployments:** the only real control against
cross-install KEK exposure is topology — never point two Keyorix installs'
`kms_key_id` at the same Key Vault key. This is worth stating plainly to anyone
evaluating or operating an Azure-KMS deployment rather than leaving it to be
discovered independently: AWS/GCP customers get a cryptographic backstop against a
shared-key misconfiguration; Azure customers do not, and must rely on getting the
one-key-per-install topology right in the first place.

(Traced during the 2026-09-05 implementation-asymmetry scan,
`keyorix-private/adversarial-review/IMPLEMENTATION-ASYMMETRY-SCAN-2026-09-05.md`
finding F5 — documentation only, no code change: the RSA-OAEP limitation is a
platform constraint the code already handles correctly (fail-closed config
validation), not a defect to fix.)

## Deferred

AWS `GenerateDataKey` as an optimisation; KMS-key rotation runbook (rotating the CMK
itself within the cloud KMS).
