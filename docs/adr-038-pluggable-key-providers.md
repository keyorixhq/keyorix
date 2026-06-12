# ADR-038: Pluggable KEK providers

**Status:** Accepted
**Date:** 2026-06-12

## Context

Keyorix uses envelope encryption (ADR-004): a per-process **DEK** (data-encryption
key) encrypts secrets/tokens, and the DEK is stored on disk wrapped by a **KEK**
(key-encryption key). Until now the KEK was *always* derived from
`KEYORIX_MASTER_PASSWORD` via PBKDF2-SHA256 (600 000 iterations) over an on-disk
salt. That single, hard-coded source is a friction point for the deployments the
certification track targets:

- **Managed/HSM-backed keys.** ENS/ENISA and enterprise on-prem buyers frequently
  require the KEK to come from a KMS or hardware module, not a passphrase a human
  types or stores in an env var.
- **Kubernetes-native delivery.** Operators want to mount the KEK from a CSI
  secrets driver, a sealed/SOPS secret, or a KMS sidecar — i.e. supply raw key
  material, not a password.

We need to abstract *where the KEK comes from* without touching the proven DEK
wrapping/data path, and without changing anything for existing deployments.

## Decision

Introduce a `crypto.KeyProvider` interface that sources the 32-byte KEK, selected
by config. Wrapping/unwrapping the DEK with that KEK is unchanged.

```go
type KeyProvider interface {
    KEK() ([]byte, error) // exactly 32 bytes; caller wipes it
    Name() string
}
```

Three providers ship (`internal/crypto`):

- **`password`** (default) — `PasswordKeyProvider`: PBKDF2-SHA256, 600 000
  iterations, over the same on-disk salt. **Byte-for-byte identical** to the
  historical derivation, proven by a test that a fresh password-provider
  `KeyManager` unwraps a DEK created by the legacy code path.
- **`file`** — `FileKeyProvider`: reads raw key material from an operator-set path
  (a mounted CSI/sealed secret, KMS sidecar output). Accepts 32 raw bytes, hex, or
  base64.
- **`env`** — `EnvKeyProvider`: reads the KEK (hex/base64) from a named env var's
  value, for KMS/secret-manager injection.

KMS- and TPM-backed providers are a **Tier-2 follow-up** implementing the same
interface.

### Config

```yaml
storage:
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
    key_provider:
      type: file            # password (default) | file | env
      file_path: /etc/keyorix/kek.key   # type=file
      env_var: KEYORIX_KEK              # type=env (value is hex/base64)
```

Absent / zero value = `password`. `KEYORIX_MASTER_PASSWORD` is required only for
the password provider; with file/env the server and the `keyorix encryption`
CLI start without it.

### Where it plugs in

The `KeyProvider` only *sources* the KEK; it carries no dependency on the cipher
code, avoiding any import cycle. `encryption.Service.Initialize` builds the
provider from config and sets it on the `KeyManager`; `KeyManager.deriveKEK`
returns the provider's KEK (or, when no provider is set — e.g. a direct unit-test
caller — the legacy passphrase+salt derivation). Both `Initialize` and the DEK
rotation paths (`RotateDEKWithSweep`, `RotateDEK`) route through `deriveKEK`, so
the same KEK source is used to wrap a rotated DEK.

## Consequences

- **Zero change for existing deployments.** The default path derives the identical
  KEK and unwraps the existing `dek.key`. No re-encryption, no migration.
- **DEK rotation is unchanged in meaning.** `keyorix encryption rotate` still
  rotates the *DEK* and re-encrypts rows; under file/env it re-wraps the new DEK
  with the externally-managed KEK. Rotating the **KEK itself** for file/env (swap
  the key material, re-wrap the DEK) is an external/operator action and a Tier-2
  concern.
- **Trust model.** `file`/`env` providers consume operator-supplied key material;
  the file path and env var are trusted configuration. The KEK is validated to be
  exactly 32 bytes and wiped after the DEK is unwrapped, as before.

### Note on package location

The backlog placed this in `internal/crypto/`, and that is where the interface and
providers live. The KEK-wrapping machinery remains in `internal/encryption/`
(which now imports `internal/crypto`), keeping providers cipher-independent.

## Verification

- **Backward-compat (load-bearing):** a `PasswordKeyProvider` `KeyManager` unwraps
  a DEK created by the legacy derivation; a wrong passphrase fails the GCM check.
- **Byte-identity:** the provider's KEK equals `PBKDF2(passphrase, salt, 600000,
  32, SHA-256)` for the same salt.
- **File/env round-trips:** init → restart → same DEK; raw/hex/base64 accepted;
  wrong-size and missing material rejected.
- **Rotation under a provider:** rotating the DEK re-wraps with the provider KEK;
  a fresh manager reads the rotated DEK.
- **Service end-to-end:** a file-provider Service encrypts a value that a fresh
  Service over the same files decrypts.

`make build` + full suite + `go vet` green; the existing encryption suite is
unchanged.

## Deferred

KMS providers (AWS KMS / GCP KMS / Azure Key Vault), TPM / OS-keychain, and
Shamir-split KEK (the original ADR-010 "KeyProvider Tier 2" note); a `resolver`
that fronts multiple providers; in-process KEK rotation for file/env; CLI
subcommands to inspect/validate the configured provider.
