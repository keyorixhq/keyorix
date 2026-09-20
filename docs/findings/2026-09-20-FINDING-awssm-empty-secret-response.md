# FINDING: read-through connectors return success with an empty secret value

**Date:** 2026-09-20
**Component:** `internal/connect/awssm.go` (`AWSSecretsManagerConnector.GetSecret`),
`internal/connect/azurekv.go` (`AzureKeyVaultConnector.GetSecret`).
**Status:** **Fixed**, same PR. Proving tests: `FuzzAWSSMConnectorResponse`
(`internal/connect/awssm_response_fuzz_test.go`, crasher `09de4b520b95a429`
committed as a seed) and `FuzzAzureKVConnectorResponse`
(`internal/connect/azurekv_response_fuzz_test.go`, new seed
`{"value":""}` plus a strengthened oracle).
**Severity: Low.**

## Summary

`FuzzAWSSMConnectorResponse` found that `AWSSecretsManagerConnector.GetSecret`
returns success with an empty string when the AWS Secrets Manager response's
`SecretString` field is present but empty (`{"SecretString":""}`), rather than
treating it the same as "no value at all" (the existing, correct behavior for
a response with neither `SecretString` nor `SecretBinary` set — see
`awssm.go`'s pre-existing `"secret %q has no value"` fallback).

**Root cause:** `SecretString` is a `*string`. The check was
`out.SecretString != nil` — true for a non-nil pointer to `""`, not just a
pointer to real content. `len(out.SecretBinary) > 0` (the binary-field check
right below it) already correctly excluded an empty byte slice; the string
field's check didn't have the analogous guard.

**Discovery detail:** the actual crasher (`09de4b520b95a429`,
`int(200)` / `[]byte("{\"SecretString\":\"\"}0")`) has a trailing `0` byte
after the closing `}`, which is not valid JSON. The fuzz test's own reference
decoder (`encoding/json.Unmarshal`, used only to derive the oracle's expected
outcome, not the code under test) rejects the whole body as malformed and so
treats it as "no value" for the oracle's purposes — while the real AWS SDK's
smithy-go `awsJson1_1` decoder is more lenient and successfully extracts
`SecretString: ""` from the same bytes before the trailing garbage. That
decoder-leniency mismatch is how the fuzzer's mutator reached this input, but
the underlying product defect is decoder-independent: a clean, valid
`{"SecretString":""}` response hits the exact same `out.SecretString != nil`
branch and returns success with `""` regardless of how it was produced.

## Fix

```go
if out.SecretString != nil && *out.SecretString != "" {
    return *out.SecretString, nil
}
```

Red-proof: reverting to the original `out.SecretString != nil` check
reproduces the crasher's exact failure
(`BYPASS: response has no SecretString/SecretBinary field but GetSecret
returned success with value ""`) 1/1; restoring the fix passes. No change was
needed to `FuzzAWSSMConnectorResponse`'s own oracle — its "no value" check
(`hasValue := ... && (ref.SecretString != nil || len(ref.SecretBinary) > 0)`)
only asserts a failure when `!hasValue && err == nil`; the trailing-garbage
decode error already makes `hasValue` false independent of this fix, so the
existing oracle catches the crasher correctly once the connector itself is
fixed.

## Sibling check: Vault, Azure, GCP (per instruction, same investigation)

- **Azure Key Vault (`azurekv.go`) — same defect, fixed here too.**
  `out.Value` is also a `*string`, checked with the identical
  `out.Value == nil` (no empty-string guard). A response body like
  `{"value":""}` reproduces the exact same "success with empty value" bug.
  Fixed identically: `out.Value == nil || *out.Value == ""`. Unlike the AWS
  case, the existing `FuzzAzureKVConnectorResponse` fuzzer's own oracle
  (`hasValue := ... && ref.Value != nil`) has the SAME pointer-only blind
  spot as the connector code — a clean `{"value":""}` seed would pass
  silently either way without also strengthening the oracle. Fixed both:
  `hasValue` now also requires `*ref.Value != ""`, and a new seed
  `f.Add(200, []byte(`{"value":""}`))` was added so this stays covered
  going forward (not a committed crasher artifact — an in-source seed,
  matching this fuzzer's existing convention for its other synthetic
  cases). Red-proofed the same way: reverting to the original checks (both
  the connector's `out.Value == nil` and the oracle's `ref.Value != nil`)
  reproduces the identical failure shape on the new seed; restoring both
  passes.
- **GCP Secret Manager (`gcpsm.go`) — already correct, not touched.**
  `if out.GetPayload() == nil || len(out.GetPayload().GetData()) == 0` — the
  length check already excludes an empty (but non-nil) payload. No change
  needed.
- **Vault (`vault.go`) — different data model, not the same shape.**
  Vault's `GetSecret` returns the secret's entire KV JSON envelope as a
  string (`string(env.Data)` / `string(kv2.Data)`), not a single scalar
  field — Vault secrets are multi-field maps by design, and an EMPTY map
  (`{}`) is a legitimate, if unusual, stored value in Vault's own data
  model (a secret with zero key-value pairs), not a signal that the API
  omitted a value field the way AWS's/Azure's absent-or-empty scalar is.
  `vault.go` already explicitly handles the cases that ARE analogous to
  "no value at all" — `len(env.Data) == 0` (KV v1, malformed/empty
  envelope) and `len(kv2.Data) == 0 || string(kv2.Data) == "null"` (KV v2,
  soft-deleted version). Not changed; noted here so the omission reads as
  considered, not overlooked.

## Can the backend actually store an empty-string secret?

- **AWS Secrets Manager: no — the API itself makes this impossible.**
  `PutSecretValue`'s (and `CreateSecret`'s) `SecretString` parameter is
  documented with `Length Constraints: Minimum length of 1. Maximum length
  of 65536` (https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html).
  A caller that tries to store `SecretString: ""` gets a `ValidationException`
  before the write ever lands — there is no legitimate way for a real,
  compliant AWS Secrets Manager to hand back `{"SecretString":""}` for a
  secret an operator actually created. The only way `GetSecretValue` can
  ever return that shape is a non-compliant/compromised/malfunctioning
  endpoint (or, as found here, a fuzzer) — exactly the class of input this
  connector's hardened-transport layer already exists to be suspicious of.
  So for AWS specifically, this fix cannot reject any secret an operator
  could actually have stored; it only closes a response shape the real API
  contract says is impossible.
- **Azure Key Vault: less certain — the REST API's own schema documents no
  `minLength` on `value`.** `SecretSetParameters.value` is listed as
  `Required: true, Type: string` with no length constraint
  (https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret?view=rest-keyvault-secrets-2025-07-01),
  unlike AWS's explicit minimum. The Azure **portal** UI refuses to create a
  secret with no value, but that is client-side, not a server-side
  guarantee — documented evidence of client libraries needing workarounds
  to push an empty value through their own type-conversion layers (e.g.
  PowerShell's `ConvertTo-SecureString` rejecting `""` and requiring a bare
  `New-Object SecureString` instead:
  https://mbraekman.github.io/2021/11/08/Azure-Key-Vault-Empty-Secrets/)
  suggests the obstacle is tooling, not the Key Vault service itself. So,
  unlike AWS, it is NOT certain an operator can never end up with a
  genuinely empty-valued Key Vault secret.
- **We fail closed on both regardless, and that is still the right call.**
  For AWS, this is moot (the case is unreachable via the real API). For
  Azure, even if an operator could legitimately store `""`, an empty
  string is never a usable credential/config value downstream — a
  consuming application that expects e.g. a password or connection string
  cannot meaningfully act on `""` either way, so surfacing it as an
  explicit `"secret %q has no value"` error (which the caller sees and can
  act on) is strictly safer than silently handing back an empty string a
  caller could mistake for "the secret is intentionally blank" and use as
  a credential. An operator who genuinely needs to store an empty-string
  value in Azure Key Vault for some reason is not a scenario this connector
  needs to support — nothing in Keyorix's own secret model treats "" as a
  meaningful stored value either (CreateSecretRequest's Value is the
  plaintext to encrypt and store; an empty plaintext secret is already an
  unusual, not a normal, state on Keyorix's own side).

## Severity

**Low.** This is a read-path correctness bug, not an authorization or
credential-leak issue — reachable only when the configured connector's own
backend (AWS Secrets Manager / Azure Key Vault) returns a 2xx response
carrying an explicitly-empty (not absent) value for the requested secret. Per
"Can the backend actually store an empty-string secret?" above, for AWS this
is only reachable via a non-compliant/compromised/malfunctioning endpoint —
the real API cannot produce it for anything an operator actually stored; for
Azure it may also be reachable via a genuinely (if unusually) empty-valued
stored secret. Either way, this connector's hardened-transport layer
(redirect refusal, private-IP dialer, response-size cap) already defends
against the more dangerous versions of "a hostile endpoint controls the
response" (credential/data exfiltration, SSRF). The concrete harm of THIS
specific gap is narrower: a caller reading
the secret gets back `""` instead of an explicit "no value" error, which
could be silently treated as a valid (if empty) credential/config value
downstream rather than failing loudly. No credential exposure, no
cross-tenant/cross-account read (unrelated to this connector's existing
confused-deputy account/project pinning), and no write-path impact.
