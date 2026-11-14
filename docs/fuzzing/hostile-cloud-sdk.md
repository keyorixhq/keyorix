# Hostile-server fuzzing of the cloud SDKs (SK1)

Durable in-repo record of the SK1 campaign. The full report (findings table, per-oracle
"what it does NOT verify", reachability ranking, talk material) was delivered separately;
this note is the lasting pointer for anyone touching these harnesses.

## What it is

Hostile-**server** fuzzing: Keyorix is the client; the cloud endpoint it talks to is
attacker-influenced (an operator-set S3/SMTP host, a MITM'd KMS/Key-Vault endpoint). Each
target drives the REAL SDK client — as the Keyorix caller constructs it, through the SDK's
own documented endpoint/transport override — against a loopback server whose replies are
fuzzer-controlled (grammar-aware mutated bodies: JSON, XML, SMTP dialogue; wrong
content-types; truncated/huge/nested bodies; 3xx redirects).

## Targets (`fuzz/thirdparty/`)

| Package | Fuzz fn | SDK / protocol | Keyorix caller |
|---------|---------|----------------|----------------|
| `smtp` | `FuzzSMTPDialogue` | wneessen/go-mail / SMTP | `internal/delivery/smtp.go`, `internal/notifychan/email.go` |
| `awskms` | `FuzzKMSResponse` | aws-sdk-go-v2/kms / awsJson1_1 | `internal/crypto/awskms` |
| `awss3` | `FuzzS3PutObjectResponse` | aws-sdk-go-v2/s3 / REST-XML | `internal/evidencesink` |
| `azurekeys` | `FuzzAzureKeysResponse` | azure-sdk-for-go keyvault/azkeys / JSON | `internal/crypto/azurekms` |

Shared oracle harness: `fuzz/thirdparty/internal/cloudfuzz` (panic/time guard, goroutine/fd
leak ceiling, HTTP-status clamp, sent-credential-in-error scanner — the scanner is
red/green-proven in `cloudfuzz_test.go`).

## Explicitly NOT duplicated

`internal/connect` already fuzzes the SAME SDKs through `BaseEndpoint`/httptest for the
**federated-secret GetSecret** path (`FuzzAWSSMConnectorResponse`,
`FuzzAzureKVConnectorResponse`, `FuzzGCPSMConnectorResponse`, `FuzzVaultConnectorResponse`).
SK1 covers only the **disjoint** surface: KMS wrap/unwrap/describe, S3 REST-XML, azkeys
wrap/unwrap, and the SMTP dialogue. Do not re-add a Secrets-Manager / Key-Vault-GetSecret /
GCP-SM target here — extend the connect ones instead.

## Oracle invariants

See `fuzz/thirdparty/INVARIANTS.md` and its `INVARIANTS.d/INV-FUZZCLOUD-*` fragments. Each
target's package doc states, per oracle, what it does NOT verify. Two deliberate non-goals:
the SMTP target does not assert error-on-malformed (go-mail legitimately succeeds on any
valid dialogue the fuzzer emits), and the azkeys target does not replicate the production
dial-time SSRF/redirect guard (`azurekms.azureKMSTransport`).

## Running

```
# seeds (fast): go test ./fuzz/thirdparty/{smtp,awskms,awss3,azurekeys}/
# one chunk:    go test -run='^$' -fuzz='^FuzzKMSResponse$' -fuzztime=540s -parallel=2 ./fuzz/thirdparty/awskms/
```

## Deferred (future work)

AWS STS AssumeRole + IAM key rotation (awsquery/XML), GCP KMS (gRPC — needs a fake gRPC
server), AWS IMDS / web-identity, azidentity GetToken. Ranked rationale in the SK1 report.
