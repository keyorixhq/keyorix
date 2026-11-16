### Testing
- **Hostile-server fuzzing of the cloud SDKs (SK1).** Added four hostile-SERVER
  fuzz targets under `fuzz/thirdparty`, driving the real SDK clients Keyorix uses
  against loopback servers with grammar-aware mutated responses, through each SDK's
  own endpoint/transport override: `FuzzKMSResponse` (aws-sdk-go-v2/kms, awsJson1_1),
  `FuzzS3PutObjectResponse` (aws-sdk-go-v2/s3, REST-XML — the evidencesink object
  store), `FuzzAzureKeysResponse` (azure-sdk-for-go keyvault/azkeys, JSON over TLS),
  and `FuzzSMTPDialogue` (wneessen/go-mail, plaintext SMTP dialogue). Oracles (each
  red/green-proven): no panic, bounded time, no goroutine/fd leak, fail-closed on a
  non-2xx response, no retry storm, and no sent credential (AWS access-key id, Azure
  bearer token, SMTP password) on the wire or in an error. Complements the existing
  `internal/connect` federated-secret response fuzzers (AWS SM / Azure KV / GCP SM /
  Vault) by covering the disjoint surface those do not: KMS wrap/unwrap, S3 REST-XML,
  and the SMTP dialogue. Shared oracle harness in `fuzz/thirdparty/internal/cloudfuzz`.
