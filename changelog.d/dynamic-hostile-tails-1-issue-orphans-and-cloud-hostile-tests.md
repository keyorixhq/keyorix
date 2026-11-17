### Fixed
- **A dynamic-secret `Issue` that fails after the target created the account no longer
  orphans it.** The postgres, mysql, mongodb and redis engines now name the generated
  account to core before their first target write; when `Issue` then fails, including a
  contained client-library panic, core revokes the account by name and, if that revoke also
  fails, records a `revoke_failed` lease for it so the sweep and the manual retry find it.
  Guarded by `internal/core/dynamic_secrets_issue_abort_test.go`.

### Testing
- **Hostile-server tests for the cloud engines and executors.** aws-sts, gcp and azure
  (engines) and aws-iam, azure-app and gcp-service-account (executors) run against
  `internal/fuzzutil/hostile` with malformed replies, giant length prefixes and headers,
  hangs, slow drips and connection resets, and must refuse with an ordinary error, return
  within their deadline, leave no goroutine or descriptor behind and carry no sent
  credential in the error or log text.

### Internal
- **`realAzureMinter` holds an `azcore.TokenCredential`** instead of the concrete
  `*azidentity.DefaultAzureCredential` (the same value in production), so a test can aim
  the same `GetToken` path at a hostile authority.
