- **INV-FUZZCLOUD-no-sent-credential-in-error** No cloud-SDK client Keyorix drives may
  echo the credential IT SENT (an AWS SigV4 access-key id, an Azure Key Vault bearer
  token, an SMTP password) into a returned error string, regardless of the hostile
  response that provoked the error. Response-body content is attacker-chosen and may be
  echoed; the SENT credential may not. Why: these errors are logged and surfaced
  (`delivery/smtp.go`, `crypto/awskms`, `crypto/azurekms`, `evidencesink`), so a
  credential in an error is a log/exfil leak. Guard: the `AssertNoSecretInError` oracle
  in every cloud target (`fuzz/thirdparty/{smtp,awskms,awss3,azurekeys}`), whose core
  `scanSecretsInError` is red/green-proven directly in
  `fuzz/thirdparty/internal/cloudfuzz` (fires on a planted leak, silent on a clean
  error / nil / empty-secret). Does NOT assert anything about a credential appearing in
  LOGS or metrics — only in the error value returned to the caller.
