### Fixed
- **`secret delete --id` shows the server's refusal.** When the lookup of the secret was refused (403) or the secret does not exist (404), the CLI printed `secret not found: %!w(<nil>)` and exited 1. It now prints the server's message and exits 4 (permission denied) or 5 (not found), like the other secret commands.

### Testing
- **Refused calls exit non-zero and show the message once.** `TestRefusedCallsExitNonZeroAndShowTheServerMessageOnce` drives `secret delete` (lookup and DELETE), `secret restore`, `share create`, `audit verify` and `audit verify --full` through `Run` against a fake server that answers 403 and 404, and `TestAuditVerifyBrokenChainExitsNonZero` covers a chain reported broken.
