### Testing
- **Real-backend spec for suspend + clear synced copies + expired.** `web/e2e/real/suspend-clear-synced-copies-expired.spec.ts` covers the case #3215 left out: a secret suspended with the clear choice that then expires keeps the `clear_synced_copies` marker on its `SecretExpired` refusal, never returns the value, and the suspend stays in the audit log.
