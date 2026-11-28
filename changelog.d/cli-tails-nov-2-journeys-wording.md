### Internal
- **E2E journey 18/19 name the way the code is given, not the refused flag.** Two subtest names and one step description said `--mfa-code` while the journeys already pass the code in `KEYORIX_MFA_CODE`. No secret-flag call site is left in `scripts/e2e/journeys` outside the refusal journey and its guard (`secret_flags_guard_test.go`).
