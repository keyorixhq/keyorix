- **INV-HTTP-pre-verdict-storage-error-not-a-failed-login** A storage error that
  happens BEFORE any credential was checked (the username lookup on `/auth/login`;
  loading the user named by a passwordless passkey's handle; ActivateMFA's
  anti-replay write is the audit-only sibling) is not a failed login: it is audited
  as an error event (`auth.login_error`, `mfa.error`), never as `auth.login_failed`
  / `webauthn.failed` / `mfa.failed`, and the per-IP login-budget slot is handed
  back (the budget counts failed credential attempts only,
  INV-HTTP-login-budget-counts-failures-only). The client response is byte-for-byte
  the one the matching negative result gets (an unknown username, a handle naming no
  user, a wrong code), so the distinction adds no account-existence signal. A
  POST-verdict storage error is the opposite case and is unchanged: answered like a
  wrong credential AND counted (INV-CORE-login-lockout-clear-only-after-delivery).
  Why: #2744/#2745/#2746 (ported from #2846 by AUTH-AUDIT-1). Guard:
  `server/http/handlers/pre_verdict_storage_error_test.go` (control vs probe:
  status, body, headers, audit rows, login_attempts rows) and
  `internal/core/pre_verdict_storage_error_labelling_test.go` (the class split, plus
  the must-not-change halves: absent account == wrong password, replay stays
  `mfa.failed`, unchanged error texts).
  An error caused by the attacker's own input is not a storage error: a passkey
  user handle that cannot name a user (0, or above MaxInt64, which Postgres's
  driver cannot even encode and answers with a non-not-found error) is refused
  before the lookup and stays a counted `webauthn.failed` (#2846 review). Guard:
  `server/http/handlers/passwordless_out_of_range_user_handle_test.go`.
  Decided exceptions to the response rule (Andrei, asks
  `auth-endpoint-outage-1-setup-consume-503` and
  `auth-endpoint-outage-1-refresh-webauthn-postverdict-503`, AUTH-LANE-FOLDS-1): the
  slot and audit rules above still hold, but a storage READ fault answers 503 +
  Retry-After `storage_unavailable` where the credential cannot be guessed or nothing
  was evaluated: `ConsumeSetup`'s token lookup (`ErrSetupNotEvaluated`, slot handed
  back; a fault after the token was found valid keeps the dead-link 400),
  `RefreshToken`'s session lookup (slot handed back) and owner read (slot kept), and
  `FinishWebAuthnLogin`'s identity read after the assertion verified
  (`ErrLoginIdentityUnavailable`, slot and lockout cost kept). `/auth/login` and the
  passwordless handle lookup keep the byte-identical answer: a username or a password
  can be guessed. Guard: `TestConsumeSetup_TokenLookupFaultIs503AndSaysNothingAboutTheToken`,
  `TestRefresh_StorageFaultSlotPolicy`,
  `TestFinishWebAuthnLogin_CompleteLoginFaultIs503AndCostsLikeAFailedAssertion`.
