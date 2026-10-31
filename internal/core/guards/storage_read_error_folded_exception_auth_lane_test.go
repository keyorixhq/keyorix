package guards

// Exceptions to TestNoStorageReadErrorFoldedIntoNotFound: the login / MFA / WebAuthn /
// step-up / impersonation lane. STORAGE-ERR-CLASS-1's brief forbids touching these files
// (FIX-3277 owns the area; MFA-RESET-TAILS-2 is queued on it). Each fold refuses the
// operation (fail closed); only the error class is wrong. Delete the row when that lane
// classifies the read with classifyReadError.

func init() {
	const lane = "login/MFA lane owned by FIX-3277 (MFA-RESET-TAILS-2 queued): fail-closed refusal, error class deferred to that lane"
	for _, key := range []string{
		"mfa.go:BeginMFAEnrollment",
		"mfa.go:ActivateMFA",
		"mfa.go:DisableMFA",
		"mfa.go:RegenerateMFARecoveryCodes",
		"mfa.go:MFARecoveryCodesRemaining",
		"mfa_stepup.go:VerifyMFAStepUp",
		"webauthn.go:FinishWebAuthnRegistration",
		"webauthn.go:DeleteWebAuthnCredential",
		"webauthn.go:FinishWebAuthnReauth",
		"impersonation.go:StartImpersonation",
		"impersonation.go:EndImpersonation",
		"impersonation.go:ReauthorizeImpersonation",
	} {
		registerFoldedReadException(key, lane)
	}
}
