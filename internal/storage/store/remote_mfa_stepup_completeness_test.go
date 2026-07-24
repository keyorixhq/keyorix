package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"UpsertMFAStepupToken": {statusIntentional,
			"step-up token recording is triggered by VerifyMFALogin; under storage.type: remote the MFA " +
				"verification is proxied to the server via RemoteMFAVerifier before the token write — the " +
				"write always runs server-side, never from a remote-storage caller"},
		"HasActiveMFAStepup": {statusIntentional,
			"step-up check runs inside checkRestrictedSecretReadApproval, which is called during secret " +
				"value reads; under storage.type: remote, value reads are proxied to the server via the " +
				"HTTP /api/v1/secrets/:id/value route — the gate always executes server-side, never from " +
				"a remote-storage caller"},
	})
}
