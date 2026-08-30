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
		"DeleteMFAStepUpGrantsFor": {statusIntentional,
			"#1480: zero internal/core caller confirmed -- server/main.go's own scheduled pruning comment " +
				"names this directly as reachable only via the RemoteStorage proxy, never a local " +
				"maintenance path (grants are cleaned up by TTL via PruneMFAStepUpGrants instead). Its only " +
				"real caller, repo-wide, was its own /system proxy handler, DeleteMFAStepUpGrantsForProxy " +
				"(server/http/handlers/mfa_stepup_proxy.go), now removed."},
	})
}
