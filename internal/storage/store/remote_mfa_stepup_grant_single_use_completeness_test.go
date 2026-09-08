package store

func init() {
	// ConsumeMFAStepUpGrant (single-use reauth grant fix, follow-up to #1775):
	// its sole purpose argument is always models.MFAStepUpPurposeReauth, minted
	// only by core.FinishWebAuthnReauth via CreateMFAStepUpGrant -- and that
	// method is ALREADY remoteUnsupported (see remote_reachability_registry_test.go's
	// "CreateMFAStepUpGrant" entry: G80 158-method classification pass, no
	// storage.type: remote caller in either topology). No Reauth-purpose grant
	// can ever exist to consume on a remote spoke in the first place. Its
	// consumer, core.requireReauth, is reached only from server/http/handlers
	// (DisableMFA, RegenerateMFARecoveryCodes, ActivateMFA, WebAuthn credential
	// register/delete, account email change), which per
	// validateRemoteStorageNotServer (internal/config/config.go) can never be
	// wired to RemoteStorage in any deployment.
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ConsumeMFAStepUpGrant": {statusIntentional,
			"mirrors CreateMFAStepUpGrant's existing remoteUnsupported status: the only purpose this method is ever called with (MFAStepUpPurposeReauth) can only be minted by FinishWebAuthnReauth, which is itself already remoteUnsupported via CreateMFAStepUpGrant, so no grant of that purpose can ever exist to consume under storage.type: remote. requireReauth (the sole caller) is reached only from server/http/handlers, never bootable against RemoteStorage (validateRemoteStorageNotServer)."},
	})
}
