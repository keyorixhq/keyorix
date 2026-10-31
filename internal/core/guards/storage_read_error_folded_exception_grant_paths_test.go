package guards

// Exceptions to TestNoStorageReadErrorFoldedIntoNotFound: grant / create / renew / copy
// paths that read a parent (project, environment, role, config, lease) and refuse with a
// not-found or validation verdict. These refuse the operation (fail closed) and nothing
// is left half-applied, unlike the revoke / suspend / unbind family STORAGE-ERR-CLASS-1
// fixed, where "not found" tells the operator the revoke is moot. Reporting them as a
// storage fault is a follow-up; delete a row when its site calls classifyReadError.
//
// STORAGE-ERR-CLASS-2 classified catalog.go, classification_gate.go, users.go,
// secret_copy_environment.go, invitations.go and membership_lifecycle.go. The rows left:
// machine_token.go and dynamic_secrets.go belong to ERR-CLASS-LEFTOVERS-1;
// setup_consume.go:completeInvitationAccept is on the setup-link path (CompleteSetup),
// whose handler FIX-3277 owns and keeps non-oracle, so its 503 mapping lands there.

func init() {
	const why = "grant/create/renew path: the fold refuses the operation (fail closed), nothing is applied; classify as a fault in a follow-up"
	for _, key := range []string{
		"dynamic_secrets.go:requireLiveProjectAndEnvironment",
		"dynamic_secrets.go:RenewLease",
		"dynamic_secrets.go:CreateDynamicSecretConfig",
		"dynamic_secrets.go:IssueLease",
		"machine_token.go:requireEnvironmentInProject",
		"setup_consume.go:completeInvitationAccept",
	} {
		registerFoldedReadException(key, why)
	}
}
