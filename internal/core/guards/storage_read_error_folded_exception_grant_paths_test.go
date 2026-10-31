package guards

// Exceptions to TestNoStorageReadErrorFoldedIntoNotFound: grant / create / renew / copy
// paths that read a parent (project, environment, role, config, lease) and refuse with a
// not-found or validation verdict. These refuse the operation (fail closed) and nothing
// is left half-applied, unlike the revoke / suspend / unbind family STORAGE-ERR-CLASS-1
// fixed, where "not found" tells the operator the revoke is moot. Reporting them as a
// storage fault is a follow-up; delete a row when its site calls classifyReadError.

func init() {
	const why = "grant/create/renew path: the fold refuses the operation (fail closed), nothing is applied; classify as a fault in a follow-up"
	for _, key := range []string{
		"catalog.go:CreateEnvironment",
		"classification_gate.go:ApproveSecretAccessRequest",
		"dynamic_secrets.go:requireLiveProjectAndEnvironment",
		"dynamic_secrets.go:RenewLease",
		"dynamic_secrets.go:CreateDynamicSecretConfig",
		"dynamic_secrets.go:IssueLease",
		"invitations.go:approveAccessRequestWithExpiryLocked",
		"machine_token.go:requireEnvironmentInProject",
		"membership_lifecycle.go:inviteMemberWithMode",
		"secret_copy_environment.go:projectEnvironment",
		"setup_consume.go:completeInvitationAccept",
		"users.go:CreateUserWithAssignments",
		"users.go:resolveProjectRoleGrant",
		"users.go:ValidateRoleGrantAuthority",
	} {
		registerFoldedReadException(key, why)
	}
}
