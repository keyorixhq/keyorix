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
// machine_token.go belongs to ERR-CLASS-LEFTOVERS-1; dynamic_secrets.go was classified by
// d4ea188c7 and its rows are gone.
// AUTH-ENDPOINT-OUTAGE-1 classified setup_consume.go:completeInvitationAccept (a read
// fault is ErrSetupPostVerdict + ErrStorageReadUnavailable).

func init() {
	const why = "grant/create/renew path: the fold refuses the operation (fail closed), nothing is applied; classify as a fault in a follow-up"
	for _, key := range []string{
		"machine_token.go:requireEnvironmentInProject",
	} {
		registerFoldedReadException(key, why)
	}
}
