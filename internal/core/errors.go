package core

import "errors"

// Sentinel errors for common failure modes. Use errors.Is to test for these
// across wrapped error chains.
var (
	// ErrIncorrectCurrentPassword is returned when a password-change or profile-update
	// request supplies the wrong current password.
	ErrIncorrectCurrentPassword = errors.New("incorrect current password")

	// ErrUserAlreadyExists is returned when a user-creation or update request
	// collides with an existing username or email.
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrInvalidBootstrapToken is returned when the supplied bootstrap token is
	// missing, empty, or does not match the server's configured token.
	ErrInvalidBootstrapToken = errors.New("invalid bootstrap token")

	// ErrInvalidInput is returned when a caller supplies a logically inconsistent
	// or out-of-range parameter (e.g. a time range where Since >= Until).
	ErrInvalidInput = errors.New("invalid input")

	// ErrInvalidAuditRetentionDays is returned by PurgeAuditLogs when the caller
	// supplies a retention window that is below the minimum 7-day floor.
	ErrInvalidAuditRetentionDays = errors.New("invalid retention_days")

	// ErrUserActiveStateConflict is returned by UpdateUser when a request that
	// explicitly asserts IsActive (an actual flip or a redundant same-value set)
	// loses a race against another concurrent UpdateUser call touching the same
	// user's active state — the row's persisted is_active moved away from the
	// value this call observed (wasActive) between its GetUser read and its
	// conditional write (storage.Storage.UpdateUserIfActiveStateMatches).
	// Mirrors TransitionMachineIdentity's #388 lost-race handling and
	// UpdateProjectInvitation's #412 "no longer pending" refusal: the caller
	// must retry against the current state, not have its change silently
	// dropped or silently clobber the winner.
	ErrUserActiveStateConflict = errors.New("user's active state changed concurrently")

	// ErrMembershipStateConflict is returned by TransitionMembership when it
	// loses a race against a concurrent TransitionMembership call on the same
	// project membership — the row's persisted state moved away from the
	// value this call observed between its read and its conditional write
	// (storage.Storage.TransitionProjectMembershipState). #G42: mirrors
	// ErrUserActiveStateConflict/ErrMachineStateConflict — the caller must
	// retry against the current state, not silently clobber (or be clobbered
	// by) the transition.
	ErrMembershipStateConflict = errors.New("project membership's state changed concurrently")

	// ErrMachineStateConflict is returned by ClassifyMachineIdentity when it
	// loses a race against a concurrent TransitionMachineIdentity call on the
	// same machine identity — the row's persisted state moved away from the
	// value this call observed between its read and its conditional write
	// (storage.Storage.TransitionMachineIdentityState). #G42: mirrors
	// ErrUserActiveStateConflict — the caller must retry against the current
	// state, not silently clobber (or be clobbered by) the state transition.
	ErrMachineStateConflict = errors.New("machine identity's state changed concurrently")

	// ErrConnectDisabled is returned by the Keyorix Connect (ADR-043) methods when
	// no external-store connector is configured.
	ErrConnectDisabled = errors.New("keyorix connect is not enabled")

	// ErrConnectUnknownConnector is returned when a caller (or a per-reference
	// grant) names a connector that isn't configured.
	ErrConnectUnknownConnector = errors.New("unknown connector")

	// ErrConnectRoleRequired is returned by CreateConnectRefGrant when roleID is 0.
	ErrConnectRoleRequired = errors.New("a role is required for a connect ref-grant")

	// ErrConnectRefNotPermitted is returned by ReadFederatedSecret when the
	// per-reference RBAC policy (ADR-045) denies the read. These four Connect
	// sentinels exist so the HTTP layer (isSafeConnectError) can classify its own
	// deliberately-crafted, safe error text via errors.Is instead of a
	// strings.Contains substring match against err.Error() — the ref itself is
	// caller-controlled and, if echoed back by an upstream connector's own error
	// text, could otherwise spoof a substring match and let raw upstream error
	// detail pass through unsanitized (backlog #116).
	ErrConnectRefNotPermitted = errors.New("is not permitted for your roles on connector")

	// ErrAuditCheckpointRefused is returned by WriteAuditCheckpoint (via
	// writeAuditCheckpointLocked) whenever it declines to sign a checkpoint: the
	// chain doesn't verify, a prior checkpoint proves a truncation, a prior
	// checkpoint's signature was tampered with, or the chain sits below the
	// certified high-water mark. Callers use errors.Is against this sentinel to
	// distinguish this expected, safe-to-surface precondition failure from an
	// unclassified storage/internal error, instead of substring-matching
	// err.Error() (which the dynamic %s/%d detail appended to each of these
	// errors would make spoofable by anything that can influence that detail).
	ErrAuditCheckpointRefused = errors.New("refusing to checkpoint")
)
