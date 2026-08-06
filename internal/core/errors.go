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
)
