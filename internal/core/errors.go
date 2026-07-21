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

	// ErrInvalidRetentionDays is returned by PurgeAuditLogs when the caller
	// supplies a retention window that is below the minimum 7-day floor.
	ErrInvalidRetentionDays = errors.New("invalid retention_days")
)
