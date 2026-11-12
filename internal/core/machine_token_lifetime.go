package core

import (
	"fmt"
	"time"
)

// MaxMachineTokenLifetimeDays is the absolute upper bound on a machine token's
// expires_in_days (about 100 years). It is a sanity bound against overflow and
// unrepresentable timestamps, not a policy ceiling: a longer-lived credential is
// already expressible as 0 (never expires).
const MaxMachineTokenLifetimeDays = 36500

// MachineTokenExpiresAt turns a client-supplied expires_in_days into the token's
// ExpiresAt. 0 means never expires (nil), the documented default of the CLI and
// both transports. A negative value or one above MaxMachineTokenLifetimeDays is
// ErrInvalidInput: it used to mint a non-expiring token (negative) or overflow
// time.AddDate into a timestamp storage and JSON cannot represent (huge). Both the
// HTTP and gRPC IssueMachineToken handlers call this, so the rule has one source.
func MachineTokenExpiresAt(expiresInDays int64, now time.Time) (*time.Time, error) {
	if expiresInDays < 0 || expiresInDays > MaxMachineTokenLifetimeDays {
		return nil, fmt.Errorf("%w: expires_in_days must be between 0 (never expires) and %d", ErrInvalidInput, MaxMachineTokenLifetimeDays)
	}
	if expiresInDays == 0 {
		return nil, nil
	}
	t := now.AddDate(0, 0, int(expiresInDays))
	return &t, nil
}
