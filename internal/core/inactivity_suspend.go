// inactivity_suspend.go — background job that suspends user accounts inactive
// longer than a configurable number of days.
//
// SuspendInactiveUsers is both the on-demand HTTP endpoint body and the
// scheduler hook. Admin users (those holding a global admin role) are never
// suspended; the job is idempotent for already-suspended users.
package core

import (
	"context"
	"fmt"
	"time"
)

// MaxInactiveDays bounds cfg.InactiveDays (#G44). Without a ceiling, a large
// enough value overflows the int64 nanosecond Duration computed below
// (time.Duration(cfg.InactiveDays) * 24 * time.Hour), wrapping around to a
// NEGATIVE duration — c.now().Add(-negativeDuration) then lands in the
// FUTURE, making every user in the deployment appear "inactive" and
// suspending them all in one call.
const MaxInactiveDays = 36500 // 100 years

// InactivitySuspendConfig controls the suspension threshold.
type InactivitySuspendConfig struct {
	// InactiveDays is the minimum number of days without a login before a
	// user is considered inactive.  Must be > 0 and <= MaxInactiveDays.
	InactiveDays int

	// DryRun, when true, causes SuspendInactiveUsers to evaluate every user
	// against the threshold and admin-skip rules but NOT call SuspendUser.
	// The returned result reflects what would have been suspended.
	DryRun bool
}

// InactivitySuspendResult is returned by SuspendInactiveUsers.
type InactivitySuspendResult struct {
	Suspended []uint // IDs of users suspended by this run
	Skipped   int    // already-suspended or admin users left untouched
	Total     int    // total live, non-deleted users examined
}

// SuspendInactiveUsers suspends every non-admin, non-deleted user whose most
// recent login (LastLoginAt) is older than cfg.InactiveDays days — or who has
// never logged in and whose account was created more than cfg.InactiveDays days
// ago.  Global admin users are always skipped.
//
// It uses ID 0 as the actor (system action) for the audit log, mirroring how
// other background jobs that call setAccountState work.
func (c *KeyorixCore) SuspendInactiveUsers(ctx context.Context, cfg InactivitySuspendConfig) (*InactivitySuspendResult, error) {
	if cfg.InactiveDays <= 0 {
		return nil, fmt.Errorf("inactive_days must be greater than 0")
	}
	if cfg.InactiveDays > MaxInactiveDays {
		return nil, fmt.Errorf("inactive_days exceeds the maximum of %d", MaxInactiveDays)
	}

	threshold := c.now().Add(-time.Duration(cfg.InactiveDays) * 24 * time.Hour)

	// Retrieve all live users inactive beyond the threshold in one query.
	users, err := c.storage.ListInactiveUsers(ctx, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to list inactive users: %w", err)
	}

	result := &InactivitySuspendResult{
		Suspended: []uint{},
	}
	result.Total = len(users)

	for _, u := range users {

		// Already suspended — nothing to do.
		if NormalizeAccountState(u.AccountState) == AccountSuspended {
			result.Skipped++
			continue
		}

		// Skip global admins.
		isAdmin, err := c.IsGlobalAdmin(ctx, u.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to check admin status for user %d: %w", u.ID, err)
		}
		if isAdmin {
			result.Skipped++
			continue
		}

		if cfg.DryRun {
			// Dry-run: record what would be suspended without mutating state.
			result.Suspended = append(result.Suspended, u.ID)
			continue
		}

		// Suspend the user.  Actor ID 0 = system/background job.
		if err := c.SuspendUser(ctx, 0, u.ID); err != nil {
			return nil, fmt.Errorf("failed to suspend user %d: %w", u.ID, err)
		}
		result.Suspended = append(result.Suspended, u.ID)
	}

	return result, nil
}
