package storage

import (
	"time"
)

// UserFilter defines filtering options for user queries
type UserFilter struct {
	Search       *string // OR match across username and email (LIKE %search%)
	Username     *string
	Email        *string
	IsActive     *bool
	CreatedAfter *time.Time
	// InactiveSince, when set, returns only users who have not logged in since the
	// given time — i.e. COALESCE(last_login_at, created_at) < InactiveSince (a user who
	// never logged in is judged by when the account was created).
	InactiveSince  *time.Time
	IncludeDeleted bool // when true, also return soft-deleted users
	Page           int
	PageSize       int
	// Offset, when > 0, sets the row offset directly (overriding the Page-derived
	// offset). Used for SCIM startIndex paging, where the window is an arbitrary 1-based
	// item offset that need not align to a Page boundary.
	Offset int
}

// MembershipCounts holds a user's project-membership tallies: Active counts
// memberships in the `active` state; Total counts all non-revoked memberships.
// UserBrief is the identity a list view shows for a user: never the full row.
type UserBrief struct {
	Username string
	Email    string
}
