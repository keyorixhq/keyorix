package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MembershipStore is the Storage slice for project memberships and member lookups.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type MembershipStore interface {
	ListProjectMembers(ctx context.Context, projectID uint) ([]ProjectMember, error)

	// Project membership lifecycle (ADR-022). Separate from the role grant.
	CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error)
	GetProjectMembership(ctx context.Context, id uint) (*models.ProjectMembership, error)
	// TransitionProjectMembershipState persists m's full row via a single
	// conditional write — "UPDATE ... WHERE id = ? AND state = ?" — succeeding
	// only if the row's CURRENT persisted state still equals fromState (the
	// value TransitionMembership/revertFailedActivation observed immediately
	// before mutating m in memory), mirroring TransitionMachineIdentityState's
	// exact shape (#G42). Unlike that helper, there's no row lock backing this
	// read — the conditional write is the ONLY thing closing the race, so
	// there must never be a plain unconditional-write alternative for a state
	// transition: a concurrent TransitionMembership call landing between the
	// read and the write would otherwise be silently reverted (or silently
	// revert this call), corrupting the ADR-022 state machine. Returns whether
	// the write actually matched a row; a false match must be treated exactly
	// like an illegal transition, not retried or silently overwritten.
	TransitionProjectMembershipState(ctx context.Context, m *models.ProjectMembership, fromState string) (bool, error)
	ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error)
	// GetActiveProjectMembership returns the user's non-revoked membership in a
	// project, or an error if none exists.
	GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error)
	// ListStaleInvitedMemberships returns memberships still in `invited` state
	// that were invited before the cutoff.
	ListStaleInvitedMemberships(ctx context.Context, before time.Time) ([]*models.ProjectMembership, error)
	// ListUserProjectMemberships returns all membership rows for a single user,
	// newest first (powers the per-user assignments view).
	ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error)
	// ListUserProjectMembershipsByUserIDs is the batch form of ListUserProjectMemberships
	// (LIST-ENDPOINTS-1): each user's rows, newest invite first, keyed by user id; a user
	// with no row is absent.
	ListUserProjectMembershipsByUserIDs(ctx context.Context, userIDs []uint) (map[uint][]*models.ProjectMembership, error)
	// CountProjectMembershipsByUsers returns per-user membership tallies (active
	// and non-revoked total) for the given user IDs in one grouped query.
	CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]MembershipCounts, error)
}
