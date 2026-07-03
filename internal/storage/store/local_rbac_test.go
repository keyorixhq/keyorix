package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #263: assignUserRole's existence check must treat an EXPIRED grant as absent, so a
// second real-incident activation (e.g. break-glass) for the same (user, role,
// project, environment) key succeeds instead of permanently failing with "already
// assigned" against a stale, un-reaped row. A genuinely still-live grant (no expiry,
// or an expiry still in the future) must continue to correctly block a duplicate.

// A permanent (non-expiring) grant still blocks a duplicate AssignRole.
func TestAssignRole_BlocksDuplicateOfLiveGrant(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	require.NoError(t, ls.AssignRole(ctx, 1, 10, sc(5, 0)))
	err := ls.AssignRole(ctx, 1, 10, sc(5, 0))
	require.Error(t, err, "a duplicate assignment of a permanent, still-live grant must be refused")
}

// A grant that has not yet expired still blocks a duplicate AssignRoleWithExpiry.
func TestAssignRoleWithExpiry_BlocksDuplicateOfLiveGrant(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	future := time.Now().Add(time.Hour)
	require.NoError(t, ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), future))

	err := ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), time.Now().Add(2*time.Hour))
	require.Error(t, err, "a duplicate assignment while the first grant is still live must be refused")
}

// The core of #263: once the FIRST grant's expires_at has naturally passed, a SECOND
// activation for the exact same (user, role, project, environment) key must succeed —
// not fail with "already assigned" against the stale, un-reaped row.
func TestAssignRoleWithExpiry_ReactivatesAfterNaturalExpiry(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	require.NoError(t, ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), past),
		"seed a grant that is already expired at creation, simulating natural expiry")

	newExpiry := time.Now().Add(time.Hour)
	err := ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), newExpiry)
	require.NoError(t, err, "a second activation after the first grant naturally expired must succeed")

	ids, err := ls.GetUserRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.Contains(t, ids, uint(10), "the fresh grant must be live and authorizing")
}

// Same as above but via the permanent AssignRole path re-granting after a PRIOR
// time-bound grant (e.g. AssignRoleWithExpiry) at the same key expired.
func TestAssignRole_SucceedsAfterPriorTimeBoundGrantExpired(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	require.NoError(t, ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), past))

	err := ls.AssignRole(ctx, 1, 10, sc(5, 0))
	require.NoError(t, err, "a permanent re-grant after the prior time-bound grant expired must succeed")

	ids, err := ls.GetUserRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.Contains(t, ids, uint(10))
}
