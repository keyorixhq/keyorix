// named_lock_overlap_sod_join_test.go — NAMEDLOCK-FENCE-1: a user joining a
// group (AddUserToGroup, under sodGrantLockKey("user", ...)) and a role granted
// to that group (AssignRoleToGroup / AssignGroupRoleWithExpiry, under the group
// key plus the keys of the members it listed) share no named lock: the joining
// user is not yet a member when the grant lists them. Each write transaction
// must therefore see the other's committed write (the join re-reads the group's
// grants, the grant re-lists the group's members) and refuse a toxic pair.
//
// User 1 holds the secrets.delete half (role 22) directly; group 31 holds
// nothing. One side grants the roles.assign half (role 21) to group 31, the
// other adds user 1 to it. Holder A loses its lock after its check passed;
// holder B (another replica) runs the other side and commits; A must be refused.
package core_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestNamedLockOverlap_SoD_GroupJoinVsGroupGrant_NoToxicPair(t *testing.T) {
	t.Parallel()
	grantRole := func(ctx context.Context, c *core.KeyorixCore) error {
		return c.AssignRoleToGroup(ctx, 99, 31, 21, core.Scope{ProjectID: 3}, false)
	}
	grantRoleWithExpiry := func(ctx context.Context, c *core.KeyorixCore) error {
		return c.AssignGroupRoleWithExpiry(ctx, 99, 31, 21, core.Scope{ProjectID: 3}, time.Now().Add(time.Hour), false)
	}
	join := func(ctx context.Context, c *core.KeyorixCore) error {
		return c.AddUserToGroup(ctx, 99, false, 1, 31, 0)
	}
	cases := []struct {
		name string
		key  string // holder A's key
		a, b func(ctx context.Context, c *core.KeyorixCore) error
	}{
		// Red before NAMEDLOCK-FENCE-1: the grant's fence checked the member
		// list taken before its transaction, which did not have user 1.
		{"AssignRoleToGroup then join", "sod-grant:group:31", grantRole, join},
		{"AssignGroupRoleWithExpiry then join", "sod-grant:group:31", grantRoleWithExpiry, join},
		// Green before too (the join already re-read the group's grants in its
		// transaction); kept so neither side's re-check can be dropped.
		{"join then AssignRoleToGroup", sodUser1Key, join, grantRole},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newOverlapSoDFixture(t)
			require.NoError(t, db.Create(&models.Group{ID: 31, Name: "empty-handed"}).Error)
			require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 22, ProjectID: 3}).Error)
			replicaB := core.NewKeyorixCore(store.NewLocalStorage(db))
			overlap := newLockLossOverlap(t, tc.key, func(ctx context.Context) error {
				return tc.b(ctx, replicaB)
			})
			replicaA := core.NewKeyorixCore(overlap.store(store.NewLocalStorage(db)))

			errA := tc.a(context.Background(), replicaA)
			t.Logf("holder A: %v; holder B: %v", errA, overlap.secondErr)
			overlap.requireFired()

			require.NoError(t, overlap.secondErr, "holder B completed one side alone and must succeed")
			require.False(t, holdsBothHalves(t, db, false),
				"holder A committed after holder B inside A's lost-lock window: user 1 holds a toxic pair through group 31 (A's error: %v)", errA)
			require.Error(t, errA)
			require.True(t, strings.Contains(errA.Error(), "separation-of-duties"), "A is refused by the separation-of-duties check, got: %v", errA)
		})
	}
}
