// named_lock_overlap_membership_test.go — NAMEDLOCK-OVERLAP-2, family
// "membership" (docs/design/named-lock-overlap.md): the role grant that backs a
// membership's activation re-reads the membership inside its own transaction,
// under membershipLockKey taken with LockNamedKeyInTx (which every state CAS
// also takes), so losing the named lock mid-section cannot leave a grant on a
// revoked membership (#2657, #2659).
//
// Each case: holder A activates user 2's membership in project 1 (an
// activation, or an open-mode invite that creates it active); its lock is lost
// once the membership is active and before A's grant, holder B (another
// replica) revokes it and commits, then A grants. A must be refused and no
// grant may remain.
package core_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const membershipKey12 = "project-membership:1:2"

// newOverlapMembershipFixture: project 1, role "project_developer", actor 99
// (global admin), user 2. invited adds membership 50 for user 2 in state
// "provisioned" (the state an activation starts from).
func newOverlapMembershipFixture(t *testing.T, invited bool) *gorm.DB {
	t.Helper()
	db := sqliteDB(t, "overlap_membership.db")
	require.NoError(t, db.AutoMigrate(&models.ProjectMembership{}, &models.Notification{}, &models.SoDPolicy{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 20, Name: "project_developer"}).Error)
	for _, u := range []models.User{
		{ID: 2, Username: "member", Email: "member@x.io", EmailFolded: "member@x.io", IsActive: true, AccountState: core.AccountActive},
		{ID: 99, Username: "actor", IsActive: true, AccountState: core.AccountActive},
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: 99, RoleID: 10}).Error)
	if invited {
		require.NoError(t, db.Create(&models.ProjectMembership{ID: 50, ProjectID: 1, UserID: 2, Role: "project_developer", State: core.MembershipProvisioned}).Error)
	}
	return db
}

// activeMembershipID returns user 2's membership in project 1 once it is
// active, or 0.
func activeMembershipID(db *gorm.DB) uint {
	var m models.ProjectMembership
	if err := db.Where("project_id = 1 AND user_id = 2 AND state = ?", core.MembershipActive).First(&m).Error; err != nil {
		return 0
	}
	return m.ID
}

func TestNamedLockOverlap_Membership_NoGrantOnRevoked(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		invited  bool
		activate func(ctx context.Context, c *core.KeyorixCore) error
	}{
		{"TransitionMembership", true, func(ctx context.Context, c *core.KeyorixCore) error {
			_, err := c.TransitionMembership(ctx, 1, 50, core.MembershipActive, 99, false)
			return err
		}},
		{"InviteMember/open", false, func(ctx context.Context, c *core.KeyorixCore) error {
			c.SetMembershipValidationMode(core.ValidationModeOpen)
			_, err := c.InviteMember(ctx, 1, 2, "project_developer", 99, 0, false)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newOverlapMembershipFixture(t, tc.invited)
			replicaB := core.NewKeyorixCore(store.NewLocalStorage(db))
			overlap := newLockLossOverlap(t, membershipKey12, func(ctx context.Context) error {
				_, err := replicaB.TransitionMembership(ctx, 1, activeMembershipID(db), core.MembershipRevoked, 99, false)
				return err
			})
			overlap.when = func() bool { return activeMembershipID(db) != 0 }
			replicaA := core.NewKeyorixCore(overlap.store(store.NewLocalStorage(db)))

			errA := tc.activate(context.Background(), replicaA)
			t.Logf("holder A: %v; holder B: %v", errA, overlap.secondErr)
			overlap.requireFired()

			require.NoError(t, overlap.secondErr, "holder B revoked an active membership with no grant yet and must succeed")
			var m models.ProjectMembership
			require.NoError(t, db.Where("project_id = 1 AND user_id = 2").First(&m).Error)
			require.Equal(t, core.MembershipRevoked, m.State, "holder B's revocation committed")
			var grants int64
			require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = 2 AND project_id = 1").Count(&grants).Error)
			require.Zero(t, grants,
				"holder A granted the role after holder B revoked the membership inside A's lost-lock window: a revoked member keeps access (A's error: %v)", errA)
			require.True(t, errors.Is(errA, core.ErrMembershipStateConflict), "A is refused by the in-transaction state re-read, got: %v", errA)
		})
	}
}
