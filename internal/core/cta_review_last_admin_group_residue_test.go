package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestCTAReview_RemoveUserRole_LastGlobalAdmin_AfterAdminGroupDeleted
// (C-GUARD2-EXEMPT-REVIEW, #2658): removing the last direct global admin must
// be refused once the only other admin grant no longer resolves to a live
// holder. RemoveUserRole's storage-level guard (RemoveGlobalAdminRoleGuarded)
// used to count any group_roles/user_roles admin ROW as a surviving admin
// without checking that the group is live and has an active global member, or
// that the user is active, so the install reached zero admins serially, with
// no race involved.
//
// Bug origin
//
//	Introduced-by: #340/#525 (the guard counts grant rows, not live holders)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act (here also a serial last-admin miscount)
//	Severity:      high (install left with zero global admins)
//	Guard:         this test (default CI, SQLite) and
//	               TestCTAReview_RemoveUserRole_LastGlobalAdmin_AfterAdminGroupDeleted_Postgres
func TestCTAReview_RemoveUserRole_LastGlobalAdmin_AfterAdminGroupDeleted(t *testing.T) {
	for _, tc := range lastAdminResidueCases {
		t.Run(tc.name, func(t *testing.T) {
			c, st := newBootstrappedCore(t)
			runLastAdminResidueCase(t, tc, c, c, st)
		})
	}
}

// TestCTAReview_RemoveUserRole_LiveAdminStillCounts is the green side of
// #2658: counting only live holders must never refuse a removal that leaves a
// REAL admin behind, and the plain last-admin refusal must still hold.
func TestCTAReview_RemoveUserRole_LiveAdminStillCounts(t *testing.T) {
	ctx := context.Background()
	t.Run("live admin group with an active member", func(t *testing.T) {
		c, st := newBootstrappedCore(t)
		adminID, adminRoleID := lastAdminResidueAdmin(t, c, st)
		member, g := lastAdminResidueGroup(t, st, adminRoleID)
		require.NoError(t, c.RemoveUserRole(ctx, adminID, adminID, adminRoleID, Scope{}))
		memberAdmin, err := c.IsGlobalAdmin(ctx, member.ID)
		require.NoError(t, err)
		assert.True(t, memberAdmin, "group %d's member must still be a global admin", g.ID)
	})
	t.Run("removed admin is also a member of a live admin group", func(t *testing.T) {
		c, st := newBootstrappedCore(t)
		adminID, adminRoleID := lastAdminResidueAdmin(t, c, st)
		g, err := st.CreateGroup(ctx, &models.Group{Name: "cta-self", NameFolded: "cta-self"})
		require.NoError(t, err)
		require.NoError(t, st.AssignRoleToGroup(ctx, g.ID, adminRoleID, storage.Scope{}))
		require.NoError(t, st.AddUserToGroup(ctx, adminID, g.ID, 0))
		require.NoError(t, c.RemoveUserRole(ctx, adminID, adminID, adminRoleID, Scope{}))
		stillAdmin, err := c.IsGlobalAdmin(ctx, adminID)
		require.NoError(t, err)
		assert.True(t, stillAdmin)
	})
	t.Run("another active direct admin", func(t *testing.T) {
		c, st := newBootstrappedCore(t)
		adminID, adminRoleID := lastAdminResidueAdmin(t, c, st)
		other := lastAdminResidueUser(t, st, "cta-dadmin")
		require.NoError(t, st.AssignRole(ctx, other.ID, adminRoleID, storage.Scope{}))
		require.NoError(t, c.RemoveUserRole(ctx, adminID, adminID, adminRoleID, Scope{}))
	})
	t.Run("sole admin is still refused", func(t *testing.T) {
		c, st := newBootstrappedCore(t)
		adminID, adminRoleID := lastAdminResidueAdmin(t, c, st)
		err := c.RemoveUserRole(ctx, adminID, adminID, adminRoleID, Scope{})
		assert.ErrorIs(t, err, storage.ErrWouldStrandLastAdmin)
	})
}

// lastAdminResidueCase leaves exactly one OTHER global admin grant ROW in
// place that no longer confers authority on any usable account.
type lastAdminResidueCase struct {
	name string
	// kill runs on the "other" core; adminID is the bootstrap admin.
	kill func(t *testing.T, c *KeyorixCore, st storage.Storage, adminID, adminRoleID uint)
}

var lastAdminResidueCases = []lastAdminResidueCase{
	{"admin group soft-deleted", func(t *testing.T, c *KeyorixCore, st storage.Storage, adminID, adminRoleID uint) {
		_, g := lastAdminResidueGroup(t, st, adminRoleID)
		require.NoError(t, c.DeleteGroup(context.Background(), adminID, g.ID))
	}},
	{"admin group's only member removed", func(t *testing.T, c *KeyorixCore, st storage.Storage, adminID, adminRoleID uint) {
		m, g := lastAdminResidueGroup(t, st, adminRoleID)
		require.NoError(t, c.RemoveUserFromGroupGlobal(context.Background(), adminID, m.ID, g.ID))
	}},
	{"admin group's only member suspended", func(t *testing.T, c *KeyorixCore, st storage.Storage, adminID, adminRoleID uint) {
		m, _ := lastAdminResidueGroup(t, st, adminRoleID)
		require.NoError(t, c.SuspendUser(context.Background(), adminID, m.ID))
	}},
	{"admin group's only member deleted", func(t *testing.T, c *KeyorixCore, st storage.Storage, adminID, adminRoleID uint) {
		m, _ := lastAdminResidueGroup(t, st, adminRoleID)
		require.NoError(t, c.DeleteUser(context.Background(), adminID, m.ID))
	}},
	{"other direct admin suspended", func(t *testing.T, c *KeyorixCore, st storage.Storage, adminID, adminRoleID uint) {
		other := lastAdminResidueUser(t, st, "cta-dadmin")
		require.NoError(t, st.AssignRole(context.Background(), other.ID, adminRoleID, storage.Scope{}))
		require.NoError(t, c.SuspendUser(context.Background(), adminID, other.ID))
	}},
}

// runLastAdminResidueCase: killer (possibly another replica) neutralises the
// other admin route while the direct admin still exists, so that step is
// allowed; remover then tries to remove the direct admin's own grant, which
// must be refused.
func runLastAdminResidueCase(t *testing.T, tc lastAdminResidueCase, killer, remover *KeyorixCore, st storage.Storage) {
	t.Helper()
	ctx := context.Background()
	adminID, adminRoleID := lastAdminResidueAdmin(t, remover, st)
	tc.kill(t, killer, st, adminID, adminRoleID)

	err := remover.RemoveUserRole(ctx, adminID, adminID, adminRoleID, Scope{})
	stillAdmin, aerr := remover.IsGlobalAdmin(ctx, adminID)
	require.NoError(t, aerr)
	assert.ErrorIs(t, err, storage.ErrWouldStrandLastAdmin, "removing the last real global admin must be refused")
	assert.True(t, stillAdmin, "the install must not be left with zero global admins")
}

// lastAdminResidueAdmin returns the bootstrap admin's ID and the global
// install-admin role it holds directly.
func lastAdminResidueAdmin(t *testing.T, c *KeyorixCore, st storage.Storage) (uint, uint) {
	t.Helper()
	ctx := context.Background()
	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	ids, err := st.GetUserRoleIDsExact(ctx, admin.ID, storage.Scope{})
	require.NoError(t, err)
	var adminRoleID uint
	for _, id := range ids {
		if c.installAdminRoleIDSet(ctx)[id] {
			adminRoleID = id
		}
	}
	require.NotZero(t, adminRoleID, "bootstrap admin must hold a global install-admin role directly")
	return admin.ID, adminRoleID
}

func lastAdminResidueUser(t *testing.T, st storage.Storage, name string) *models.User {
	t.Helper()
	u, err := st.CreateUser(context.Background(), &models.User{Username: name, Email: name + "@example.com", IsActive: true, AccountState: AccountActive, PasswordHash: "x"})
	require.NoError(t, err)
	return u
}

// lastAdminResidueGroup creates a group holding adminRoleID globally with one
// active global member.
func lastAdminResidueGroup(t *testing.T, st storage.Storage, adminRoleID uint) (*models.User, *models.Group) {
	t.Helper()
	ctx := context.Background()
	m := lastAdminResidueUser(t, st, "cta-gadmin")
	g, err := st.CreateGroup(ctx, &models.Group{Name: "cta-admins", NameFolded: "cta-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, g.ID, adminRoleID, storage.Scope{}))
	require.NoError(t, st.AddUserToGroup(ctx, m.ID, g.ID, 0))
	return m, g
}

// TestGlobalAdminLiveAccountStates_MatchAccountLoginBlocked pins the storage
// layer's hard-coded "can log in" account_state list (used by
// RemoveGlobalAdminRoleGuarded's live-holder check, #2658) to
// AccountLoginBlocked, which filterActiveHolders uses for the same verdict.
// It fails if a new account state is added to one and not the other.
func TestGlobalAdminLiveAccountStates_MatchAccountLoginBlocked(t *testing.T) {
	live := map[string]bool{}
	for _, s := range store.GlobalAdminLiveAccountStates() {
		live[s] = true
		assert.False(t, AccountLoginBlocked(0, s), "storage counts %q as live but AccountLoginBlocked blocks it", s)
	}
	for s := range validAccountStates {
		assert.Equal(t, !AccountLoginBlocked(0, s), live[s], "account_state %q: storage live-list and AccountLoginBlocked disagree", s)
	}
}
