package core

import (
	"context"
	"testing"
	"time"

	stg "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaleAccounts_PassesCutoffAndDefaultsState(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	want := c.now().Add(-7 * 24 * time.Hour)

	// Empty state defaults to pending_first_login.
	store.On("ListUsersInStateBefore", ctx, AccountPendingFirstLogin, want).
		Return([]*models.User{{ID: 1, AccountState: AccountPendingFirstLogin}}, nil)

	out, err := c.StaleAccounts(ctx, "", 7*24*time.Hour)
	require.NoError(t, err)
	assert.Len(t, out, 1)
	store.AssertCalled(t, "ListUsersInStateBefore", ctx, AccountPendingFirstLogin, want)
}

func TestProjectMembershipCounts_Delegates(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	ids := []uint{2, 3}
	store.On("CountProjectMembershipsByUsers", ctx, ids).
		Return(map[uint]stg.MembershipCounts{2: {Active: 1, Total: 2}}, nil)

	got, err := c.ProjectMembershipCounts(ctx, ids)
	require.NoError(t, err)
	assert.Equal(t, 1, got[2].Active)
	assert.Equal(t, 2, got[2].Total)
}

func TestListUserProjectMemberships_Delegates(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	store.On("ListUserProjectMemberships", ctx, uint(2)).
		Return([]*models.ProjectMembership{{ID: 9, ProjectID: 1, UserID: 2, State: "active"}}, nil)

	out, err := c.ListUserProjectMemberships(ctx, 2)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, uint(9), out[0].ID)
}
