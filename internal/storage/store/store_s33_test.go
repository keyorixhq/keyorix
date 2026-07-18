// store_s33_test.go — coverage blitz for store functions whose error-return
// branches were not yet covered: assignUserRole/assignGroupRole default cases,
// DeleteExpiredRoleGrants, RotateSession, RevokeAllPersonalAccessTokensForUser.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AssignRole / assignUserRole — "default" switch case (non-ErrRecordNotFound error)
func TestAssignRole_DBError_S33(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.AssignRole(context.Background(), 1, 2, storage.Scope{ProjectID: 1, EnvironmentID: 1})
	require.Error(t, err)
}

// AssignRoleWithExpiry — same default case via assignUserRole
func TestAssignRoleWithExpiry_DBError_S33(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	expires := time.Now().Add(time.Hour)
	err := ls.AssignRoleWithExpiry(context.Background(), 1, 2, storage.Scope{ProjectID: 1, EnvironmentID: 1}, expires)
	require.Error(t, err)
}

// AssignRoleToGroup / assignGroupRole — "default" switch case
func TestAssignRoleToGroup_DBError_S33(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.AssignRoleToGroup(context.Background(), 1, 2, storage.Scope{ProjectID: 1, EnvironmentID: 1})
	require.Error(t, err)
}

// AssignRoleToGroupWithExpiry — same default case via assignGroupRole
func TestAssignRoleToGroupWithExpiry_DBError_S33(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	expires := time.Now().Add(time.Hour)
	err := ls.AssignRoleToGroupWithExpiry(context.Background(), 1, 2, storage.Scope{ProjectID: 1, EnvironmentID: 1}, expires)
	require.Error(t, err)
}

// DeleteExpiredRoleGrants — transaction's first Find fails
func TestDeleteExpiredRoleGrants_DBError_S33(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.DeleteExpiredRoleGrants(context.Background(), time.Now())
	require.Error(t, err)
}

// RotateSession — transaction's Update fails
func TestRotateSession_DBError_S33(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	newSess := &models.Session{
		UserID:       1,
		SessionToken: "plaintext-token",
		FamilyID:     "family-1",
	}
	_, _, err := ls.RotateSession(context.Background(), 99, newSess, time.Now())
	require.Error(t, err)
}

// RevokeAllPersonalAccessTokensForUser — Pluck fails on no-table DB
func TestRevokeAllPersonalAccessTokensForUser_DBError_S33(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	hashes, err := ls.RevokeAllPersonalAccessTokensForUser(context.Background(), 1)
	assert.Nil(t, hashes)
	require.Error(t, err)
}
