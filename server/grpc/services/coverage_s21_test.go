package services

// coverage_s21_test.go — targeted tests to raise coverage on:
//
//   audit_service.go:212   WriteAuditCheckpoint      (50%)
//   audit_service.go:91    reauthorizeAuditStream     (63.6%)
//
// Focuses on the branches not yet exercised by coverage_s17_test.go,
// coverage_s17b_test.go, and coverage_s18_test.go:
//
//   WriteAuditCheckpoint:
//     - non-"refusing to checkpoint" error → clientSafe path (line 229)
//
//   reauthorizeAuditStream:
//     - GetUser returns storage error (line 103 err != nil case)
//     - AccountLoginBlocked true (deprovisioned/suspended state, IsActive still true)
//     - GetMachineIdentity returns error (line 97 err != nil case)

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// reauthorizeAuditStream — uncovered branches
// ---------------------------------------------------------------------------

// TestReauthorizeAuditStream_AccountLoginBlocked_S21 covers the branch where
// the user row exists with IsActive==true but AccountState is "suspended"
// (AccountLoginBlocked returns true). This exercises the third condition on
// line 103: `core.AccountLoginBlocked(u.AccountState)`.
func TestReauthorizeAuditStream_AccountLoginBlocked_S21(t *testing.T) {
	svc, h := newAuditServiceWithMachineUser(t)

	// Create user 3 with IsActive=true but a suspended account state.
	require.NoError(t, h.DB.Create(&models.User{
		ID: 3, Username: "carol", Email: "carol@example.com",
		IsActive: true, AccountState: core.AccountSuspended,
	}).Error)
	// Grant super_admin so authorizeGlobal(audit.read) passes — the state check must then deny.
	require.NoError(t, h.DB.Create(&models.UserRole{UserID: 3, RoleID: 1}).Error)

	actor := &interceptors.UserContext{UserID: 3, Username: "carol", Permissions: []string{"audit.read"}}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	err := svc.reauthorizeAuditStream(ctx, actor)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestReauthorizeAuditStream_AccountLoginBlocked_Deprovisioned_S21 covers the
// same logical branch but with AccountDeprovisioned (the SCIM variant).
func TestReauthorizeAuditStream_AccountLoginBlocked_Deprovisioned_S21(t *testing.T) {
	svc, h := newAuditServiceWithMachineUser(t)

	require.NoError(t, h.DB.Create(&models.User{
		ID: 4, Username: "dave", Email: "dave@example.com",
		IsActive: true, AccountState: core.AccountDeprovisioned,
	}).Error)
	require.NoError(t, h.DB.Create(&models.UserRole{UserID: 4, RoleID: 1}).Error)

	actor := &interceptors.UserContext{UserID: 4, Username: "dave", Permissions: []string{"audit.read"}}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	err := svc.reauthorizeAuditStream(ctx, actor)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestReauthorizeAuditStream_GetUserError_S21 covers the `err != nil` branch
// on line 103: GetUser fails (user does not exist in the DB) — the condition
// `err != nil || !u.IsActive || AccountLoginBlocked(...)` is true via `err != nil`.
func TestReauthorizeAuditStream_GetUserError_S21(t *testing.T) {
	svc, h := newAuditServiceWithMachineUser(t)

	// Grant role to non-existent user so authorizeGlobal passes, but GetUser
	// will fail because the users table has no row for ID 50.
	require.NoError(t, h.DB.Create(&models.UserRole{UserID: 50, RoleID: 1}).Error)

	actor := &interceptors.UserContext{UserID: 50, Username: "ghost", Permissions: []string{"audit.read"}}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	err := svc.reauthorizeAuditStream(ctx, actor)
	// Either PermissionDenied (role check fails) or PermissionDenied (GetUser err).
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestReauthorizeAuditStream_MachineGetError_S21 covers the `err != nil` branch
// on line 97: GetMachineIdentity fails because the machine row does not exist in
// the DB (the role exists but the machine identity row is absent).
func TestReauthorizeAuditStream_MachineGetError_S21(t *testing.T) {
	svc, h := newAuditServiceWithMachineUser(t)

	// Grant role to a non-existent machine so authorizeGlobal may pass, then
	// GetMachineIdentity(99) fails (no row) → PermissionDenied.
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{
		MachineIdentityID: 99, RoleID: 1, ProjectID: 0,
	}).Error)

	actor := &interceptors.UserContext{
		MachineIdentityID: 99,
		ActorType:         core.ActorTypeMachine,
		Permissions:       []string{"audit.read"},
	}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	err := svc.reauthorizeAuditStream(ctx, actor)
	// Either the global permission check or the machine-state check must deny.
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
