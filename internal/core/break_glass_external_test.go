package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enableBreakGlass(h *testhelper.RBACTestHelper, role string, def, max time.Duration) {
	h.CoreService.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: role, DefaultTTL: def, MaxTTL: max,
	})
}

func migrateBreakGlass(t *testing.T, h *testhelper.RBACTestHelper) {
	require.NoError(t, h.DB.AutoMigrate(&models.BreakGlassActivation{}, &models.AuditEvent{}))
}

// Activating break-glass time-bound-grants the configured emergency role to the
// caller and records the justified activation.
func TestActivateBreakGlass_GrantsTimeBoundRole(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour) // role 3

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident #42", "")
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassActive, act.State)
	assert.Equal(t, uint(3), act.RoleID)
	require.NotNil(t, act.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(4*time.Hour), *act.ExpiresAt, 2*time.Minute)

	// alice now holds the emergency (editor) role at the project, time-bound.
	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.Contains(t, ids, uint(3), "emergency role is active")

	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "prod incident #42", list[0].Justification)
}

// A requested TTL is capped at the configured maximum.
func TestActivateBreakGlass_CapsTTL(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 1*time.Hour) // max 1h

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	act, err := h.CoreService.ActivateBreakGlass(ctx, 2, 10, "incident", "10h")
	require.NoError(t, err)
	require.NotNil(t, act.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(1*time.Hour), *act.ExpiresAt, 2*time.Minute, "10h request capped at the 1h max")
}

// Break-glass refuses when disabled, and a justification is mandatory.
func TestActivateBreakGlass_DisabledAndJustificationRequired(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)

	// Disabled (default policy) → refused.
	_, err := h.CoreService.ActivateBreakGlass(ctx, 2, 10, "incident", "")
	require.Error(t, err)

	// Enabled but no justification → refused.
	enableBreakGlass(h, "editor", time.Hour, time.Hour)
	_, err = h.CoreService.ActivateBreakGlass(ctx, 2, 10, "", "")
	require.Error(t, err)
}

// Revoking an activation removes the grant early and marks it revoked.
func TestRevokeBreakGlass_RemovesGrant(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "incident", "")
	require.NoError(t, err)

	require.NoError(t, h.CoreService.RevokeBreakGlass(ctx, 1, proj, act.ID))

	// The emergency role is gone.
	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.NotContains(t, ids, uint(3))

	// The record is revoked, and re-revoking fails.
	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, core.BreakGlassRevoked, list[0].State)
	require.Error(t, h.CoreService.RevokeBreakGlass(ctx, 1, proj, act.ID))
}

// List reports an active record past its expiry as expired (lazy reconciliation).
func TestListBreakGlassActivations_ExpiredReconciliation(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)

	const proj = uint(2)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	require.NoError(t, h.DB.Create(&models.BreakGlassActivation{
		ProjectID: proj, UserID: 10, RoleID: 3, RoleName: "editor",
		Justification: "old", State: core.BreakGlassActive, ExpiresAt: &past, CreatedAt: past,
	}).Error)

	list, err := h.CoreService.ListBreakGlassActivations(ctx, proj)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, core.BreakGlassExpired, list[0].State, "an active grant past expiry reads as expired")
}
