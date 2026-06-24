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

// With no MaxTTL configured, a requested TTL is still bounded — to the default TTL,
// not honored unbounded. The core enforces "break-glass is time-bound" itself rather
// than relying on the config layer to have supplied a ceiling.
func TestActivateBreakGlass_UnsetMaxTTLFloorsToDefault(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 0) // MaxTTL unset (0)

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	act, err := h.CoreService.ActivateBreakGlass(ctx, 2, 10, "incident", "720h") // 30-day override
	require.NoError(t, err)
	require.NotNil(t, act.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(4*time.Hour), *act.ExpiresAt, 2*time.Minute,
		"with no MaxTTL, an override must be bounded to the default TTL, not honored as 720h")
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

// An expired break-glass grant must confer NO access at the authorization boundary — not
// merely show as "expired" in the activation list. Break-glass self-grants a time-bound
// emergency role; once it lapses, Authorize must deny, relying on the expires_at filter in
// role resolution (GetUserRoleIDsAt). This drives the real activate → authorize → expire
// flow end to end, rather than only the SQL filter in isolation.
func TestBreakGlass_ExpiredGrantDeniesAuthorization(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour) // editor = role 3 (secrets.read + secrets.write)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)

	_, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident", "")
	require.NoError(t, err)

	// While active, the emergency role authorizes a write at the project scope.
	ok, err := h.CoreService.Authorize(ctx, 10, "secrets.write", core.Scope{ProjectID: proj})
	require.NoError(t, err)
	require.True(t, ok, "break-glass must grant the emergency permission while active")

	// Simulate the grant lapsing: push its expiry into the past (equivalent to the TTL
	// elapsing). Role resolution filters out expires_at <= now, so the role drops away.
	require.NoError(t, h.DB.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ?", 10, 3).
		Update("expires_at", time.Now().Add(-time.Hour)).Error)

	// The emergency role no longer resolves...
	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.NotContains(t, ids, uint(3), "an expired emergency role must drop out of role resolution")

	// ...and Authorize denies the permission it used to grant.
	ok, err = h.CoreService.Authorize(ctx, 10, "secrets.write", core.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.False(t, ok, "an expired break-glass grant must confer no access at the authorization boundary")
}
