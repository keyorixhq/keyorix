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

// breakGlassAuditDescription returns the description of the single audit row of
// eventType.
func breakGlassAuditDescription(t *testing.T, h *testhelper.RBACTestHelper, eventType string) string {
	t.Helper()
	events, _, err := h.Storage.GetAuditLogs(context.Background(), &storage.AuditFilter{Action: &eventType, PageSize: 10})
	require.NoError(t, err)
	require.Len(t, events, 1, "one %s row", eventType)
	return events[0].Description
}

// #3741: break_glass.activated and break_glass.revoked name the user the way
// role.assigned does (`user 10 ("alice")`), not as a bare id.
func TestBreakGlassAudit_NamesTheUser(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident #42", "")
	require.NoError(t, err)
	assert.Contains(t, breakGlassAuditDescription(t, h, core.EventBreakGlassActivated),
		`break-glass: user 10 ("alice") self-granted "editor"`)

	require.NoError(t, h.CoreService.RevokeBreakGlass(ctx, 1, 0, proj, act.ID))
	assert.Contains(t, breakGlassAuditDescription(t, h, core.EventBreakGlassRevoked),
		`(user 10 ("alice"), role "editor") early`)
}

// An unreadable user never fails the revocation: the description falls back to the
// bare id.
func TestBreakGlassAudit_DeletedUserFallsBackToTheID(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	enableBreakGlass(h, "editor", 4*time.Hour, 24*time.Hour)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	makeProjectMember(t, h, 10, proj)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 10, "prod incident #42", "")
	require.NoError(t, err)

	require.NoError(t, h.DB.Delete(&models.User{}, 10).Error, "soft-delete the user")

	require.NoError(t, h.CoreService.RevokeBreakGlass(ctx, 1, 0, proj, act.ID), "an unreadable user must not fail the revoke")
	desc := breakGlassAuditDescription(t, h, core.EventBreakGlassRevoked)
	assert.Contains(t, desc, `(user 10, role "editor") early`)
	assert.NotContains(t, desc, "alice")
}
