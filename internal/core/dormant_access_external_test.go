package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The access review annotates user grants with their last secret-access time (the
// most recent of several reads), and leaves it nil for a user with no recorded
// activity — the dormant-access signal.
func TestGenerateProjectAccessReview_AnnotatesLastUsed(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "bob", 11)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // alice editor — has activity
	h.AssignUserRole(t, 11, 4, uptr(proj)) // bob viewer — never used it

	pid := proj
	aid := uint(10)
	older := time.Now().Add(-72 * time.Hour)
	newer := time.Now().Add(-1 * time.Hour)
	require.NoError(t, h.DB.Create(&models.AuditEvent{EventType: "secret.read", UserID: &aid, ProjectID: &pid, EventTime: older}).Error)
	require.NoError(t, h.DB.Create(&models.AuditEvent{EventType: "secret.read", UserID: &aid, ProjectID: &pid, EventTime: newer}).Error)

	review, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)

	var alice, bob *core.AccessReviewEntry
	for _, e := range review {
		switch e.PrincipalName {
		case "alice":
			alice = e
		case "bob":
			bob = e
		}
	}
	require.NotNil(t, alice)
	require.NotNil(t, bob)
	require.NotNil(t, alice.LastUsedAt, "alice has recorded secret access")
	assert.WithinDuration(t, newer, *alice.LastUsedAt, time.Second, "the most recent access wins")
	assert.Nil(t, bob.LastUsedAt, "bob has no activity → dormant standing access")
}

// Activity in another project does not count toward this project's last-used.
func TestGenerateProjectAccessReview_LastUsedIsProjectScoped(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	aid := uint(10)
	otherProj := uint(3)
	require.NoError(t, h.DB.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &aid, ProjectID: &otherProj, EventTime: time.Now(),
	}).Error)

	review, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	require.Len(t, review, 1)
	assert.Nil(t, review[0].LastUsedAt, "activity in project 3 doesn't count for project 2")
}
