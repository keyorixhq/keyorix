package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestDeleteUser_RecordsActorInAuditEvent guards #356: deleting a user must
// leave an audit trail attributing the actor who performed the deletion (via
// the threaded actorID parameter), matching the audited convention already
// used by SuspendUser/ReactivateUser/RequirePasswordReset.
func TestDeleteUser_RecordsActorInAuditEvent(t *testing.T) {
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()

	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2}, nil)
	store.On("DeleteUser", ctx, uint(2)).Return(nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "user.deleted" && e.UserID != nil && *e.UserID == uint(7)
	})).Return(nil)

	require.NoError(t, c.DeleteUser(ctx, 7, 2))
	store.AssertExpectations(t)
}

// TestDeleteUser_ZeroActorOmitsAttribution confirms an unset actor (0) is not
// recorded as a spurious "user 0" attribution — the audit event's UserID is
// left nil rather than pointing at a nonexistent actor.
func TestDeleteUser_ZeroActorOmitsAttribution(t *testing.T) {
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()

	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2}, nil)
	store.On("DeleteUser", ctx, uint(2)).Return(nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "user.deleted" && e.UserID == nil
	})).Return(nil)

	require.NoError(t, c.DeleteUser(ctx, 0, 2))
	store.AssertExpectations(t)
}
