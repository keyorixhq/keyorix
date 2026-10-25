package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
)

// TestRemoveRoleFromGroup_NotAssigned_WrapsSentinel pins that a group-role
// removal with no matching grant wraps storage.ErrRoleNotAssigned, like
// RemoveRole for a user, so callers can tell "nothing to remove" from a
// storage failure (the HTTP handler answered 500 for it; MERGE-FIX-3585-2).
func TestRemoveRoleFromGroup_NotAssigned_WrapsSentinel(t *testing.T) {
	ls := newRBACStoreMax(t)
	err := ls.RemoveRoleFromGroup(context.Background(), 1, 1, storage.Scope{})
	assert.ErrorIs(t, err, storage.ErrRoleNotAssigned)
}
