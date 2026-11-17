package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestOwnerGateRecheckReadFaultIsTyped: a storage fault while re-checking an owner's
// gate permission (#4160) fails closed as a storage read fault (503), not an untyped
// 500 (STORAGE-ERR-CLASS-4; REVIEW-4336-DEEP-1 L4).
func TestOwnerGateRecheckReadFaultIsTyped(t *testing.T) {
	t.Parallel()
	c := setupTestCore(t)
	m := c.storage.(*MockStorage)
	m.On("GetSecretACL", mock.Anything, uint(9), uint(5)).Return((*models.SecretACL)(nil), errors.New("connection reset by peer"))
	secret := &models.SecretNode{ID: 9, ProjectID: 1, EnvironmentID: 1, OwnerID: 5}
	err := c.requireOwnerHoldsGatePermission(context.Background(), &PermissionContext{Source: "owner"}, secret, 5, "secrets.write", SecretActionUpdate)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrStorageReadUnavailable)
	require.NotErrorIs(t, err, ErrPermissionDenied)
}
