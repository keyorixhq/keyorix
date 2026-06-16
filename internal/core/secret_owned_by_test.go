package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestSecretOwnedBy(t *testing.T) {
	cases := []struct {
		name  string
		owner uint
		actor uint
		want  bool
	}{
		{"human owner matches", 5, 5, true},
		{"human non-owner", 5, 6, false},
		{"ownerless vs machine (both zero) is NOT ownership", 0, 0, false},
		{"ownerless vs human", 0, 5, false},
		{"human-owned vs machine actor", 5, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, secretOwnedBy(tc.owner, tc.actor))
		})
	}
}

// TestRevokeShare_MachineCannotManageOwnerlessSecret is the security regression for
// the OwnerID=0 gap: a machine actor (id 0) must NOT be treated as the owner of an
// ownerless (machine-created) secret, so it cannot revoke shares on it.
func TestRevokeShare_MachineCannotManageOwnerlessSecret(t *testing.T) {
	mockStorage := new(MockStorage)
	core := &KeyorixCore{storage: mockStorage}
	ctx := context.Background()

	mockStorage.On("GetShareRecord", ctx, uint(1)).
		Return(&models.ShareRecord{ID: 1, SecretID: 7, OwnerID: 0, RecipientID: 2}, nil)
	mockStorage.On("GetSecret", ctx, uint(7)).
		Return(&models.SecretNode{ID: 7, Name: "machine-secret", OwnerID: 0}, nil)

	// revokedBy = 0 (a machine). Before the fix, 0 == 0 passed the owner gate.
	err := core.RevokeShare(ctx, 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), i18n.T("ErrorPermissionDenied", nil))
	// It must not have proceeded to delete the share.
	mockStorage.AssertNotCalled(t, "DeleteShareRecord", mock.Anything, mock.Anything)
}

// TestShareSecret_OwnerlessSecretNotShareable confirms an ownerless secret can't be
// shared via the owner gate even by a non-zero caller (defence in depth).
func TestShareSecret_OwnerlessSecretNotShareable(t *testing.T) {
	mockStorage := new(MockStorage)
	core := &KeyorixCore{storage: mockStorage}
	ctx := context.Background()

	mockStorage.On("GetSecret", ctx, uint(7)).
		Return(&models.SecretNode{ID: 7, Name: "machine-secret", OwnerID: 0}, nil)

	_, err := core.ShareSecret(ctx, &ShareSecretRequest{
		SecretID: 7, RecipientID: 2, Permission: "read", SharedBy: 9,
	})
	require.Error(t, err)
	mockStorage.AssertNotCalled(t, "CreateShareRecord", mock.Anything, mock.Anything)
}
