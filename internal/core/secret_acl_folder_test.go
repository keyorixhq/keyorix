// secret_acl_folder_test.go — Unit tests for per-folder ACL inheritance.
//
// These tests cover the folder-ACL inheritance walk in HasSecretACL.
// They use MockStorage so the full SecretNode tree can be constructed in
// memory without a real database.
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newMockACLCore returns a KeyorixCore backed by the given MockStorage.
func newMockACLCore(ms *MockStorage) *KeyorixCore {
	return NewKeyorixCore(ms)
}

// --- helpers ---

// mockNoACL registers a GetSecretACL expectation that returns nil (no entry, not found error).
func mockNoACL(ms *MockStorage, secretID, userID uint) {
	ms.On("GetSecretACL", mock.Anything, secretID, userID).
		Return((*models.SecretACL)(nil), fmt.Errorf("not found"))
}

// mockAllowACL registers a GetSecretACL expectation that returns an ACL with the given perms.
func mockAllowACL(ms *MockStorage, secretID, userID uint, perms ...string) {
	encoded, _ := EncodeSecretACLPerms(perms)
	ms.On("GetSecretACL", mock.Anything, secretID, userID).
		Return(&models.SecretACL{
			SecretID:    secretID,
			UserID:      userID,
			Permissions: encoded,
		}, nil)
}

// --- HasSecretACL tests ---

// TestHasSecretACL_DirectAllow verifies that a direct ACL on the secret node
// itself (no folder walk needed) returns true.
func TestHasSecretACL_DirectAllow(t *testing.T) {
	ms := new(MockStorage)
	c := newMockACLCore(ms)
	ctx := context.Background()

	const (
		secretID = uint(10)
		userID   = uint(1)
		perm     = "secrets.read"
	)

	mockAllowACL(ms, secretID, userID, perm)
	// Ancestors should not be needed once direct ACL is decided.

	got, err := c.HasSecretACL(ctx, userID, secretID, perm)
	require.NoError(t, err)
	assert.True(t, got, "direct ACL should grant access")
	// GetSecretAncestors must NOT be called — resolved at the node level.
	ms.AssertNotCalled(t, "GetSecretAncestors")
	ms.AssertExpectations(t)
}

// TestHasSecretACL_NoDirectACL_FolderInheritance verifies that an ACL on a
// parent folder is inherited by a child secret when the secret has no direct ACL.
func TestHasSecretACL_NoDirectACL_FolderInheritance(t *testing.T) {
	ms := new(MockStorage)
	c := newMockACLCore(ms)
	ctx := context.Background()

	const (
		folderID = uint(5)
		secretID = uint(10)
		userID   = uint(1)
		perm     = "secrets.read"
	)

	// No ACL directly on the secret.
	mockNoACL(ms, secretID, userID)
	// Ancestor walk returns the folder.
	ms.On("GetSecretAncestors", mock.Anything, secretID).Return([]uint{folderID}, nil)
	// Allow ACL on the folder.
	mockAllowACL(ms, folderID, userID, perm)

	got, err := c.HasSecretACL(ctx, userID, secretID, perm)
	require.NoError(t, err)
	assert.True(t, got, "folder ACL should be inherited by child secret")
	ms.AssertExpectations(t)
}

// TestHasSecretACL_GrandparentInheritance verifies that a folder ACL at depth 2
// (grandparent) is inherited by a grandchild secret when neither the secret
// itself nor its direct parent folder carries an ACL.
func TestHasSecretACL_GrandparentInheritance(t *testing.T) {
	ms := new(MockStorage)
	c := newMockACLCore(ms)
	ctx := context.Background()

	const (
		grandparentFolderID = uint(3)
		parentFolderID      = uint(5)
		secretID            = uint(10)
		userID              = uint(1)
		perm                = "secrets.read"
	)

	// No ACL on the secret.
	mockNoACL(ms, secretID, userID)
	// Ancestor chain: parent first, then grandparent.
	ms.On("GetSecretAncestors", mock.Anything, secretID).
		Return([]uint{parentFolderID, grandparentFolderID}, nil)
	// No ACL on parent folder.
	mockNoACL(ms, parentFolderID, userID)
	// Allow ACL on grandparent folder.
	mockAllowACL(ms, grandparentFolderID, userID, perm)

	got, err := c.HasSecretACL(ctx, userID, secretID, perm)
	require.NoError(t, err)
	assert.True(t, got, "grandparent folder ACL should be inherited by grandchild secret")
	ms.AssertExpectations(t)
}

// TestHasSecretACL_DirectOverridesFolder verifies that a more-specific direct
// secret ACL takes precedence over a folder-level ACL: the secret-level
// allow should be returned without ever consulting ancestors.
func TestHasSecretACL_DirectOverridesFolder(t *testing.T) {
	ms := new(MockStorage)
	c := newMockACLCore(ms)
	ctx := context.Background()

	const (
		secretID = uint(10)
		userID   = uint(1)
		perm     = "secrets.read"
	)

	// Secret-level allow (more specific).
	mockAllowACL(ms, secretID, userID, perm)
	// The ancestor call should not even be made once the secret-level ACL is decided.

	got, err := c.HasSecretACL(ctx, userID, secretID, perm)
	require.NoError(t, err)
	assert.True(t, got, "secret-level ACL must be used before consulting folders")
	// GetSecretAncestors must NOT be called.
	ms.AssertNotCalled(t, "GetSecretAncestors")
	ms.AssertExpectations(t)
}

// TestHasSecretACL_UnrelatedFolderNotGranted verifies that a folder ACL does NOT
// grant access to secrets outside that folder tree.
func TestHasSecretACL_UnrelatedFolderNotGranted(t *testing.T) {
	ms := new(MockStorage)
	c := newMockACLCore(ms)
	ctx := context.Background()

	const (
		unrelatedFolderID = uint(99)
		secretID          = uint(10)
		userID            = uint(1)
		perm              = "secrets.read"
	)

	// No ACL on the secret.
	mockNoACL(ms, secretID, userID)
	// Ancestor chain for this secret has no ancestors (it is at the root).
	ms.On("GetSecretAncestors", mock.Anything, secretID).Return([]uint{}, nil)

	// The unrelated folder's ACL is never consulted.
	got, err := c.HasSecretACL(ctx, userID, secretID, perm)
	require.NoError(t, err)
	assert.False(t, got, "ACL on an unrelated folder must not grant access to secrets in another folder")
	ms.AssertExpectations(t)
	// Unrelated folder GetSecretACL must never be called.
	ms.AssertNotCalled(t, "GetSecretACL", mock.Anything, unrelatedFolderID, mock.Anything)
}

// TestHasSecretACL_CycleProtection verifies that a circular ParentID reference
// in the ancestor chain does not cause an infinite loop. GetSecretAncestors is
// expected to cap the walk at maxAncestorDepth (20) and return whatever it found.
func TestHasSecretACL_CycleProtection(t *testing.T) {
	ms := new(MockStorage)
	c := newMockACLCore(ms)
	ctx := context.Background()

	const (
		secretID = uint(10)
		userID   = uint(1)
		perm     = "secrets.read"
	)

	// No ACL on the secret.
	mockNoACL(ms, secretID, userID)

	// Simulate a cycle: storage returns a bounded list (depth-capped) of ancestor
	// IDs with no ACL on any of them. The test verifies no panic / hang occurs.
	ancestors := []uint{20, 21, 22}
	ms.On("GetSecretAncestors", mock.Anything, secretID).Return(ancestors, nil)
	for _, id := range ancestors {
		mockNoACL(ms, id, userID)
	}

	got, err := c.HasSecretACL(ctx, userID, secretID, perm)
	require.NoError(t, err, "cycle in ancestor chain must not error")
	assert.False(t, got, "no ACL entry anywhere means denied")
	ms.AssertExpectations(t)
}

// TestHasSecretACL_RemoteStorageSkipsAncestorWalk verifies that when
// GetSecretAncestors returns ErrUnsupportedByBackend (as RemoteStorage does),
// only the node-level ACL is consulted — no ancestor walk happens — and the
// function returns without error.
func TestHasSecretACL_RemoteStorageSkipsAncestorWalk(t *testing.T) {
	ms := new(MockStorage)
	c := newMockACLCore(ms)
	ctx := context.Background()

	const (
		secretID = uint(10)
		userID   = uint(1)
		perm     = "secrets.read"
	)

	// No ACL on the secret itself.
	mockNoACL(ms, secretID, userID)
	// Simulate RemoteStorage returning ErrUnsupportedByBackend (properly wrapped).
	ms.On("GetSecretAncestors", mock.Anything, secretID).
		Return(([]uint)(nil), fmt.Errorf("GetSecretAncestors: %w", storage.ErrUnsupportedByBackend))

	// Should not error, just skip the folder walk.
	got, err := c.HasSecretACL(ctx, userID, secretID, perm)
	require.NoError(t, err, "wrapped ErrUnsupportedByBackend must not propagate as an error")
	assert.False(t, got, "no ACL without ancestor walk means denied")
	ms.AssertExpectations(t)
}
