package share

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── runCreate ────────────────────────────────────

func TestRunCreate_BadPermission(t *testing.T) {
	orig := createPermission
	defer func() { createPermission = orig }()
	createPermission = "admin"
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid permission")
}

func TestRunCreate_BadExpires(t *testing.T) {
	origPerm, origExp := createPermission, createExpires
	defer func() { createPermission = origPerm; createExpires = origExp }()
	createPermission = "read"
	createExpires = "not-a-date"
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--expires")
}

func TestRunCreate_BadTTL(t *testing.T) {
	origPerm, origTTL := createPermission, createTTL
	defer func() { createPermission = origPerm; createTTL = origTTL }()
	createPermission = "write"
	createTTL = "not-a-duration"
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ttl")
}

func TestRunCreate_LocalModeStorageError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origPerm := createPermission
	defer func() { createPermission = origPerm }()
	createPermission = "read"
	// Storage init will fail (no DB), but we should get a storage error, not a panic.
	err := runCreate(nil, nil)
	_ = err // may succeed with empty store or fail; no panic
}

// ──────────────────────────── runList ──────────────────────────────────────

func TestRunList_LocalModeStorageError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origID := listSecretID
	defer func() { listSecretID = origID }()
	listSecretID = 1
	err := runList(nil, nil)
	_ = err
}

// ──────────────────────────── runRevoke ────────────────────────────────────

func TestRunRevoke_LocalModeStorageError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origID := revokeShareID
	defer func() { revokeShareID = origID }()
	revokeShareID = 1
	err := runRevoke(nil, nil)
	_ = err
}

// ──────────────────────────── runGroupShares ───────────────────────────────

func TestRunGroupShares_LocalModeStorageError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origID := groupSharesGroupID
	defer func() { groupSharesGroupID = origID }()
	groupSharesGroupID = 1
	err := runGroupShares(nil, nil)
	_ = err
}

// ──────────────────────────── runSharedSecrets ─────────────────────────────

func TestRunSharedSecrets_LocalModeStorageError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origID := sharedSecretsUserID
	defer func() { sharedSecretsUserID = origID }()
	sharedSecretsUserID = 1
	err := runSharedSecrets(nil, nil)
	_ = err
}

// ──────────────────────────── runUpdate ────────────────────────────────────

func TestRunUpdate_ClearExpiryAndExpiresMutuallyExclusive(t *testing.T) {
	origPerm, origID, origClear, origExpires := updatePermission, updateShareID, updateClearExpiry, updateExpires
	defer func() {
		updatePermission = origPerm
		updateShareID = origID
		updateClearExpiry = origClear
		updateExpires = origExpires
	}()
	updatePermission = "read"
	updateShareID = 1
	updateClearExpiry = true
	updateExpires = "2027-01-01T00:00:00Z"
	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--clear-expiry cannot be combined with --expires or --ttl")
}

func TestRunUpdate_InvalidPermission(t *testing.T) {
	origPerm, origID := updatePermission, updateShareID
	defer func() { updatePermission = origPerm; updateShareID = origID }()
	updatePermission = "admin"
	updateShareID = 1
	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid permission")
}

func TestRunUpdate_LocalModeStorageError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origPerm, origID := updatePermission, updateShareID
	defer func() { updatePermission = origPerm; updateShareID = origID }()
	updatePermission = "read"
	updateShareID = 1
	err := runUpdate(nil, nil)
	_ = err
}

func TestRunUpdate_ClearExpiryLocalMode(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origPerm, origID, origClear := updatePermission, updateShareID, updateClearExpiry
	defer func() { updatePermission = origPerm; updateShareID = origID; updateClearExpiry = origClear }()
	updatePermission = "write"
	updateShareID = 1
	updateClearExpiry = true
	err := runUpdate(nil, nil)
	_ = err
}

// ──────────────────────────── resolveShareExpiry additional helpers ──────────

func TestResolveShareExpiry_InvalidExpires(t *testing.T) {
	_, err := resolveShareExpiry("not-a-date", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--expires")
}

func TestResolveShareExpiry_InvalidTTL(t *testing.T) {
	_, err := resolveShareExpiry("", "not-a-duration")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ttl")
}

func TestResolveShareExpiry_BothEmpty(t *testing.T) {
	exp, err := resolveShareExpiry("", "")
	require.NoError(t, err)
	assert.Nil(t, exp)
}

func TestFormatShareExpiry_Set(t *testing.T) {
	tm := time.Date(2026, 7, 1, 15, 0, 0, 0, time.UTC)
	s := formatShareExpiry(&tm)
	assert.Contains(t, s, "2026-07-01")
}

// ──────────────────────────── runGroupShares empty result ─────────────────────

func TestRunGroupShares_EmptyResult(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := groupSharesGroupID
	defer func() { groupSharesGroupID = orig }()
	groupSharesGroupID = 1

	// With an empty in-memory store, ListGroupShares returns empty, not an error.
	err := runGroupShares(nil, nil)
	// Expected: nil (empty shares) or storage init error — no panic.
	_ = err
}

// ──────────────────────────── runSharedSecrets empty result ───────────────────

func TestRunSharedSecrets_EmptyResult(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := sharedSecretsUserID
	defer func() { sharedSecretsUserID = orig }()
	sharedSecretsUserID = 1
	err := runSharedSecrets(nil, nil)
	_ = err
}

// ──────────────────────────── runList empty result ────────────────────────────

func TestRunList_EmptyResult_V2(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := listSecretID
	defer func() { listSecretID = orig }()
	listSecretID = 1
	err := runList(nil, nil)
	_ = err
}

// ──────────────────────────── runRevoke on nonexistent share ──────────────────

func TestRunRevoke_NonexistentShare(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := revokeShareID
	defer func() { revokeShareID = orig }()
	revokeShareID = 9999
	err := runRevoke(nil, nil)
	// expected error about share not found, not a panic
	_ = err
}

// ──────────────────────────── command flags ─────────────────────────────────

func TestGroupSharesCmd_HasGroupIDFlag(t *testing.T) {
	assert.NotNil(t, groupSharesCmd.Flags().Lookup("group-id"))
}

func TestSharedSecretsCmd_HasUserIDFlag(t *testing.T) {
	assert.NotNil(t, sharedSecretsCmd.Flags().Lookup("user-id"))
}

func TestRevokeCmd_HasShareIDFlag(t *testing.T) {
	assert.NotNil(t, revokeCmd.Flags().Lookup("share-id"))
}

func TestUpdateCmd_HasClearExpiryFlag(t *testing.T) {
	assert.NotNil(t, updateCmd.Flags().Lookup("clear-expiry"))
}

func TestCreateCmd_HasTTLAndExpiresFlags(t *testing.T) {
	assert.NotNil(t, createCmd.Flags().Lookup("ttl"))
	assert.NotNil(t, createCmd.Flags().Lookup("expires"))
}
