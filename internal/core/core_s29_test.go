// core_s29_test.go — sprint-29 coverage blitz:
// secrets_validation.go (validateCreateSecretRequest, validateUpdateSecretRequest),
// groups.go (GetGroupMembers, validateCreateGroupRequest, validateUpdateGroupRequest),
// secret_description.go (validateNameLength),
// secrets_versions.go (isVersionConflict),
// compliance_digest.go (plural),
// membership_lifecycle.go (transitionVerb),
// machine_identities.go (machineVerb),
// rotation_executor.go (resolveCharset),
// scim_groups.go (filterNonZero),
// secrets.go (GetSecretByNameWithPermissionCheck, UpdateSecretWithPermissionCheck, DeleteSecretWithPermissionCheck),
// audit_retention.go (AuditRetentionCoverage, VerifyAuditChain),
// jit_access.go (AssignGroupRoleWithExpiry extra branches),
// account.go (ChangePassword, passwordReused, applyNewPassword),
// secret_listing_query.go (sortSecrets),
// oidc.go (DeleteOIDCBinding),
// rbac.go (AssignRoleToUser, RemoveRoleFromUser).
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── secrets_validation.go ─────────────────────────────────────────────────────

func TestValidateCreateSecretRequest_EmptyName(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateCreateSecretRequest(&CreateSecretRequest{Value: []byte("v"), ProjectID: 1, EnvironmentID: 1, CreatedBy: "me"})
	require.Error(t, err)
}

func TestValidateCreateSecretRequest_NameTooLong(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	err := c.validateCreateSecretRequest(&CreateSecretRequest{Name: string(long), Value: []byte("v"), ProjectID: 1, EnvironmentID: 1, CreatedBy: "me"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestValidateCreateSecretRequest_EmptyValue(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateCreateSecretRequest(&CreateSecretRequest{Name: "n", ProjectID: 1, EnvironmentID: 1, CreatedBy: "me"})
	require.Error(t, err)
}

func TestValidateCreateSecretRequest_ZeroProjectID(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateCreateSecretRequest(&CreateSecretRequest{Name: "n", Value: []byte("v"), EnvironmentID: 1, CreatedBy: "me"})
	require.Error(t, err)
}

func TestValidateCreateSecretRequest_ZeroEnvironmentID(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateCreateSecretRequest(&CreateSecretRequest{Name: "n", Value: []byte("v"), ProjectID: 1, CreatedBy: "me"})
	require.Error(t, err)
}

func TestValidateCreateSecretRequest_EmptyCreatedBy(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateCreateSecretRequest(&CreateSecretRequest{Name: "n", Value: []byte("v"), ProjectID: 1, EnvironmentID: 1})
	require.Error(t, err)
}

func TestValidateCreateSecretRequest_Valid(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateCreateSecretRequest(&CreateSecretRequest{Name: "n", Value: []byte("v"), ProjectID: 1, EnvironmentID: 1, CreatedBy: "me"})
	require.NoError(t, err)
}

func TestValidateUpdateSecretRequest_ZeroID(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateUpdateSecretRequest(&UpdateSecretRequest{UpdatedBy: "me"})
	require.Error(t, err)
}

func TestValidateUpdateSecretRequest_EmptyUpdatedBy(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateUpdateSecretRequest(&UpdateSecretRequest{ID: 1})
	require.Error(t, err)
}

func TestValidateUpdateSecretRequest_Valid(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateUpdateSecretRequest(&UpdateSecretRequest{ID: 1, UpdatedBy: "me"})
	require.NoError(t, err)
}

// ── secret_description.go — validateNameLength ─────────────────────────────

func TestValidateNameLength_OK(t *testing.T) {
	err := validateNameLength("secret name", "hello")
	require.NoError(t, err)
}

func TestValidateNameLength_TooLong(t *testing.T) {
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'x'
	}
	err := validateNameLength("secret name", string(long))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestValidateDescription_OK(t *testing.T) {
	err := validateDescription("short")
	require.NoError(t, err)
}

func TestValidateDescription_TooLong(t *testing.T) {
	long := make([]byte, 1025)
	for i := range long {
		long[i] = 'd'
	}
	err := validateDescription(string(long))
	require.Error(t, err)
}

// ── secrets_versions.go — isVersionConflict ────────────────────────────────

func TestIsVersionConflict_Nil(t *testing.T) {
	assert.False(t, isVersionConflict(nil))
}

func TestIsVersionConflict_Sentinel(t *testing.T) {
	assert.True(t, isVersionConflict(storage.ErrDuplicateSecretVersion))
}

func TestIsVersionConflict_SQLite(t *testing.T) {
	assert.True(t, isVersionConflict(errors.New("UNIQUE constraint failed: secret_versions.node_id")))
}

func TestIsVersionConflict_Postgres(t *testing.T) {
	assert.True(t, isVersionConflict(errors.New("duplicate key value violates unique constraint \"secret_versions_pkey\"")))
}

func TestIsVersionConflict_Other(t *testing.T) {
	assert.False(t, isVersionConflict(errors.New("some other error")))
}

// ── compliance_digest.go — plural ─────────────────────────────────────────

func TestPlural_One(t *testing.T) {
	assert.Equal(t, "", plural(1))
}

func TestPlural_Many(t *testing.T) {
	assert.Equal(t, "s", plural(0))
	assert.Equal(t, "s", plural(2))
}

// ── membership_lifecycle.go — transitionVerb ─────────────────────────────

func TestTransitionVerb_KnownStates(t *testing.T) {
	assert.Equal(t, "identity_verified", transitionVerb(MembershipIdentityVerified))
	assert.Equal(t, "provisioned", transitionVerb(MembershipProvisioned))
	assert.Equal(t, "activated", transitionVerb(MembershipActive))
	assert.Equal(t, "revoked", transitionVerb(MembershipRevoked))
}

func TestTransitionVerb_Unknown(t *testing.T) {
	assert.Equal(t, "custom_state", transitionVerb("custom_state"))
}

// ── machine_identities.go — machineVerb ─────────────────────────────────

func TestMachineVerb_KnownStates(t *testing.T) {
	assert.Equal(t, "activated", machineVerb(MachineActive))
	assert.Equal(t, "suspended", machineVerb(MachineSuspended))
	assert.Equal(t, "revoked", machineVerb(MachineRevoked))
}

func TestMachineVerb_Unknown(t *testing.T) {
	assert.Equal(t, "some_state", machineVerb("some_state"))
}

// ── rotation_executor.go — resolveCharset ────────────────────────────────

func TestResolveCharset_LowerAlnum(t *testing.T) {
	result := resolveCharset("lower_alphanumeric")
	assert.Equal(t, charsetLowerAlnum, result)
}

func TestResolveCharset_Hex(t *testing.T) {
	result := resolveCharset("hex")
	assert.Equal(t, charsetHex, result)
}

func TestResolveCharset_AlnumSymbols(t *testing.T) {
	result := resolveCharset("alphanumeric_symbols")
	assert.Equal(t, charsetAlnumSymbols, result)
}

func TestResolveCharset_Default(t *testing.T) {
	result := resolveCharset("unknown")
	assert.Equal(t, charsetAlphanumeric, result)
}

// ── scim_groups.go — filterNonZero ───────────────────────────────────────

func TestFilterNonZero_Empty(t *testing.T) {
	result := filterNonZero([]uint{})
	assert.Empty(t, result)
}

func TestFilterNonZero_WithZeros(t *testing.T) {
	result := filterNonZero([]uint{0, 1, 0, 2, 3})
	assert.Equal(t, []uint{1, 2, 3}, result)
}

func TestFilterNonZero_AllNonZero(t *testing.T) {
	result := filterNonZero([]uint{1, 2, 3})
	assert.Equal(t, []uint{1, 2, 3}, result)
}

// ── groups.go — GetGroupMembers ───────────────────────────────────────────

func TestGetGroupMembers_ZeroID(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	_, err := c.GetGroupMembers(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group ID is required")
}

func TestGetGroupMembers_StorageError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListGroupMembers", mock.Anything, uint(1)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.GetGroupMembers(context.Background(), 1)
	require.Error(t, err)
}

func TestGetGroupMembers_Success(t *testing.T) {
	ms := new(MockStorage)
	members := []*models.User{{ID: 1, Username: "alice"}}
	ms.On("ListGroupMembers", mock.Anything, uint(1)).Return(members, nil)
	c := NewKeyorixCore(ms)
	result, err := c.GetGroupMembers(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

// ── groups.go — validateCreateGroupRequest ───────────────────────────────

func TestValidateCreateGroupRequest_EmptyName(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateCreateGroupRequest(&CreateGroupRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group name is required")
}

func TestValidateCreateGroupRequest_NameTooLong(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	err := c.validateCreateGroupRequest(&CreateGroupRequest{Name: string(long)})
	require.Error(t, err)
}

func TestValidateCreateGroupRequest_DescriptionTooLong(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	long := make([]byte, 1025)
	for i := range long {
		long[i] = 'd'
	}
	err := c.validateCreateGroupRequest(&CreateGroupRequest{Name: "mygroup", Description: string(long)})
	require.Error(t, err)
}

func TestValidateCreateGroupRequest_Valid(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateCreateGroupRequest(&CreateGroupRequest{Name: "mygroup"})
	require.NoError(t, err)
}

// ── groups.go — validateUpdateGroupRequest ───────────────────────────────

func TestValidateUpdateGroupRequest_ZeroID(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateUpdateGroupRequest(&UpdateGroupRequest{Name: "mygroup"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group ID is required")
}

func TestValidateUpdateGroupRequest_NameTooLong(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	err := c.validateUpdateGroupRequest(&UpdateGroupRequest{ID: 1, Name: string(long)})
	require.Error(t, err)
}

func TestValidateUpdateGroupRequest_Valid(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.validateUpdateGroupRequest(&UpdateGroupRequest{ID: 1, Name: "mygroup"})
	require.NoError(t, err)
}

// ── secret_listing_query.go — sortSecrets ────────────────────────────────

func TestSortSecrets_ByName(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	now := time.Now()
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: &models.SecretNode{Name: "zebra", CreatedAt: now}},
		{SecretNode: &models.SecretNode{Name: "apple", CreatedAt: now}},
	}
	c.sortSecrets(secrets, "name", "asc")
	assert.Equal(t, "apple", secrets[0].Name)
	assert.Equal(t, "zebra", secrets[1].Name)
}

func TestSortSecrets_ByNameDesc(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	now := time.Now()
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: &models.SecretNode{Name: "apple", CreatedAt: now}},
		{SecretNode: &models.SecretNode{Name: "zebra", CreatedAt: now}},
	}
	c.sortSecrets(secrets, "name", "desc")
	assert.Equal(t, "zebra", secrets[0].Name)
}

func TestSortSecrets_ByCreatedAt(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: &models.SecretNode{Name: "a", CreatedAt: older}},
		{SecretNode: &models.SecretNode{Name: "b", CreatedAt: newer}},
	}
	c.sortSecrets(secrets, "created_at", "asc")
	assert.Equal(t, "a", secrets[0].Name)
}

func TestSortSecrets_ByCreatedAtDesc(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: &models.SecretNode{Name: "a", CreatedAt: older}},
		{SecretNode: &models.SecretNode{Name: "b", CreatedAt: newer}},
	}
	c.sortSecrets(secrets, "created_at", "desc")
	assert.Equal(t, "b", secrets[0].Name)
}

func TestSortSecrets_ByOwner(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	now := time.Now()
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: &models.SecretNode{Name: "a", CreatedAt: now}, OwnerUsername: "bob"},
		{SecretNode: &models.SecretNode{Name: "b", CreatedAt: now}, OwnerUsername: "alice"},
	}
	c.sortSecrets(secrets, "owner", "asc")
	assert.Equal(t, "alice", secrets[0].OwnerUsername)
}

func TestSortSecrets_ByOwnerDesc(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	now := time.Now()
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: &models.SecretNode{Name: "a", CreatedAt: now}, OwnerUsername: "alice"},
		{SecretNode: &models.SecretNode{Name: "b", CreatedAt: now}, OwnerUsername: "bob"},
	}
	c.sortSecrets(secrets, "owner", "desc")
	assert.Equal(t, "bob", secrets[0].OwnerUsername)
}

func TestSortSecrets_ByUpdatedAtDefault(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: &models.SecretNode{Name: "a", UpdatedAt: older}},
		{SecretNode: &models.SecretNode{Name: "b", UpdatedAt: newer}},
	}
	// Default sort is updated_at desc.
	c.sortSecrets(secrets, "", "")
	assert.Equal(t, "b", secrets[0].Name)
}

func TestSortSecrets_UpdatedAtAsc(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: &models.SecretNode{Name: "a", UpdatedAt: newer}},
		{SecretNode: &models.SecretNode{Name: "b", UpdatedAt: older}},
	}
	c.sortSecrets(secrets, "updated_at", "asc")
	assert.Equal(t, "b", secrets[0].Name)
}

// ── secrets.go — GetSecretByNameWithPermissionCheck ──────────────────────

func TestGetSecretByNameWithPermissionCheck_NotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecretByName", mock.Anything, "missing", uint(1), uint(1)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretByNameWithPermissionCheck(context.Background(), "missing", 1, 1, 1)
	require.Error(t, err)
}

func TestGetSecretByNameWithPermissionCheck_PermissionDenied(t *testing.T) {
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 5, OwnerID: 99}
	ms.On("GetSecretByName", mock.Anything, "mysecret", uint(1), uint(1)).Return(secret, nil)
	ms.On("GetSecret", mock.Anything, uint(5)).Return(secret, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(5)).Return([]*models.ShareRecord{}, nil)
	ms.On("GetUserGroups", mock.Anything, uint(2)).Return([]*models.Group{}, nil)
	// RBAC fallback (r124): no roles → deny.
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretByNameWithPermissionCheck(context.Background(), "mysecret", 1, 1, 2)
	require.Error(t, err)
}

// ── secrets.go — UpdateSecretWithPermissionCheck ─────────────────────────

func TestUpdateSecretWithPermissionCheck_ZeroUserID_s29(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	_, err := c.UpdateSecretWithPermissionCheck(context.Background(), &UpdateSecretRequest{ID: 1, UpdatedBy: "me"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestUpdateSecretWithPermissionCheck_PermissionDenied(t *testing.T) {
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 1, OwnerID: 99} // user 2 is not owner
	ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	ms.On("GetUserGroups", mock.Anything, uint(2)).Return([]*models.Group{}, nil)
	// RBAC fallback (r124): no roles → deny.
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.UpdateSecretWithPermissionCheck(context.Background(), &UpdateSecretRequest{ID: 1, UserID: 2, UpdatedBy: "me"})
	require.Error(t, err)
}

// ── secrets.go — DeleteSecretWithPermissionCheck ─────────────────────────

func TestDeleteSecretWithPermissionCheck_ZeroUserID_s29(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	err := c.DeleteSecretWithPermissionCheck(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestDeleteSecretWithPermissionCheck_PermissionDenied(t *testing.T) {
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 1, OwnerID: 99}
	ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	ms.On("GetUserGroups", mock.Anything, uint(2)).Return([]*models.Group{}, nil)
	// RBAC fallback (r124): no roles → deny.
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	c := NewKeyorixCore(ms)
	err := c.DeleteSecretWithPermissionCheck(context.Background(), 1, 2)
	require.Error(t, err)
}

// ── audit_retention.go — AuditRetentionCoverage, VerifyAuditChain ────────

func TestAuditRetentionCoverage_StorageError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("AuditRetentionStats", mock.Anything).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.AuditRetentionCoverage(context.Background())
	require.Error(t, err)
}

func TestAuditRetentionCoverage_Success(t *testing.T) {
	ms := new(MockStorage)
	ms.On("AuditRetentionStats", mock.Anything).Return(&storage.AuditRetentionStats{TotalEvents: 10}, nil)
	c := NewKeyorixCore(ms)
	result, err := c.AuditRetentionCoverage(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(10), result.TotalEvents)
}

func TestVerifyAuditChain_StorageError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("VerifyAuditChain", mock.Anything).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.VerifyAuditChain(context.Background())
	require.Error(t, err)
}

func TestVerifyAuditChain_Valid(t *testing.T) {
	ms := new(MockStorage)
	ms.On("VerifyAuditChain", mock.Anything).Return(&storage.AuditChainVerification{
		Valid:         true,
		ChainedEvents: 5,
	}, nil)
	// No key set → AuditCheckpointsAvailable returns false → enforceAuditCheckpoint is a no-op.
	c := NewKeyorixCore(ms)
	result, err := c.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	assert.True(t, result.Valid)
}
