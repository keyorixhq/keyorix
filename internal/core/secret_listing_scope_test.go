// secret_listing_scope_test.go — unit tests for ListSecretsInScopeWithSharingInfo.
//
// This is the role-visibility listing path: unlike ListSecretsWithSharingInfo
// (ownership/ACL/shares only), it surfaces every secret in the requested scope,
// with sharing metadata overlaid where the caller also owns/holds an ACL/share
// grant on a given secret. See its own doc comment (secret_listing_query.go) for
// why this exists — closing the gap where a project-scoped viewer role could GET
// any individual secret in their project but never discover it via listing.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestListSecretsInScopeWithSharingInfo_RoleOnlyVisibility verifies that a
// secret the caller neither owns nor holds an ACL/share grant for is still
// returned (role-scope visibility), with sharing fields left at their zero
// value (no owned/ACL/shared relationship).
func TestListSecretsInScopeWithSharingInfo_RoleOnlyVisibility(t *testing.T) {
	c, db := newACLListCore(t)
	ctx := context.Background()

	// Owned by user 1, not user 2; no ACL/share grant for user 2 either.
	s := mkACLListSecret(t, db, "role-visible-secret")

	p1 := uint(1)
	filter := &models.SecretListFilter{ProjectID: &p1, Page: 1, PageSize: 20}
	result, err := c.ListSecretsInScopeWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	require.Equal(t, int64(1), result.Total)
	require.Len(t, result.Secrets, 1)
	assert.Equal(t, s.ID, result.Secrets[0].ID)
	assert.False(t, result.Secrets[0].IsOwnedByUser, "not owned by the caller")
	assert.False(t, result.Secrets[0].IsShared, "not shared with the caller")
	assert.Equal(t, 0, result.Secrets[0].ShareCount)
}

// TestListSecretsInScopeWithSharingInfo_OwnedSecretGetsSharingInfo verifies
// that a secret the caller owns is overlaid with real ownership metadata
// (IsOwnedByUser), not left at role-only zero values.
func TestListSecretsInScopeWithSharingInfo_OwnedSecretGetsSharingInfo(t *testing.T) {
	c, db := newACLListCore(t)
	ctx := context.Background()

	// Owned by user 2 directly (mkACLListSecret defaults OwnerID to 1, so build
	// this one explicitly).
	s := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "owned-secret",
		IsSecret: true, Status: "active", OwnerID: 2,
	}
	require.NoError(t, db.Create(s).Error)

	p1 := uint(1)
	filter := &models.SecretListFilter{ProjectID: &p1, Page: 1, PageSize: 20}
	result, err := c.ListSecretsInScopeWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	require.Equal(t, int64(1), result.Total)
	require.Len(t, result.Secrets, 1)
	assert.Equal(t, s.ID, result.Secrets[0].ID)
	assert.True(t, result.Secrets[0].IsOwnedByUser, "ownership metadata must be overlaid onto the role-visible entry")
}

// TestListSecretsInScopeWithSharingInfo_ACLGrantedSecretGetsSharingInfo
// verifies that a secret the caller holds an ACL grant on (but doesn't own)
// is overlaid with ACL sharing metadata.
func TestListSecretsInScopeWithSharingInfo_ACLGrantedSecretGetsSharingInfo(t *testing.T) {
	c, db := newACLListCore(t)
	ctx := context.Background()

	s := mkACLListSecret(t, db, "acl-granted-secret") // owned by user 1
	grantACL(t, db, s.ID, 2, "secrets.read")

	p1 := uint(1)
	filter := &models.SecretListFilter{ProjectID: &p1, Page: 1, PageSize: 20}
	result, err := c.ListSecretsInScopeWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	require.Equal(t, int64(1), result.Total)
	require.Len(t, result.Secrets, 1)
	assert.Equal(t, s.ID, result.Secrets[0].ID)
	assert.False(t, result.Secrets[0].IsOwnedByUser)
	assert.Equal(t, "read", result.Secrets[0].UserPermission, "ACL grant metadata must be overlaid onto the role-visible entry")
}

// TestListSecretsInScopeWithSharingInfo_ProjectBoundary verifies role-scope
// visibility never crosses a project boundary: a secret in project 2 must not
// appear when the filter is scoped to project 1, even though the caller is
// (in this test) authorized to list project 1's scope.
func TestListSecretsInScopeWithSharingInfo_ProjectBoundary(t *testing.T) {
	c, db := newACLListCore(t)
	ctx := context.Background()

	mkACLListSecret(t, db, "p1-secret") // project 1
	sP2 := &models.SecretNode{
		ProjectID: 2, EnvironmentID: 2, Name: "p2-secret",
		IsSecret: true, Status: "active", OwnerID: 1,
	}
	require.NoError(t, db.Create(sP2).Error)

	p1 := uint(1)
	filter := &models.SecretListFilter{ProjectID: &p1, Page: 1, PageSize: 20}
	result, err := c.ListSecretsInScopeWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	require.Equal(t, int64(1), result.Total)
	assert.Equal(t, "p1-secret", result.Secrets[0].Name)
}

// TestListSecretsInScopeWithSharingInfo_EmptyScope verifies an empty scope
// (no secrets at all) returns cleanly with no error and no panics on the
// sharing-info overlay's early-return path.
func TestListSecretsInScopeWithSharingInfo_EmptyScope(t *testing.T) {
	c, _ := newACLListCore(t)
	ctx := context.Background()

	p1 := uint(1)
	filter := &models.SecretListFilter{ProjectID: &p1, Page: 1, PageSize: 20}
	result, err := c.ListSecretsInScopeWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	assert.Empty(t, result.Secrets)
}

// TestListSecretsInScopeWithSharingInfo_UnscopedIncludesSharedSecrets
// verifies the unscoped path (filter.ProjectID == nil): unlike the scoped
// path (which excludes ShareRecord-based sharing lookups, matching
// ListSecretsWithSharingInfo's existing "project view shows owned/ACL only"
// rule), a nil-ProjectID filter attaches share-based sharing metadata too.
func TestListSecretsInScopeWithSharingInfo_UnscopedIncludesSharedSecrets(t *testing.T) {
	c, db := newACLListCore(t)
	ctx := context.Background()

	s := mkACLListSecret(t, db, "shared-secret") // owned by user 1
	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: s.ID, OwnerID: 1, RecipientID: 2, Permission: "read",
	}).Error)

	filter := &models.SecretListFilter{Page: 1, PageSize: 20}
	result, err := c.ListSecretsInScopeWithSharingInfo(ctx, 2, filter)
	require.NoError(t, err)

	require.Equal(t, int64(1), result.Total)
	require.Len(t, result.Secrets, 1)
	assert.Equal(t, s.ID, result.Secrets[0].ID)
	assert.True(t, result.Secrets[0].IsShared, "share-record metadata must be overlaid on the unscoped path")
}
