// permissions_acl_error_test.go — regression coverage for
// docs/findings/2026-09-23-FINDING-checksecretpermission-acl-error-swallowed.md:
// CheckSecretPermission's ACL-grant block used to swallow a real HasSecretACL
// error (aerr == nil && hasACL) and silently fall through to the RBAC
// fallback, instead of propagating it the way AuthorizeSecret (the
// middleware's equivalent path, authz.go) already correctly does.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckSecretPermission_ACLReadErrorPropagates: a caller with a genuine
// (folder-inherited) ACL grant and NO independent RBAC access must get the
// real error back when the ancestor read that would have found that grant
// fails — not a silent fallthrough to "insufficient permissions" as if no
// grant existed at all.
func TestCheckSecretPermission_ACLReadErrorPropagates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)

	folderID := mkACLFolder(t, db, "acl-err-folder", nil)
	sid := mkACLSecretInFolder(t, db, "acl-err-secret", folderID)

	// A genuine grant, but on the ANCESTOR folder — aclGrantsPermission's
	// direct-secret check finds nothing, so HasSecretACL must reach
	// GetSecretAncestors to find it. Grantee 55 is one of newACLCore's seeded
	// project members but holds no real RBAC role (only the RoleID:999
	// placeholder, which grants nothing).
	require.NoError(t, c.GrantSecretACL(ctx, 99, folderID, 55, []string{"secrets.write"}))

	wantErr := errors.New("ancestors unavailable")
	c2 := newACLCoreWithStorage(c, &ancestorErrStorage{Storage: c.storage, err: wantErr})

	_, err := c2.CheckSecretPermission(ctx, sid, 55, PermissionWrite)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr, "the real ancestor-read failure must propagate, not be swallowed as 'no ACL grant'")
	assert.NotContains(t, err.Error(), "insufficient permissions",
		"must be reported as a real read failure, not conflated with a genuine denial")
}

// TestCheckSecretPermission_ACLGrantWithWorkingRead_Succeeds is the control:
// the identical fixture, with the ancestor read working normally, must grant
// access via the ACL path. Confirms the error-propagation fix above didn't
// also break the success path it guards.
func TestCheckSecretPermission_ACLGrantWithWorkingRead_Succeeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)

	folderID := mkACLFolder(t, db, "acl-ok-folder", nil)
	sid := mkACLSecretInFolder(t, db, "acl-ok-secret", folderID)
	require.NoError(t, c.GrantSecretACL(ctx, 99, folderID, 55, []string{"secrets.write"}))

	permCtx, err := c.CheckSecretPermission(ctx, sid, 55, PermissionWrite)
	require.NoError(t, err)
	require.NotNil(t, permCtx)
	assert.Equal(t, "acl", permCtx.Source)
}

// TestCheckSecretPermission_ACLUnsupportedBackend_StillFallsThroughToRBAC
// confirms the fix didn't touch the OTHER branch HasSecretACL/aclGrantsPermission
// degrade to (false, nil) for: storage.ErrUnsupportedByBackend (a backend that
// doesn't support SecretACL at all, e.g. RemoteStorage's still-unproxied ACL
// read path) must keep falling through to the RBAC fallback exactly as
// before — NOT start being treated as a propagated error. Reuses
// unsupportedACLStorage (secret_acl_test.go) unchanged.
func TestCheckSecretPermission_ACLUnsupportedBackend_StillFallsThroughToRBAC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "acl-unsupported-secret")

	// Grantee 55 has no RBAC role (only the RoleID:999 placeholder) and no ACL
	// grant is even attempted here — the backend doesn't support ACL at all.
	c2 := newACLCoreWithStorage(c, unsupportedACLStorage{Storage: c.storage})

	_, err := c2.CheckSecretPermission(ctx, sid, 55, PermissionWrite)
	require.Error(t, err)
	// Must be the ordinary "no grant found" denial, not a propagated read error —
	// ErrUnsupportedByBackend must never surface as a hard failure here.
	assert.Contains(t, err.Error(), "insufficient permissions")
}
