// sod_admin_role_getrole_error_test.go — deterministic unit test for
// docs/findings/2026-10-02-FINDING-sod-policy-create-getrole-error-misread-as-not-admin.md:
// isGlobalAdminRoleName's GetRole-error `continue` was indistinguishable from a
// successful lookup resolving to a non-admin role, so CreateSoDPolicy denied (and
// audited as a DENIAL) a genuine admin whenever the one GetRole call it needs
// transiently failed.
package core

import (
	"context"
	"errors"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getRoleErrStub wraps a real storage.Storage and overrides exactly GetRole
// to inject a fixed error, mirroring the secretReadErrStub /
// mfaSecretReadErrStub pattern used elsewhere in this package.
type getRoleErrStub struct {
	corestorage.Storage
	err error
}

func (s *getRoleErrStub) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Storage.GetRole(ctx, id)
}

// TestCreateSoDPolicy_GetRoleErrorIsNotMisreadAsNonAdmin: the bootstrapped
// admin's sole role is an admin-tier role (per isGlobalAdminRoleName's own
// reproduction in the finding). A GetRole failure resolving that one role must
// surface as a retrieval error, not a permission-denied, and must NOT write a
// "DENIED: not admin-tier" audit event for an actor who was never actually
// evaluated as non-admin.
func TestCreateSoDPolicy_GetRoleErrorIsNotMisreadAsNonAdmin(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = &getRoleErrStub{Storage: realStorage, err: faultErr}

	_, err = c.CreateSoDPolicy(ctx, admin.ID, "fault-test-policy", "", "secrets.read", "secrets.write")
	require.Error(t, err, "a GetRole storage error must still refuse the create")
	assert.NotContains(t, err.Error(), "admin-tier",
		"a storage error must not be reported as a permission denial")
	assert.ErrorIs(t, err, faultErr, "the real storage error must be visible to the caller, not swallowed")

	// No DENIED audit event, and no policy, from the faulted attempt.
	var deniedCount int64
	require.NoError(t, st.DB().Model(&models.AuditEvent{}).
		Where("description LIKE ?", "%DENIED: not admin-tier%").Count(&deniedCount).Error)
	assert.Zero(t, deniedCount,
		"a storage error must not be audited as a confirmed non-admin denial")

	policies, err := c.ListSoDPolicies(ctx)
	require.NoError(t, err)
	assert.Empty(t, policies, "the faulted create must not have persisted a policy")

	// Fault clears: the SAME admin, never actually demoted, can now create the
	// policy — proving admin status was never really lost, just unconfirmable.
	c.storage = realStorage
	policy, err := c.CreateSoDPolicy(ctx, admin.ID, "fault-test-policy", "", "secrets.read", "secrets.write")
	require.NoError(t, err)
	require.NotNil(t, policy)
}
