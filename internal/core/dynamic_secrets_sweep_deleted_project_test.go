// dynamic_secrets_sweep_deleted_project_test.go — #2652 backstop: the expiry sweep
// still revokes a lease whose config DeleteProject's #369 cascade disabled and whose
// project (and environment) it soft-deleted.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestDynamicSecrets_SweepRevokesLeaseUnderDeletedProject pins the bound #2652's
// residual risk depends on. CreateDynamicSecretLease's write-then-FOR-SHARE re-read of
// the config closes the IssueLease vs DeleteProject window, but a lease that ever
// escapes the cascade's own revocation (a revoke_failed drop, a future regression of
// that re-read) is only bounded by its TTL if RevokeExpiredLeases → RevokeLease does
// not refuse it for living under a disabled config and a deleted project. Nothing in
// RevokeLease checks either today; this test fails if a liveness gate is ever added
// there, which would turn such a lease into a credential nothing can drop.
//
// The project/environment/config end state is written directly: it is exactly what
// deleteProjectCascade leaves (config disabled, project and environment soft-deleted),
// without core.DeleteProject's post-commit revokeProjectDynamicSecretLeases, which is
// the step a #2652 lease escapes. The fixture database carries the dynamic-secret,
// project and environment tables but not secret_nodes or shares, so the full storage
// cascade cannot run here. The "purged" case hard-deletes the project and environment,
// the state PurgeDeletedProjectsBefore leaves once the retention window has passed
// (it does not touch dynamic_secret_configs, which have no deleted_at).
func TestDynamicSecrets_SweepRevokesLeaseUnderDeletedProject(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, status string
		purged       bool
	}{
		{"active", "active", false},
		{"revoke_failed", "revoke_failed", false},
		{"active_project_purged", "active", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, db, fake, fixed := newDynamicTestCore(t)
			ctx := context.Background()
			cfg := mkConfig(t, c, ctx)

			issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
			require.NoError(t, err)
			require.NoError(t, db.Model(&models.DynamicSecretLease{}).
				Where("lease_id = ?", issued.LeaseID).Update("status", tc.status).Error)
			backdateLeaseExpiry(t, db, issued.LeaseID, fixed.Add(-1))

			require.NoError(t, db.Model(&models.DynamicSecretConfig{}).
				Where("id = ?", cfg.ID).Update("disabled", true).Error)
			parents := func() *gorm.DB { // a fresh chain per call: a reused one keeps its WHERE
				if tc.purged {
					return db.Unscoped()
				}
				return db
			}
			require.NoError(t, parents().Delete(&models.Environment{}, cfg.EnvironmentID).Error)
			require.NoError(t, parents().Delete(&models.Project{}, cfg.ProjectID).Error)

			// The precondition is real: new issues are refused, the parent is gone.
			_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
			require.ErrorContains(t, err, "disabled")
			var live int64
			require.NoError(t, db.Model(&models.Project{}).Where("id = ?", cfg.ProjectID).Count(&live).Error)
			require.Zero(t, live, "project must be deleted for this test to mean anything")

			n, err := c.RevokeExpiredLeases(ctx, fixed)
			require.NoError(t, err)
			assert.Equal(t, 1, n)
			assert.Equal(t, []string{issued.Username}, fake.Revoked, "the target credential must be dropped")

			after, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
			require.NoError(t, err)
			assert.Equal(t, "revoked", after.Status)
			assert.Equal(t, "expired", after.RevokeReason)
			assert.NotNil(t, after.RevokedAt)
		})
	}
}
