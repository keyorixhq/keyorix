// cta_review_lease_revoke_under_deleted_project_postgres_test.go — LIVENESS-IN-TX-NOV-1
// item 1 (#2652): the revocation half, on real Postgres and through the real storage
// cascade. TestDynamicSecrets_SweepRevokesLeaseUnderDeletedProject (SQLite) writes the
// cascade's end state by hand; this one runs LocalStorage.DeleteProject itself (configs
// disabled, project and environment soft-deleted, under its project row lock) and then
// revokes from the OTHER replica.
package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCTAReview_LeaseRevokeUnderDeletedProject_CrossReplicaPostgres: a lease that
// escaped core.DeleteProject's post-commit revocation (the #2652 shape) must still be
// droppable by both RevokeExpiredLeases (the scheduler sweep) and a direct RevokeLease,
// although its config is disabled and its project soft-deleted (INV-CORE-expired-lease-
// revoked-under-deleted-parent). The storage cascade is called directly, without core's
// revokeProjectDynamicSecretLeases: that is the step such a lease escapes.
func TestCTAReview_LeaseRevokeUnderDeletedProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	for _, c := range []*KeyorixCore{f.setup, f.coreA, f.coreB} {
		c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	}
	cfg, err := f.setup.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
		Name: "cta-revoke-deleted", ProjectID: f.projectID, EnvironmentID: f.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: f.adminID,
	})
	require.NoError(t, err)
	expiring, err := f.coreA.IssueLease(f.ctx, cfg.ID, 0, f.adminID)
	require.NoError(t, err)
	manual, err := f.coreA.IssueLease(f.ctx, cfg.ID, 0, f.adminID)
	require.NoError(t, err)

	// The cascade alone: config disabled, project and environment soft-deleted.
	require.NoError(t, f.setup.Storage().DeleteProject(f.ctx, f.projectID))
	require.EqualValues(t, 1, f.countLive(&models.Project{}, "id = ? AND deleted_at IS NOT NULL", f.projectID), "project must be deleted")
	require.EqualValues(t, 1, f.countLive(&models.DynamicSecretConfig{}, "id = ? AND disabled = ?", cfg.ID, true), "config must be disabled")
	require.EqualValues(t, 2, f.countLive(&models.DynamicSecretLease{}, "config_id = ? AND status = ?", cfg.ID, "active"),
		"precondition: both leases escaped the cascade and are still active")
	_, err = f.coreB.IssueLease(f.ctx, cfg.ID, 0, f.adminID)
	require.Error(t, err, "precondition: minting under the deleted project is refused")

	// Direct revoke (the admin path RevokeLeasesForConfig and the REST/gRPC revoke use).
	require.NoError(t, f.coreB.RevokeLease(f.ctx, manual.LeaseID, f.adminID, "manual"))

	// The sweep, run from replica B past the lease's expiry.
	n, err := f.coreB.RevokeExpiredLeases(f.ctx, expiring.ExpiresAt.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the sweep must revoke the one expired lease left")

	assert.ElementsMatch(t, []string{manual.Username, expiring.Username}, fake.Revoked,
		"both credentials must be dropped on the target")
	for _, id := range []string{manual.LeaseID, expiring.LeaseID} {
		l, err := f.coreB.Storage().GetDynamicSecretLease(f.ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "revoked", l.Status, "lease %s", id)
		assert.NotNil(t, l.RevokedAt, "lease %s", id)
	}
}
