// concurrency_dynamic_secret_update_postgres_test.go — #2698.
//
// LocalStorage.UpdateDynamicSecretConfig and UpdateDynamicSecretLease were
// bare GORM Save(...) calls on a struct the caller had read earlier, unlocked.
// Save writes every column, so each one reverted whatever a narrower concurrent
// writer had changed in between. Two subtests, one per consequence:
//
//  1. ClassifyDynamicSecretConfig writes `disabled=false` back over the
//     incident kill switch (SetDynamicSecretConfigEnabled(false), which also
//     revokes the config's live leases). The config can mint real database
//     credentials again, and the audit trail reads "config_disabled" then only
//     "classified" — nothing says it was re-enabled. The same column is what
//     DeleteProject's #369 cascade sets, so the same write also re-enables a
//     config under a deleted project.
//  2. RenewLease writes the stale Status/RevokeError/RevokedAt back over a
//     concurrent RevokeLease. A successful revoke becomes `active` again with a
//     LATER expiry, so the row lies about a dead credential and keeps holding a
//     MaxActiveLeases slot until the sweep; a revoke that recorded
//     `revoke_failed` is erased outright, error cleared.
//
// Neither model has a DeletedAt, so — unlike #2695/#2697 — Save's upsert
// fallback cannot resurrect a deleted row here. These are plain lost updates
// on the columns that carry the security state.
//
// Reuses the two-replica fixture in
// concurrency_check_then_act_exempt_review_postgres_test.go (same package);
// see that file's header for what the GORM-callback interleaving technique
// does and does not prove.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// dynCfg2698 seeds a dynamic-secret config on the fixture project with the fake
// engine wired into every replica.
func dynCfg2698(t *testing.T, f *ctaReview, name string) *models.DynamicSecretConfig {
	t.Helper()
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	for _, c := range []*KeyorixCore{f.setup, f.coreA, f.coreB} {
		c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	}
	cfg, err := f.setup.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
		Name: name, ProjectID: f.projectID, EnvironmentID: f.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, MaxTTLSeconds: 86400, CreatedBy: "admin", ActorID: f.adminID,
	})
	require.NoError(t, err)
	return cfg
}

func TestCTAReview_ClassifyDynamicSecretConfig_vs_KillSwitch_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	cfg := dynCfg2698(t, f, "dyn-2698-classify")
	require.False(t, cfg.Disabled)

	// Replica B pulls the incident kill switch between A's unlocked
	// GetDynamicSecretConfig and A's own UPDATE.
	var killErr error
	fired := f.beforeA("update", "dynamic_secret_configs", func() {
		_, killErr = f.coreB.SetDynamicSecretConfigEnabled(f.ctx, f.adminID, cfg.ID, false)
	})

	_, classifyErr := f.coreA.ClassifyDynamicSecretConfig(f.ctx, f.adminID, cfg.ID, ClassificationRestricted)

	require.True(t, fired(), "replica A never reached its config UPDATE — the interleaving under test never happened")
	require.NoError(t, killErr, "replica B's disable must report success; the whole point is that it did")

	var persisted models.DynamicSecretConfig
	require.NoError(t, f.setupDB.First(&persisted, cfg.ID).Error)
	assert.True(t, persisted.Disabled,
		"a disable that returned success must stay disabled: a classification change must not re-enable the config (classify err: %v)", classifyErr)

	// The assertion that matters operationally: the kill switch must still hold,
	// i.e. no new credential can be minted. IssueLease is the only thing that
	// reads `disabled` to make that decision, so this is the effect, not a proxy.
	_, issueErr := f.coreA.IssueLease(f.ctx, cfg.ID, 60, f.adminID)
	require.Error(t, issueErr, "the kill switch must still refuse new leases")
	assert.Zero(t, f.countLive(&models.DynamicSecretLease{}, "config_id = ? AND status = ?", cfg.ID, "active"),
		"no live credential may exist for a config the kill switch disabled")
}

func TestCTAReview_RenewLease_vs_RevokeLease_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	cfg := dynCfg2698(t, f, "dyn-2698-renew")

	issued, err := f.setup.IssueLease(f.ctx, cfg.ID, 60, f.adminID)
	require.NoError(t, err)

	// Replica B revokes the lease between A's unlocked read and A's own UPDATE.
	var revokeErr error
	fired := f.beforeA("update", "dynamic_secret_leases", func() {
		revokeErr = f.coreB.RevokeLease(f.ctx, issued.LeaseID, f.adminID, "incident")
	})

	_, renewErr := f.coreA.RenewLease(f.ctx, issued.LeaseID, 3600, f.adminID)

	require.True(t, fired(), "replica A never reached its lease UPDATE — the interleaving under test never happened")
	require.NoError(t, revokeErr, "replica B's revoke must report success; the whole point is that it did")

	var persisted models.DynamicSecretLease
	require.NoError(t, f.setupDB.Where("lease_id = ?", issued.LeaseID).First(&persisted).Error)
	assert.Equal(t, "revoked", persisted.Status,
		"a revoke that returned success must stay revoked: RenewLease must not write the stale status back (renew err: %v)", renewErr)
	assert.NotNil(t, persisted.RevokedAt, "the revocation timestamp must survive too")

	// The operational consequence of the revert: a revoked lease that reads as
	// active keeps occupying a MaxActiveLeases slot.
	assert.Zero(t, f.countLive(&models.DynamicSecretLease{}, "lease_id = ? AND status IN ?", issued.LeaseID, []string{"active", "revoke_failed"}),
		"a revoked lease must not count towards the config's active-lease ceiling")
}
