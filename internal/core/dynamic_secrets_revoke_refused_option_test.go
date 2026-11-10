package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3980: a MongoDB config stored with tlsCAFile before #3952 could no longer
// revoke the leases it had issued, and MongoDB users have no native expiry, so
// they stayed live on the target. The sweep must drop them through the real
// engine; issuing from that config must still be refused before any connection.
func TestRevokeExpiredLeases_StoredConfigWithRefusedOptionStillRevokes(t *testing.T) {
	c, db, _, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	target := dynamictest.StartFakeMongo(t)
	c.SetDynamicAllowPrivateTargets(true) // the fake target sits on loopback
	c.SetDynamicSweepEnabled(true)
	c.SetDynamicEngineFactory(func(bt string) (dynamic.CredentialEngine, error) { return dynamic.New(bt, true, true) })

	adminDSN := fmt.Sprintf("mongodb://%s/?directConnection=true&tlsCAFile=/nonexistent/private-ca.pem", target.Addr)
	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "refused-now", ProjectID: 1, EnvironmentID: 2, BackendType: "mongodb",
		AdminDSN: adminDSN, DefaultTTLSeconds: 3600, ActorID: testAdminActorID,
	})
	var fe *dsn.ForbiddenOptionError
	require.True(t, errors.As(err, &fe), "create must refuse the option, got %v", err)

	// Stored before the refusal existed: write the row directly, as an older build did.
	cfg := &models.DynamicSecretConfig{Name: "stored-earlier", ProjectID: 1, EnvironmentID: 2, BackendType: "mongodb", DefaultTTLSeconds: 3600}
	require.NoError(t, db.Create(cfg).Error)
	enc, meta, err := c.encryptAuthSecret(adminDSN, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	require.NoError(t, err)
	require.NoError(t, db.Model(cfg).Updates(map[string]any{"admin_dsn_enc": enc, "admin_dsn_meta": meta}).Error)

	for _, l := range []models.DynamicSecretLease{
		{LeaseID: "lease-active", RoleName: "kx_dyn_active", Status: "active"},
		{LeaseID: "lease-failed", RoleName: "kx_dyn_failed", Status: "revoke_failed", RevokeError: "backend revoke failed"},
	} {
		l.ConfigID, l.ProjectID, l.EnvironmentID = cfg.ID, cfg.ProjectID, cfg.EnvironmentID
		l.IssuedAt, l.ExpiresAt = fixed.Add(-2*time.Hour), fixed.Add(-time.Hour)
		require.NoError(t, db.Create(&l).Error)
	}

	revoked, err := c.RevokeExpiredLeases(ctx, fixed)
	require.NoError(t, err)
	assert.Equal(t, 2, revoked)
	assert.ElementsMatch(t, []string{"kx_dyn_active", "kx_dyn_failed"}, target.Dropped(), "the users must be dropped on the target")
	for _, id := range []string{"lease-active", "lease-failed"} {
		var l models.DynamicSecretLease
		require.NoError(t, db.Where("lease_id = ?", id).First(&l).Error)
		assert.Equal(t, "revoked", l.Status, id)
		assert.Equal(t, "expired", l.RevokeReason, id)
		assert.Empty(t, l.RevokeError, id)
	}

	_, err = c.IssueLease(ctx, cfg.ID, 0, testAdminActorID)
	require.True(t, errors.As(err, &fe), "issue from the stored config must still refuse, got %v", err)
	assert.Empty(t, target.Created(), "a refused issue must not create a user")
}
