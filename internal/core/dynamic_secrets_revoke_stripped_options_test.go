// dynamic_secrets_revoke_stripped_options_test.go — #3980.
//
// A config stored before #3952 can carry an admin_dsn option that makes the
// driver read a server file. #3952 refuses it on every connection, which also
// blocked RevokeLease for the leases already issued from it. These tests store
// such a config the way an old server did (the DSN written straight to the row,
// past CreateDynamicSecretConfig's check) and revoke through the real postgres
// engine against an in-process protocol stub.
package core

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newStrippedRevokeCore wires the real dynamic engines (private targets
// allowed, so the loopback stub is reachable) and returns the stub's clean DSN.
func newStrippedRevokeCore(t *testing.T) (*KeyorixCore, *gorm.DB, *dynamictest.FakePostgres, string) {
	t.Helper()
	c, db, _, _ := newDynamicTestCore(t)
	c.SetDynamicAllowPrivateTargets(true)
	c.SetDynamicEngineFactory(func(bt string) (dynamic.CredentialEngine, error) { return dynamic.New(bt, true, false) })
	pg := dynamictest.StartFakePostgres(t)
	return c, db, pg, fmt.Sprintf("host=%s port=%s user=admin password=pw dbname=d sslmode=disable connect_timeout=5", pg.Host, pg.Port)
}

// storeLegacyConfig creates a config with a clean DSN, then overwrites the stored
// DSN with adminDSN, as a server before #3952 would have stored it, and records
// an active lease for role on it.
func storeLegacyConfig(t *testing.T, c *KeyorixCore, name, cleanDSN, adminDSN, role string) (*models.DynamicSecretConfig, string) {
	t.Helper()
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: name, ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: cleanDSN, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.NoError(t, err)
	enc, meta, err := c.encryptAuthSecret(adminDSN, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	require.NoError(t, err)
	require.NoError(t, c.storage.SetDynamicSecretConfigAdminDSN(ctx, cfg.ID, enc, meta))
	now := c.now()
	leaseID := "lease-" + name
	_, err = c.storage.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID: cfg.ID, LeaseID: leaseID, ProjectID: cfg.ProjectID, EnvironmentID: cfg.EnvironmentID,
		RoleName: role, Status: "active", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)
	return cfg, leaseID
}

func auditDescriptions(t *testing.T, db *gorm.DB, eventType string) []string {
	t.Helper()
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", eventType).Order("id").Find(&events).Error)
	var out []string
	for _, e := range events {
		out = append(out, e.Description)
	}
	return out
}

// TestDynamicSecrets_RevokeLease_StoredConfigWithRefusedFileOption: the lease of
// a legacy config is revoked on the target and audited exactly like the lease of
// a clean config, while Issue from the legacy config stays refused.
func TestDynamicSecrets_RevokeLease_StoredConfigWithRefusedFileOption(t *testing.T) {
	c, db, pg, clean := newStrippedRevokeCore(t)
	ctx := context.Background()

	// Control: an ordinary config, issued and revoked through the same engine.
	cleanCfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "clean-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: clean, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.NoError(t, err)
	issued, err := c.IssueLease(ctx, cleanCfg.ID, 0, 7)
	require.NoError(t, err)
	require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))

	legacyCfg, legacyLease := storeLegacyConfig(t, c, "legacy-db", clean,
		clean+" sslcert=/etc/keyorix/server.crt sslkey=/etc/keyorix/server.key passfile=/root/.pgpass", "kx_dyn_legacy")

	_, err = c.IssueLease(ctx, legacyCfg.ID, 0, 7)
	require.Error(t, err, "issue from a DSN with a refused file option stays refused")
	assert.Contains(t, err.Error(), "is not allowed")

	require.NoError(t, c.RevokeLease(ctx, legacyLease, 7, "manual"), "#3980: the legacy lease must still revoke")
	assert.Contains(t, pg.Statements(), `DROP ROLE IF EXISTS "kx_dyn_legacy"`, "the role was really dropped on the target")

	l, err := c.storage.GetDynamicSecretLease(ctx, legacyLease)
	require.NoError(t, err)
	assert.Equal(t, "revoked", l.Status)
	assert.Empty(t, l.RevokeError)
	assert.NotNil(t, l.RevokedAt)

	// Same audit event as the ordinary revoke: same type, same text but the id.
	descs := auditDescriptions(t, db, "dynamic_lease.revoked")
	require.Len(t, descs, 2)
	norm := func(s, id string) string { return strings.ReplaceAll(s, id, "<lease>") }
	var got []string
	for _, d := range descs {
		got = append(got, norm(norm(d, issued.LeaseID), legacyLease))
	}
	assert.Equal(t, got[0], got[1], "the stripped revoke is audited like a normal one")
	assert.Empty(t, auditDescriptions(t, db, "dynamic_lease.revoke_failed"))
}

// A DSN revoke cannot rewrite (service names the target from a server file)
// stays revoke_failed, with the refused option as the stored reason.
func TestDynamicSecrets_RevokeLease_UnstrippableOptionStaysRevokeFailed(t *testing.T) {
	c, db, pg, clean := newStrippedRevokeCore(t)
	ctx := context.Background()
	_, lease := storeLegacyConfig(t, c, "svc-db", clean, clean+" service=prod", "kx_dyn_svc")

	err := c.RevokeLease(ctx, lease, 7, "manual")
	require.Error(t, err)
	assert.NotContains(t, pg.Statements(), "kx_dyn_svc", "nothing reached the target")

	l, gerr := c.storage.GetDynamicSecretLease(ctx, lease)
	require.NoError(t, gerr)
	assert.Equal(t, "revoke_failed", l.Status)
	assert.Contains(t, l.RevokeError, `"service"`, "the lease names the option that blocks the revoke")
	assert.Contains(t, l.RevokeError, "drop the lease's role by hand")
	failed := auditDescriptions(t, db, "dynamic_lease.revoke_failed")
	require.Len(t, failed, 1)
	assert.Contains(t, failed[0], `"service"`)
}
