package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #4374 soft period (dsn.StoredSQLTransportGrace): an admin_dsn stored before the
// transport policy covered postgres/mysql keeps issuing for one release, audited on
// every issue; after it, issue refuses it like save does.

// storeWeakSQLConfig stores adminDSN as a server before #4374 would have: created
// with a verifying DSN, then overwritten underneath the save-time check.
func storeWeakSQLConfig(t *testing.T, c *KeyorixCore, name, adminDSN string) *models.DynamicSecretConfig {
	t.Helper()
	cfg, err := createSQLConfig(c, name, "postgres", "postgres://admin:s3cret@127.0.0.1:5432/app?sslmode=verify-full")
	require.NoError(t, err)
	enc, meta, err := c.encryptAuthSecret(adminDSN, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	require.NoError(t, err)
	require.NoError(t, c.storage.SetDynamicSecretConfigAdminDSN(context.Background(), cfg.ID, enc, meta))
	return cfg
}

// Soft period: a stored sslmode=prefer admin_dsn (pgx's default) keeps issuing and
// revoking, with an audit event on every issue.
func TestDynamicSecrets_IssueLease_StoredWeakSQLTransportAuditedEveryIssue(t *testing.T) {
	if !dsn.StoredSQLTransportGrace {
		t.Skip("the soft period is over: TestDynamicSecrets_IssueLease_StoredWeakSQLTransportRefusedAfterGrace covers it")
	}
	c, db := newSQLTransportCore(t, false)
	pg := dynamictest.StartFakePostgres(t) // declines TLS, so prefer falls back to plaintext
	cfg := storeWeakSQLConfig(t, c, "legacy", fmt.Sprintf("postgres://admin:s3cret@%s:%s/app?sslmode=prefer&connect_timeout=5", pg.Host, pg.Port))

	ctx := context.Background()
	first, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err, "a stored admin_dsn keeps issuing during the soft period")
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	descs := auditDescriptions(t, db, "dynamic_lease.insecure_transport")
	require.Len(t, descs, 2, "one audit event per issue")
	for _, d := range descs {
		assert.Contains(t, d, "sslmode=prefer")
		assert.Contains(t, d, `"legacy"`)
		assert.Contains(t, d, "grace period")
		assert.NotContains(t, d, "s3cret")
		assert.NotContains(t, d, pg.Port)
	}
	require.NoError(t, c.RevokeLease(ctx, first.LeaseID, 7, "manual"), "and revokes as it issues")
}

// The next release: the same stored admin_dsn is refused at issue time.
func TestDynamicSecrets_IssueLease_StoredWeakSQLTransportRefusedAfterGrace(t *testing.T) {
	c, db := newSQLTransportCore(t, false)
	c.dynamicSQLTransportGraceEnded = true
	cfg := storeWeakSQLConfig(t, c, "legacy", "postgres://admin:s3cret@127.0.0.1:1/app?sslmode=require")
	_, err := c.IssueLease(context.Background(), cfg.ID, 0, 7)
	fe, ok := errors.AsType[*dsn.ForbiddenOptionError](err)
	require.True(t, ok, "want a transport refusal, got %v", err)
	assert.Equal(t, "sslmode=require", fe.Option)
	assert.Empty(t, auditDescriptions(t, db, "dynamic_lease.issued"))
}
