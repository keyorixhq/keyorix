package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// The startup warning's scan lists the legacy config with its live leases and
// leaves the clean one out.
func TestListConfigsWithRefusedAdminDSN(t *testing.T) {
	c, db, _, clean := newStrippedRevokeCore(t)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{})) // ListProjectsWithCounts joins it
	ctx := context.Background()
	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "clean-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: clean, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.NoError(t, err)
	legacy, _ := storeLegacyConfig(t, c, "legacy-db", clean, clean+" sslrootcert=/etc/ssl/private-ca.pem", "kx_dyn_legacy")

	rep, err := c.ListConfigsWithRefusedAdminDSN(ctx)
	require.NoError(t, err)
	assert.Zero(t, rep.Unreadable)
	require.Len(t, rep.Configs, 1)
	assert.Equal(t, RefusedAdminDSNConfig{
		ConfigID: legacy.ID, ProjectID: 1, Name: "legacy-db", BackendType: "postgres", Option: "sslrootcert", LiveLeases: 1,
	}, rep.Configs[0])
}
