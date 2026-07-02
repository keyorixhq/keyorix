package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeDynConfig(t *testing.T, c *KeyorixCore, name, classification string) uint {
	t.Helper()
	cfg, err := c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name:           name,
		ProjectID:      1,
		EnvironmentID:  1,
		BackendType:    "postgres",
		AdminDSN:       "postgres://admin:pw@localhost/db",
		Classification: classification,
		CreatedBy:      "admin",
	})
	require.NoError(t, err)
	return cfg.ID
}

func TestCreateDynamicSecretConfig_WithClassification(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)

	id := makeDynConfig(t, c, "analytics-ro", ClassificationConfidential)
	cfg, err := c.GetDynamicSecretConfig(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, "confidential", cfg.Classification)

	// Invalid level is rejected at create.
	_, err = c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: "bad", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
		AdminDSN: "postgres://x", Classification: "top-secret", CreatedBy: "admin",
	})
	require.Error(t, err)
}

func TestClassifyDynamicSecretConfig(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	id := makeDynConfig(t, c, "prod-admin", "") // starts unclassified

	// Invalid level rejected.
	_, err := c.ClassifyDynamicSecretConfig(ctx, 1, id, "secret")
	require.Error(t, err)

	// Set to restricted.
	updated, err := c.ClassifyDynamicSecretConfig(ctx, 1, id, ClassificationRestricted)
	require.NoError(t, err)
	assert.Equal(t, "restricted", updated.Classification)

	// Persisted.
	reload, err := c.GetDynamicSecretConfig(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "restricted", reload.Classification)

	// Clearing back to "" is allowed.
	cleared, err := c.ClassifyDynamicSecretConfig(ctx, 1, id, "")
	require.NoError(t, err)
	assert.Empty(t, cleared.Classification)

	// Unknown config id errors.
	_, err = c.ClassifyDynamicSecretConfig(ctx, 1, 9999, ClassificationPublic)
	require.Error(t, err)
}

func TestClassificationPosture_CoversDynamicConfigs(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	makeDynConfig(t, c, "a", ClassificationRestricted)
	makeDynConfig(t, c, "b", ClassificationRestricted)
	makeDynConfig(t, c, "c", ClassificationInternal)
	makeDynConfig(t, c, "d", "") // unclassified

	p := c.classificationPosture(context.Background(), &CompliancePosture{})
	assert.Equal(t, 4, p.DynamicConfigs.Total)
	assert.Equal(t, 2, p.DynamicConfigs.Restricted)
	assert.Equal(t, 1, p.DynamicConfigs.Internal)
	assert.Equal(t, 1, p.DynamicConfigs.Unclassified)
	assert.Equal(t, 0, p.DynamicConfigs.Public)
}
