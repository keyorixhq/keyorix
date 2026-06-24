package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rotationOrderNames returns the secret names in a project's rotation order, and asserts
// none is blank — a blank name means an edge to an unresolved (e.g. soft-deleted) secret
// leaked into the order.
func rotationOrderNames(t *testing.T, c *KeyorixCore, projectID uint) []string {
	t.Helper()
	ro, err := c.GetProjectRotationOrder(context.Background(), projectID)
	require.NoError(t, err)
	names := make([]string, len(ro.Order))
	for i, r := range ro.Order {
		require.NotEmpty(t, r.SecretName, "rotation order must not contain an unresolved (soft-deleted) secret")
		names[i] = r.SecretName
	}
	return names
}

// A soft-deleted secret drops out of the project rotation order (it must not surface as a
// phantom, blank-named node), the rest of the graph is unaffected, and restoring it brings
// it — and its edges, which were never removed — straight back.
func TestGetProjectRotationOrder_CascadesSoftDeleteAndRestore(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)
	dbPass := mkSecret(t, db, 1, "db-password")
	appTok := mkSecret(t, db, 1, "app-token")
	cacheKey := mkSecret(t, db, 1, "cache-key")
	// app-token and cache-key both depend on db-password.
	_, err := c.AddSecretDependency(ctx, 10, appTok, dbPass, "")
	require.NoError(t, err)
	_, err = c.AddSecretDependency(ctx, 10, cacheKey, dbPass, "")
	require.NoError(t, err)

	// Baseline: dependency first, then its two dependents (sorted by id).
	assert.Equal(t, []string{"db-password", "app-token", "cache-key"}, rotationOrderNames(t, c, 1))

	// Soft-delete one dependent: it leaves the order; db-password and cache-key remain.
	require.NoError(t, c.DeleteSecret(ctx, appTok))
	assert.Equal(t, []string{"db-password", "cache-key"}, rotationOrderNames(t, c, 1),
		"the soft-deleted secret is gone from the order, with no blank-named phantom")

	// Restore it: the edge row was never removed, so it reappears in full.
	require.NoError(t, c.RestoreSecret(ctx, 0, appTok))
	assert.Equal(t, []string{"db-password", "app-token", "cache-key"}, rotationOrderNames(t, c, 1),
		"restoring the secret brings it and its dependency edge back")
}

// Impact analysis (the blast radius of rotating a secret) excludes a soft-deleted
// dependent and includes it again after restore.
func TestGetSecretImpact_CascadesSoftDeleteAndRestore(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)
	dbPass := mkSecret(t, db, 1, "db-password")
	appTok := mkSecret(t, db, 1, "app-token")
	cacheKey := mkSecret(t, db, 1, "cache-key")
	_, err := c.AddSecretDependency(ctx, 10, appTok, dbPass, "")
	require.NoError(t, err)
	_, err = c.AddSecretDependency(ctx, 10, cacheKey, dbPass, "")
	require.NoError(t, err)

	impactNames := func() []string {
		si, err := c.GetSecretImpact(ctx, dbPass)
		require.NoError(t, err)
		names := make([]string, len(si.Affected))
		for i, a := range si.Affected {
			names[i] = a.SecretName
		}
		return names
	}

	assert.ElementsMatch(t, []string{"app-token", "cache-key"}, impactNames())

	require.NoError(t, c.DeleteSecret(ctx, appTok))
	assert.ElementsMatch(t, []string{"cache-key"}, impactNames(), "soft-deleted dependent drops from the blast radius")

	require.NoError(t, c.RestoreSecret(ctx, 0, appTok))
	assert.ElementsMatch(t, []string{"app-token", "cache-key"}, impactNames(), "restore brings it back")
}
