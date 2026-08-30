package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
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
	_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, appTok, dbPass, "", 0)
	require.NoError(t, err)
	_, err = c.AddSecretDependency(ctx, ActorTypeUser, 10, cacheKey, dbPass, "", 0)
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
	_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, appTok, dbPass, "", 0)
	require.NoError(t, err)
	_, err = c.AddSecretDependency(ctx, ActorTypeUser, 10, cacheKey, dbPass, "", 0)
	require.NoError(t, err)

	impactNames := func() []string {
		si, err := c.GetSecretImpact(ctx, ActorTypeUser, 10, dbPass)
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

// --- audit event emission tests ---

// DeleteSecret emits secret.dependency_invalidated for each incident edge.
func TestDeleteSecret_EmitsDependencyInvalidatedAuditEvents(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)

	dbPass := mkSecret(t, db, 1, "db-password")
	appTok := mkSecret(t, db, 1, "app-token")
	cacheKey := mkSecret(t, db, 1, "cache-key")
	// appTok and cacheKey both depend on dbPass.
	_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, appTok, dbPass, "", 0)
	require.NoError(t, err)
	_, err = c.AddSecretDependency(ctx, ActorTypeUser, 10, cacheKey, dbPass, "", 0)
	require.NoError(t, err)

	// Soft-delete the dependency target (dbPass). Both edges become invalid.
	require.NoError(t, c.DeleteSecret(ctx, dbPass))

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretDependencyInvalidated).Find(&events).Error)
	assert.Len(t, events, 2, "one invalidation event per incident edge")

	// All events reference a dependent secret (not dbPass itself), because dbPass is
	// the depends-on target and both appTok and cacheKey lose their upstream.
	secretIDs := make(map[uint]bool)
	for _, e := range events {
		if e.SecretNodeID != nil {
			secretIDs[*e.SecretNodeID] = true
		}
	}
	assert.True(t, secretIDs[appTok], "app-token dependent must be referenced")
	assert.True(t, secretIDs[cacheKey], "cache-key dependent must be referenced")
}

// RestoreSecret emits secret.dependency_restored for each incident edge.
func TestRestoreSecret_EmitsDependencyRestoredAuditEvents(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)

	dbPass := mkSecret(t, db, 1, "db-password")
	appTok := mkSecret(t, db, 1, "app-token")
	cacheKey := mkSecret(t, db, 1, "cache-key")
	_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, appTok, dbPass, "", 0)
	require.NoError(t, err)
	_, err = c.AddSecretDependency(ctx, ActorTypeUser, 10, cacheKey, dbPass, "", 0)
	require.NoError(t, err)

	require.NoError(t, c.DeleteSecret(ctx, dbPass))
	require.NoError(t, c.RestoreSecret(ctx, 42, dbPass))

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretDependencyRestored).Find(&events).Error)
	assert.Len(t, events, 2, "one restore event per incident edge")
}

// No dependency audit events are emitted when the secret has no dependency edges.
func TestDeleteSecret_NoDependencyEventsWhenNoEdges(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)

	isolated := mkSecret(t, db, 1, "isolated")
	require.NoError(t, c.DeleteSecret(ctx, isolated))

	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventSecretDependencyInvalidated).Count(&count).Error)
	assert.Zero(t, count, "no dependency events for a secret with no edges")
}

// DeleteSecret emits an event for the edge where the deleted secret is the dependent
// (not just where it is the depends-on target).
func TestDeleteSecret_EmitsEventWhenDeletedSecretIsDependent(t *testing.T) {
	ctx := context.Background()
	c, db := newDepCore(t)

	upstream := mkSecret(t, db, 1, "upstream")
	downstream := mkSecret(t, db, 1, "downstream")
	// downstream depends on upstream.
	_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, downstream, upstream, "", 0)
	require.NoError(t, err)

	// Delete the dependent (downstream). The edge is incident to it, so one event
	// is expected with SecretNodeID = downstream.
	require.NoError(t, c.DeleteSecret(ctx, downstream))

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretDependencyInvalidated).Find(&events).Error)
	require.Len(t, events, 1)
	require.NotNil(t, events[0].SecretNodeID)
	assert.Equal(t, downstream, *events[0].SecretNodeID)
}
