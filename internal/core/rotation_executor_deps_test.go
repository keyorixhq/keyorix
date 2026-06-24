package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/rotation"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// depExecCore is rotationExecCore plus the secret-dependency table and a single active
// 30-day project policy, so auto-rotation has a dependency graph to order by (ADR-052/053).
func depExecCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	c, db, fixed := rotationExecCore(t)
	require.NoError(t, db.AutoMigrate(&models.SecretDependency{}))
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	return c, db, fixed
}

// seedDependency inserts a directed edge "dependent depends on dependsOn" in project 1.
func seedDependency(t *testing.T, db *gorm.DB, dependent, dependsOn uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID: 1, DependentSecretID: dependent, DependsOnSecretID: dependsOn,
	}).Error)
}

// autoRotateEventDescriptions returns the auto-rotation audit event descriptions in write
// order (event id ascending) — i.e. the order the executor rotated/deferred secrets.
func autoRotateEventDescriptions(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretAutoRotated).Order("id ASC").Find(&events).Error)
	descs := make([]string, len(events))
	for i, e := range events {
		descs[i] = e.Description
	}
	return descs
}

// A dependent rotates only AFTER the secret it depends on. The dependency is given a
// HIGHER id than its dependent so a naive id-ordered pass would rotate them in the wrong
// order — proving the ordering comes from the dependency graph, not the scan order.
func TestRunAutoRotation_RotatesInDependencyOrder(t *testing.T) {
	c, db, fixed := depExecCore(t)
	overdue := fixed.Add(-60 * 24 * time.Hour)
	// secret 1 (app-token) depends on secret 2 (db-password): db-password must rotate first.
	seedRotatableSecret(t, db, 1, "app-token", true, overdue)
	seedRotatableSecret(t, db, 2, "db-password", true, overdue)
	seedDependency(t, db, 1, 2) // dependent=app-token depends on db-password

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n, "both overdue secrets rotate")
	assert.Equal(t, 2, latestVersion(t, db, 1).VersionNumber)
	assert.Equal(t, 2, latestVersion(t, db, 2).VersionNumber)

	descs := autoRotateEventDescriptions(t, db)
	require.Len(t, descs, 2)
	assert.Contains(t, descs[0], "db-password", "the dependency rotates first")
	assert.Contains(t, descs[1], "app-token", "the dependent rotates second")
}

// When a dependency fails to rotate, the dependent is DEFERRED rather than rotated
// against a now-stale dependency — and the deferral propagates transitively down the
// chain (A fails → B deferred → C deferred).
func TestRunAutoRotation_DefersDependentsOfFailedDependency(t *testing.T) {
	fake := &fakeExecutor{name: "pg", err: errors.New("connection refused")}
	c, db, fixed := depExecCore(t)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	overdue := fixed.Add(-60 * 24 * time.Hour)

	// Chain: app-token (3) depends on db-app (2) depends on db-root (1, a backend secret
	// that fails to rotate upstream).
	seedBackendSecret(t, db, 1, "pg", "db_root", overdue) // name "upstream-cred"; fails
	seedRotatableSecret(t, db, 2, "db-app", true, overdue)
	seedRotatableSecret(t, db, 3, "app-token", true, overdue)
	seedDependency(t, db, 2, 1) // db-app depends on db-root
	seedDependency(t, db, 3, 2) // app-token depends on db-app

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "the dependency failed, so neither dependent rotates")

	// Nothing downstream got a new version.
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber, "failed dependency unchanged")
	assert.Equal(t, 1, latestVersion(t, db, 2).VersionNumber, "deferred dependent unchanged")
	assert.Equal(t, 1, latestVersion(t, db, 3).VersionNumber, "transitively-deferred dependent unchanged")

	descs := autoRotateEventDescriptions(t, db)
	joined := strings.Join(descs, "\n")
	assert.Contains(t, joined, "FAILED", "the dependency's failure is audited")
	// db-app deferred because db-root (the backend secret, named "upstream-cred") didn't rotate.
	assert.Contains(t, joined, `DEFERRED for secret "db-app"`)
	// app-token deferred because db-app didn't rotate this run (transitive propagation).
	assert.Contains(t, joined, `DEFERRED for secret "app-token": it depends on "db-app"`)
}

// A sibling dependent of a SUCCESSFUL dependency still rotates — deferral is scoped to the
// dependents of secrets that did not rotate, not a blanket stand-down.
func TestRunAutoRotation_SuccessfulDependencyDoesNotDeferDependent(t *testing.T) {
	c, db, fixed := depExecCore(t)
	overdue := fixed.Add(-60 * 24 * time.Hour)
	seedRotatableSecret(t, db, 1, "db-password", true, overdue) // generated → succeeds
	seedRotatableSecret(t, db, 2, "app-token", true, overdue)
	seedDependency(t, db, 2, 1)

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n, "dependency succeeds, so the dependent rotates too")
	assert.Equal(t, 2, latestVersion(t, db, 2).VersionNumber)
}

// A cyclic graph (which the add path normally rejects, ADR-052) must never block
// rotation: the executor falls back to a flat best-effort pass and still rotates.
func TestRunAutoRotation_CyclicGraphFallsBackToFlatRotation(t *testing.T) {
	c, db, fixed := depExecCore(t)
	overdue := fixed.Add(-60 * 24 * time.Hour)
	seedRotatableSecret(t, db, 1, "a", true, overdue)
	seedRotatableSecret(t, db, 2, "b", true, overdue)
	// Insert a cycle directly, bypassing the acyclic-at-create guard.
	seedDependency(t, db, 1, 2)
	seedDependency(t, db, 2, 1)

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n, "a cyclic graph falls back to flat order and still rotates both")
	assert.Equal(t, 2, latestVersion(t, db, 1).VersionNumber)
	assert.Equal(t, 2, latestVersion(t, db, 2).VersionNumber)
}
