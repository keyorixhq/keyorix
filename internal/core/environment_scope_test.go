// environment_scope_test.go — regression coverage for GetEnvironmentInProject
// and its use in requireLiveProjectAndEnvironment: storage.Storage's
// GetEnvironment/DeleteEnvironment take a bare, unscoped id (unlike
// RestoreEnvironment, which is project-scoped by signature), so any core
// caller that already believes an environment belongs to a specific project
// must cross-check that belief explicitly instead of trusting the bare id —
// otherwise a caller authorized for project A could reference an environment
// that actually belongs to project B and operate on it by mistake (or via a
// crafted request that supplies a mismatched id).
package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newEnvScopeTestCore builds a minimal KeyorixCore over an isolated in-memory
// SQLite DB, keyed by test name to avoid cross-test collisions.
func newEnvScopeTestCore(t *testing.T) *KeyorixCore {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
	))
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
}

// TestGetEnvironmentInProject_CrossProjectReferenceRefused is the required
// regression case: an environment belonging to project A, a caller operating
// in the context of project B, references that environment's bare id — the
// project-scoped lookup must refuse it rather than silently returning A's
// environment as if it belonged to B.
func TestGetEnvironmentInProject_CrossProjectReferenceRefused(t *testing.T) {
	c := newEnvScopeTestCore(t)
	ctx := context.Background()

	projectA, err := c.storage.CreateProject(ctx, &models.Project{Name: "project-a"})
	require.NoError(t, err)
	projectB, err := c.storage.CreateProject(ctx, &models.Project{Name: "project-b"})
	require.NoError(t, err)

	envInA, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: projectA.ID})
	require.NoError(t, err)

	// Caller operating in the context of project B, referencing A's environment
	// by its bare id, must be refused.
	got, err := c.GetEnvironmentInProject(ctx, projectB.ID, envInA.ID)
	require.Error(t, err, "environment belonging to a different project must be refused, not returned")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "not found", "mismatch must surface as a generic not-found error, not leak that the id exists under a different project")

	// Sanity: the SAME lookup scoped to the environment's real, owning project
	// (A) succeeds, proving the refusal above is specifically about project
	// scoping and not some other bug in the lookup.
	got, err = c.GetEnvironmentInProject(ctx, projectA.ID, envInA.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, envInA.ID, got.ID)
}

// TestGetEnvironmentInProject_NonexistentEnvironmentRefused confirms the
// helper still behaves like a normal not-found lookup when the id simply
// doesn't exist at all (not just when it exists under a different project).
func TestGetEnvironmentInProject_NonexistentEnvironmentRefused(t *testing.T) {
	c := newEnvScopeTestCore(t)
	ctx := context.Background()

	project, err := c.storage.CreateProject(ctx, &models.Project{Name: "solo-project"})
	require.NoError(t, err)

	_, err = c.GetEnvironmentInProject(ctx, project.ID, 999999)
	require.Error(t, err)
}

// TestRequireLiveProjectAndEnvironment_CrossProjectMismatchRefused exercises
// the dynamic-secrets liveness gate (shared by IssueLease/RenewLease)
// directly: even though today's only callers pass coupled projectID/
// environmentID fields from the same config/lease row, the gate itself must
// independently refuse a mismatch rather than relying on that coupling to
// always hold.
func TestRequireLiveProjectAndEnvironment_CrossProjectMismatchRefused(t *testing.T) {
	c := newEnvScopeTestCore(t)
	ctx := context.Background()

	projectA, err := c.storage.CreateProject(ctx, &models.Project{Name: "dyn-project-a"})
	require.NoError(t, err)
	projectB, err := c.storage.CreateProject(ctx, &models.Project{Name: "dyn-project-b"})
	require.NoError(t, err)

	envInB, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: projectB.ID})
	require.NoError(t, err)

	// projectID names a live project (A), but environmentID actually belongs
	// to a different project (B) — must be refused.
	err = c.requireLiveProjectAndEnvironment(ctx, projectA.ID, envInB.ID)
	require.Error(t, err, "a projectID/environmentID pair spanning two different projects must be refused")

	// Sanity: the correctly-paired (A, A's own environment) case still passes.
	envInA, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: projectA.ID})
	require.NoError(t, err)
	require.NoError(t, c.requireLiveProjectAndEnvironment(ctx, projectA.ID, envInA.ID))

	// Sanity: environmentID == 0 (no environment scoping requested) still passes.
	require.NoError(t, c.requireLiveProjectAndEnvironment(ctx, projectA.ID, 0))
}
