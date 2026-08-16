// rotation_policy_scope_test.go — regression coverage for
// findings-handlers/handlers-rotation-policies-handler.json#0: an
// environment-scoped rotation policy's secret lookup was not actually confined
// to its own project, letting it enumerate/rotate a different project's secrets.
//
// Two things were broken together:
//  1. CreateRotationPolicy never checked that a supplied ProjectID/EnvironmentID
//     pair on a policy actually belong to each other (or derived ProjectID from
//     the environment when only EnvironmentID was given).
//  2. scopedPolicySecrets's "environment" scope branch queried ListSecrets with
//     only EnvironmentID set, leaving ProjectID at its zero value. LocalStorage's
//     ListSecrets treats a nil ProjectID as "don't filter by project", so the
//     lookup was effectively unscoped with respect to project ownership.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestCreateRotationPolicy_EnvironmentProjectMismatchRejected covers fix #1: an
// actor authorized against their own project (project 1) must not be able to
// create an "environment-scoped" rotation policy whose EnvironmentID actually
// belongs to a different project (project 2) they may have no access to.
func TestCreateRotationPolicy_EnvironmentProjectMismatchRejected(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.RotationPolicy{}, &models.AuditEvent{}))
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}

	// Project 1 (the attacker's own, legitimate project) and Project 2 (the
	// victim's), each with an environment. Both environments even share the
	// same name ("production") — plausible for an attacker to guess/target a
	// same-looking environment in a project they don't own.
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "production"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "production"}).Error)

	attackerProject := uint(1)
	victimEnv := uint(20) // belongs to project 2, not project 1

	_, err = c.CreateRotationPolicy(context.Background(), 1, &CreateRotationPolicyRequest{
		Name: "cross-project", Scope: "environment",
		ProjectID: &attackerProject, EnvironmentID: &victimEnv,
		IntervalDays: 90, AlertDaysBefore: 7, CreatedBy: "attacker",
	})
	require.Error(t, err, "a policy claiming project 1 but pointing at project 2's environment must be rejected")
	assert.Contains(t, err.Error(), "does not belong to project")

	// Sanity: no policy row was left behind by the rejected create.
	var count int64
	require.NoError(t, db.Model(&models.RotationPolicy{}).Count(&count).Error)
	assert.Zero(t, count)
}

// TestCreateRotationPolicy_EnvironmentScopeDerivesProjectID covers the other
// half of fix #1: when only EnvironmentID is given (ProjectID omitted, which is
// legal — CreateRotationPolicy only requires ProjectID for scope="project"),
// the policy's ProjectID must be derived from the environment's true owning
// project, never left nil. A nil ProjectID on an environment-scoped policy is
// exactly what let scopedPolicySecrets's environment branch go unscoped.
func TestCreateRotationPolicy_EnvironmentScopeDerivesProjectID(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.RotationPolicy{}, &models.AuditEvent{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return time.Now() }}

	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "production"}).Error)
	envID := uint(20)

	p, err := c.CreateRotationPolicy(context.Background(), 1, &CreateRotationPolicyRequest{
		Name: "env-only", Scope: "environment",
		EnvironmentID: &envID,
		IntervalDays:  90, AlertDaysBefore: 7, CreatedBy: "admin",
	})
	require.NoError(t, err)
	require.NotNil(t, p.ProjectID)
	assert.Equal(t, uint(2), *p.ProjectID, "ProjectID must be derived from the environment's true owning project")
}

// TestScopedPolicySecrets_EnvironmentScopeDoesNotLeakAcrossProjects is the
// storage-level regression for fix #2, exercised directly against
// scopedPolicySecrets so it also covers a mismatched/legacy policy row that
// didn't go through CreateRotationPolicy's validation (e.g. pre-existing data
// from before this fix). Two projects each get an environment named the same
// way, and secrets of their own; a policy is inserted claiming project 1 but
// scoped (via EnvironmentID) to project 2's environment. The secret lookup must
// never surface project 2's secrets.
func TestScopedPolicySecrets_EnvironmentScopeDoesNotLeakAcrossProjects(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.RotationPolicy{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}

	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "production"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "production"}).Error)

	require.NoError(t, db.Create(&models.SecretNode{ProjectID: 1, EnvironmentID: 10, Name: "own-secret", Type: "password"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ProjectID: 2, EnvironmentID: 20, Name: "victim-secret", Type: "password"}).Error)

	attackerProject := uint(1)
	victimEnv := uint(20) // belongs to project 2
	policy := &models.RotationPolicy{
		Name: "cross-project", Scope: "environment",
		ProjectID: &attackerProject, EnvironmentID: &victimEnv,
		IntervalDays: 90, AlertDaysBefore: 7, IsActive: true, CreatedBy: "attacker",
	}
	require.NoError(t, db.Create(policy).Error)

	secrets, err := c.scopedPolicySecrets(context.Background(), policy, nil)
	require.NoError(t, err)
	for _, s := range secrets {
		assert.Equal(t, uint(1), s.ProjectID, "a policy claiming project 1 must never surface project 2's secrets")
	}
	assert.Empty(t, secrets, "a mismatched project/environment pair must yield no secrets, not the other project's")
}

// TestScopedPolicySecrets_EnvironmentScopeMatchesOwnProject is the positive
// counterpart: a correctly-scoped environment policy (ProjectID derived from
// its own environment, as CreateRotationPolicy now guarantees) must still see
// its own project's secrets in that environment.
func TestScopedPolicySecrets_EnvironmentScopeMatchesOwnProject(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.RotationPolicy{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}

	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "production"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "production"}).Error)

	require.NoError(t, db.Create(&models.SecretNode{ProjectID: 1, EnvironmentID: 10, Name: "own-secret", Type: "password"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ProjectID: 2, EnvironmentID: 20, Name: "victim-secret", Type: "password"}).Error)

	ownProject := uint(1)
	ownEnv := uint(10)
	policy := &models.RotationPolicy{
		Name: "correctly-scoped", Scope: "environment",
		ProjectID: &ownProject, EnvironmentID: &ownEnv,
		IntervalDays: 90, AlertDaysBefore: 7, IsActive: true, CreatedBy: "admin",
	}
	require.NoError(t, db.Create(policy).Error)

	secrets, err := c.scopedPolicySecrets(context.Background(), policy, nil)
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	assert.Equal(t, "own-secret", secrets[0].Name)
	assert.Equal(t, uint(1), secrets[0].ProjectID)
}
