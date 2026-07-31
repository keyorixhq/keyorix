// local_rotation_policies_test.go — SQLite integration tests for the two
// LocalStorage methods introduced by the rotation-state feature:
// GetRotationPolicyBySecret and UpdateRotationState.
package store

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newRotationPoliciesTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.RotationPolicy{},
	))
	return NewLocalStorage(db)
}

// seedRotationPolicyFixture creates a project, environment, secret, and an active
// project-scoped rotation policy. Returns (ls, secretID, policyID).
func seedRotationPolicyFixture(t *testing.T, ls *LocalStorage) (secretID uint, policyID uint) {
	t.Helper()
	ctx := context.Background()

	proj := &models.Project{Name: "rp-test-proj"}
	require.NoError(t, ls.db.Create(proj).Error)

	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, ls.db.Create(env).Error)

	secret := &models.SecretNode{
		Name:          "MY_API_KEY",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		IsSecret:      true,
	}
	require.NoError(t, ls.db.Create(secret).Error)

	policy := &models.RotationPolicy{
		Name:         "30-day",
		Scope:        "project",
		ProjectID:    &proj.ID,
		IntervalDays: 30,
		IsActive:     true,
		CreatedBy:    "tester",
	}
	require.NoError(t, ls.db.WithContext(ctx).Create(policy).Error)

	return secret.ID, policy.ID
}

// TestGetRotationPolicyBySecret_HappyPath verifies that a secret with an active
// project-scoped policy returns that policy.
func TestGetRotationPolicyBySecret_HappyPath(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()
	secretID, policyID := seedRotationPolicyFixture(t, ls)

	got, err := ls.GetRotationPolicyBySecret(ctx, secretID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, policyID, got.ID)
	assert.Equal(t, "30-day", got.Name)
}

// TestGetRotationPolicyBySecret_SecretNotFound verifies that a non-existent
// secret ID returns a "secret not found" error.
func TestGetRotationPolicyBySecret_SecretNotFound(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()

	_, err := ls.GetRotationPolicyBySecret(ctx, 99999)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "secret not found"),
		"expected 'secret not found' in error: %v", err)
}

// TestGetRotationPolicyBySecret_NoPolicyForSecret verifies that a secret that
// exists but has no active policy returns a "rotation policy not found" error.
func TestGetRotationPolicyBySecret_NoPolicyForSecret(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()

	// Create a secret in its own project with no rotation policy attached.
	proj := &models.Project{Name: "bare-proj"}
	require.NoError(t, ls.db.Create(proj).Error)
	env := &models.Environment{Name: "staging", ProjectID: proj.ID}
	require.NoError(t, ls.db.Create(env).Error)
	secret := &models.SecretNode{
		Name:          "BARE_KEY",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		IsSecret:      true,
	}
	require.NoError(t, ls.db.Create(secret).Error)

	_, err := ls.GetRotationPolicyBySecret(ctx, secret.ID)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "rotation policy not found"),
		"expected 'rotation policy not found' in error: %v", err)
}

// TestGetRotationPolicyBySecret_EnvironmentScopeWins verifies that when both a
// project-scoped and an environment-scoped policy exist, the environment-scoped
// one is preferred (narrowest scope first).
func TestGetRotationPolicyBySecret_EnvironmentScopeWins(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()

	proj := &models.Project{Name: "multi-scope-proj"}
	require.NoError(t, ls.db.Create(proj).Error)
	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, ls.db.Create(env).Error)
	secret := &models.SecretNode{
		Name:          "TOKEN",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		IsSecret:      true,
	}
	require.NoError(t, ls.db.Create(secret).Error)

	// Project-scoped policy (lower priority).
	projPolicy := &models.RotationPolicy{
		Name:         "project-wide-60d",
		Scope:        "project",
		ProjectID:    &proj.ID,
		IntervalDays: 60,
		IsActive:     true,
		CreatedBy:    "tester",
	}
	require.NoError(t, ls.db.Create(projPolicy).Error)

	// Environment-scoped policy (higher priority).
	envPolicy := &models.RotationPolicy{
		Name:          "env-30d",
		Scope:         "environment",
		ProjectID:     &proj.ID,
		EnvironmentID: &env.ID,
		IntervalDays:  30,
		IsActive:      true,
		CreatedBy:     "tester",
	}
	require.NoError(t, ls.db.Create(envPolicy).Error)

	got, err := ls.GetRotationPolicyBySecret(ctx, secret.ID)
	require.NoError(t, err)
	assert.Equal(t, envPolicy.ID, got.ID, "environment-scoped policy should win over project-scoped")
}

// TestUpdateRotationState_HappyPath verifies that UpdateRotationState stamps the
// expected state, error message, and last_state_at on the policy row.
func TestUpdateRotationState_HappyPath(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()
	_, policyID := seedRotationPolicyFixture(t, ls)

	err := ls.UpdateRotationState(ctx, policyID, "failed", "connection refused")
	require.NoError(t, err)

	var got models.RotationPolicy
	require.NoError(t, ls.db.First(&got, policyID).Error)
	assert.Equal(t, "failed", got.RotationState)
	assert.Equal(t, "connection refused", got.LastRotationError)
	assert.NotNil(t, got.LastStateAt)
}

// TestUpdateRotationState_NotFound verifies that updating a non-existent policy
// returns a "rotation policy not found" error.
func TestUpdateRotationState_NotFound(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()

	err := ls.UpdateRotationState(ctx, 99999, "succeeded", "")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "rotation policy not found"),
		"expected 'rotation policy not found' in error: %v", err)
}

// TestGetRotationPolicyBySecret_SecretLookupDBError verifies that a real DB
// failure on the secret lookup propagates as a wrapped error (not "not found").
func TestGetRotationPolicyBySecret_SecretLookupDBError(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()
	_, _ = seedRotationPolicyFixture(t, ls)

	// Drop secret_nodes so the first query returns a table-missing error.
	require.NoError(t, ls.db.Exec("DROP TABLE secret_nodes").Error)

	_, err := ls.GetRotationPolicyBySecret(ctx, 1)
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), "not found"),
		"expected a DB-error path (not a not-found), got: %v", err)
}

// TestGetRotationPolicyBySecret_PolicyLookupDBError verifies that a real DB
// failure on the policy lookup (after a successful secret lookup) propagates
// as a wrapped error from the policy query path.
func TestGetRotationPolicyBySecret_PolicyLookupDBError(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()
	secretID, _ := seedRotationPolicyFixture(t, ls)

	// Drop rotation_policies so the policy query returns a table-missing error
	// while the secret lookup still succeeds.
	require.NoError(t, ls.db.Exec("DROP TABLE rotation_policies").Error)

	_, err := ls.GetRotationPolicyBySecret(ctx, secretID)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "GetRotationPolicyBySecret"),
		"expected wrapped policy-lookup error, got: %v", err)
}

// TestUpdateRotationState_DBError verifies that a real DB failure propagates
// as an error from UpdateRotationState.
func TestUpdateRotationState_DBError(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()
	_, policyID := seedRotationPolicyFixture(t, ls)

	sqlDB, err := ls.db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	err = ls.UpdateRotationState(ctx, policyID, "rotating", "")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "UpdateRotationState"),
		"expected error to mention UpdateRotationState, got: %v", err)
}

// TestUpdateRotationState_ClearsError verifies that a subsequent succeeded state
// with an empty error message overwrites the previous error string.
func TestUpdateRotationState_ClearsError(t *testing.T) {
	ls := newRotationPoliciesTestStore(t)
	ctx := context.Background()
	_, policyID := seedRotationPolicyFixture(t, ls)

	require.NoError(t, ls.UpdateRotationState(ctx, policyID, "failed", "timeout"))
	require.NoError(t, ls.UpdateRotationState(ctx, policyID, "succeeded", ""))

	var got models.RotationPolicy
	require.NoError(t, ls.db.First(&got, policyID).Error)
	assert.Equal(t, "succeeded", got.RotationState)
	assert.Equal(t, "", got.LastRotationError)
}
