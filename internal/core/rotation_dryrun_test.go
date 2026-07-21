package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/rotation"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newDryRunCore builds a minimal KeyorixCore backed by an in-memory SQLite DB.
func newDryRunCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.RotationPolicy{},
		&models.AuditEvent{}, &models.Project{}, &models.Environment{},
		&models.Role{}, &models.UserRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	c := &KeyorixCore{
		storage: store.NewLocalStorage(db),
		now:     func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) },
	}
	return c, db
}

// seedDryRunSecret inserts a SecretNode into the DB and returns its ID.
func seedDryRunSecret(t *testing.T, db *gorm.DB, id uint, backend, ref string) {
	t.Helper()
	require.NoError(t, db.Create(&models.SecretNode{
		ID: id, Name: "test-secret", ProjectID: 1, EnvironmentID: 1,
		IsSecret: true, Status: "active",
		RotationBackend: backend, RotationRef: ref,
	}).Error)
}

// seedActivePolicy inserts an active project-scoped RotationPolicy.
func seedActivePolicy(t *testing.T, db *gorm.DB) {
	t.Helper()
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid,
		IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
}

// TestSimulateRotation_SecretNotFound ensures an error is returned (not a DryRunResult)
// when the secret ID does not exist.
func TestSimulateRotation_SecretNotFound(t *testing.T) {
	c, _ := newDryRunCore(t)
	_, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 9999})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found")
}

// TestSimulateRotation_NoPolicy verifies that a secret with no covering rotation policy
// results in Valid=false with the policy_exists check failing.
func TestSimulateRotation_NoPolicy(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "pg", "myrole")
	// No rotation policy inserted.
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.False(t, res.Valid)

	policyCheck := findCheck(res.Checks, "policy_exists")
	require.NotNil(t, policyCheck)
	assert.False(t, policyCheck.Passed)
	assert.Contains(t, policyCheck.Message, "no active rotation policy")
}

// TestSimulateRotation_InactivePolicyOnly verifies that a secret covered only by
// an INACTIVE policy still fails policy_exists.
func TestSimulateRotation_InactivePolicyOnly(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "pg", "myrole")
	// Insert the inactive policy via raw SQL to force is_active = false (GORM's struct
	// Create omits zero bool values, letting the column default = true override it).
	require.NoError(t, db.Exec(
		"INSERT INTO rotation_policies (id, name, scope, project_id, interval_days, is_active, created_by, notify_on_breach, alert_days_before) VALUES (2, 'inactive', 'project', 1, 30, false, 'admin', false, 7)",
	).Error)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	assert.False(t, res.Valid)

	policyCheck := findCheck(res.Checks, "policy_exists")
	require.NotNil(t, policyCheck)
	assert.False(t, policyCheck.Passed)
}

// TestSimulateRotation_EnvironmentScopedPolicyCovering verifies that an environment-
// scoped policy covering this secret's environment passes policy_exists.
func TestSimulateRotation_EnvironmentScopedPolicyCovering(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "pg", "myrole")
	envID := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 3, Name: "env-policy", Scope: "environment", EnvironmentID: &envID,
		IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)

	policyCheck := findCheck(res.Checks, "policy_exists")
	require.NotNil(t, policyCheck)
	assert.True(t, policyCheck.Passed)
}

// TestSimulateRotation_EnvironmentScopedPolicyWrongEnv verifies that an environment-
// scoped policy for a different environment does NOT cover this secret.
func TestSimulateRotation_EnvironmentScopedPolicyWrongEnv(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "pg", "myrole")
	otherEnvID := uint(99)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 4, Name: "other-env-policy", Scope: "environment", EnvironmentID: &otherEnvID,
		IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)

	policyCheck := findCheck(res.Checks, "policy_exists")
	require.NotNil(t, policyCheck)
	assert.False(t, policyCheck.Passed)
}

// TestSimulateRotation_UnknownBackend verifies that a secret with no/unknown backend
// fails the backend_known check.
func TestSimulateRotation_UnknownBackend(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "unknown-backend", "myrole")
	seedActivePolicy(t, db)
	// Only "pg" is registered, not "unknown-backend".
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	assert.False(t, res.Valid)

	backendCheck := findCheck(res.Checks, "backend_known")
	require.NotNil(t, backendCheck)
	assert.False(t, backendCheck.Passed)
	assert.Contains(t, backendCheck.Message, "not registered")
}

// TestSimulateRotation_NoBackendConfigured verifies that a secret with an empty backend
// fails the backend_known check with a "no backend configured" message.
func TestSimulateRotation_NoBackendConfigured(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "", "myrole")
	seedActivePolicy(t, db)

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	assert.False(t, res.Valid)

	backendCheck := findCheck(res.Checks, "backend_known")
	require.NotNil(t, backendCheck)
	assert.False(t, backendCheck.Passed)
	assert.Contains(t, backendCheck.Message, "empty")
}

// TestSimulateRotation_NoRotationManagerConfigured verifies the message when the
// rotation manager is nil (no backends configured at all).
func TestSimulateRotation_NoRotationManagerConfigured(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "pg", "myrole")
	seedActivePolicy(t, db)
	// c.rotationManager is nil (not set)

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	assert.False(t, res.Valid)

	backendCheck := findCheck(res.Checks, "backend_known")
	require.NotNil(t, backendCheck)
	assert.False(t, backendCheck.Passed)
	assert.Contains(t, backendCheck.Message, "no rotation backends are configured")
}

// TestSimulateRotation_EmptyRef verifies that an empty rotation ref fails ref_non_empty.
func TestSimulateRotation_EmptyRef(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "pg", "")
	seedActivePolicy(t, db)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	assert.False(t, res.Valid)

	refCheck := findCheck(res.Checks, "ref_non_empty")
	require.NotNil(t, refCheck)
	assert.False(t, refCheck.Passed)
	assert.Contains(t, refCheck.Message, "empty")
}

// TestSimulateRotation_InvalidRef verifies that a ref containing disallowed characters
// fails the ref_valid check.
func TestSimulateRotation_InvalidRef(t *testing.T) {
	c, db := newDryRunCore(t)
	// A ref with a SQL metacharacter (single-quote) should fail ref_valid.
	seedDryRunSecret(t, db, 1, "pg", "bad'ref")
	seedActivePolicy(t, db)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	assert.False(t, res.Valid)

	refValidCheck := findCheck(res.Checks, "ref_valid")
	require.NotNil(t, refValidCheck)
	assert.False(t, refValidCheck.Passed)
}

// TestSimulateRotation_AllValid verifies that a fully configured secret passes
// all checks and returns Valid=true.
func TestSimulateRotation_AllValid(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "pg", "myrole")
	seedActivePolicy(t, db)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.True(t, res.Valid)
	assert.Equal(t, uint(1), res.SecretID)
	assert.Equal(t, "test-secret", res.SecretName)
	assert.Equal(t, "pg", res.Backend)
	assert.Equal(t, "myrole", res.Ref)
	assert.False(t, res.SimulatedAt.IsZero())

	// All checks must be present and pass.
	require.Len(t, res.Checks, 4)
	for _, ch := range res.Checks {
		assert.True(t, ch.Passed, "check %q should pass", ch.Name)
	}
}

// TestSimulateRotation_AllChecksPresent verifies that the result always has all
// four named checks, even on a fully failing secret.
func TestSimulateRotation_AllChecksPresent(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "", "")
	// No policy, no manager.

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	require.Len(t, res.Checks, 4)
	names := make([]string, len(res.Checks))
	for i, ch := range res.Checks {
		names[i] = ch.Name
	}
	assert.Contains(t, names, "policy_exists")
	assert.Contains(t, names, "backend_known")
	assert.Contains(t, names, "ref_non_empty")
	assert.Contains(t, names, "ref_valid")
}

// TestSimulateRotation_SimulatedAtPopulated verifies that SimulatedAt is always set.
func TestSimulateRotation_SimulatedAtPopulated(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "pg", "myrole")
	seedActivePolicy(t, db)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), res.SimulatedAt)
}

// TestCheckRefValid_EmptyRefPassthrough verifies the special-case path where
// checkRefValid is called with an empty ref (defers to ref_non_empty).
func TestCheckRefValid_EmptyRefPassthrough(t *testing.T) {
	ch := checkRefValid("")
	assert.True(t, ch.Passed)
	assert.Equal(t, "ref_valid", ch.Name)
	assert.Contains(t, ch.Message, "empty")
}

// TestCheckRefNonEmpty_NonEmpty verifies the passing case.
func TestCheckRefNonEmpty_NonEmpty(t *testing.T) {
	ch := checkRefNonEmpty("myrole")
	assert.True(t, ch.Passed)
	assert.Equal(t, "ref_non_empty", ch.Name)
}

// TestCheckRefValid_ValidRef verifies a clean ref passes.
func TestCheckRefValid_ValidRef(t *testing.T) {
	ch := checkRefValid("myrole")
	assert.True(t, ch.Passed)
	assert.Equal(t, "ref_valid", ch.Name)
}

// TestSimulateRotation_ProjectScopedPolicyCovering verifies that a project-scoped
// active policy passes policy_exists.
func TestSimulateRotation_ProjectScopedPolicyCovering(t *testing.T) {
	c, db := newDryRunCore(t)
	seedDryRunSecret(t, db, 1, "pg", "myrole")
	seedActivePolicy(t, db) // project-scoped
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))

	res, err := c.SimulateRotation(context.Background(), RotationDryRunRequest{SecretID: 1})
	require.NoError(t, err)

	policyCheck := findCheck(res.Checks, "policy_exists")
	require.NotNil(t, policyCheck)
	assert.True(t, policyCheck.Passed)
	assert.Contains(t, policyCheck.Message, "30-day")
}

// TestCheckPolicyExists_StorageErrorFirstQuery verifies that a storage error on the
// project-policy query (first call) returns a failing policy_exists check.
func TestCheckPolicyExists_StorageErrorFirstQuery(t *testing.T) {
	mockSt := new(MockStorage)
	c := &KeyorixCore{
		storage: mockSt,
		now:     func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) },
	}
	pid := uint(1)
	// First call (project-scoped): return error.
	mockSt.On("ListRotationPolicies", mock.Anything, &pid, (*uint)(nil)).
		Return(nil, fmt.Errorf("db error"))

	ch := c.checkPolicyExists(context.Background(), 1, 1)
	assert.False(t, ch.Passed)
	assert.Equal(t, "policy_exists", ch.Name)
	assert.Contains(t, ch.Message, "could not list rotation policies")
	mockSt.AssertExpectations(t)
}

// TestCheckPolicyExists_StorageErrorSecondQuery verifies that a storage error on the
// environment-policy query (second call, after the first returns no active policy)
// returns a failing policy_exists check.
func TestCheckPolicyExists_StorageErrorSecondQuery(t *testing.T) {
	mockSt := new(MockStorage)
	c := &KeyorixCore{
		storage: mockSt,
		now:     func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) },
	}
	pid := uint(1)
	envID := uint(1)
	// First call (project-scoped): return an inactive policy so the loop doesn't return early.
	inactive := &models.RotationPolicy{ID: 99, Name: "inactive", Scope: "project", IsActive: false}
	mockSt.On("ListRotationPolicies", mock.Anything, &pid, (*uint)(nil)).
		Return([]*models.RotationPolicy{inactive}, nil)
	// Second call (environment-scoped): return error.
	mockSt.On("ListRotationPolicies", mock.Anything, (*uint)(nil), &envID).
		Return(nil, fmt.Errorf("env db error"))

	ch := c.checkPolicyExists(context.Background(), 1, 1)
	assert.False(t, ch.Passed)
	assert.Equal(t, "policy_exists", ch.Name)
	assert.Contains(t, ch.Message, "could not list rotation policies")
	mockSt.AssertExpectations(t)
}

// findCheck is a helper that returns a pointer to the DryRunCheck with the given name,
// or nil if not found.
func findCheck(checks []DryRunCheck, name string) *DryRunCheck {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}
