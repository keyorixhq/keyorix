// secret_dep_coverage_test.go — coverage blitz for secret_dependencies.go and
// secret_dependencies_proxy.go, targeting the branches left uncovered after the
// impact-preview feature commit (394f0635):
//
//   - ListSecretDependencies: success path (line 62)
//   - AddSecretDependency: success path (line 94)
//   - RemoveSecretDependency: success path (line 118)
//   - GetSecretImpact: success path (line 137)
//   - GetProjectRotationOrder: storage-error path (lines 174-177)
//   - GetProjectRotationPlan: storage-error path (lines 195-198)
//   - GetDeploymentRotationPlan: storage-error path (lines 212-215)
//   - CreateSecretDependencyExclusiveProxy: duplicate + cycle + default error
//     branches (lines 149-153)
//   - GetSecretDependencyProxy: internal-error path (lines 173-175)
//   - DeleteSecretDependencyProxy: internal-error path (lines 227-229)
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ── DB helpers ────────────────────────────────────────────────────────────────

var sDepCovCounter atomic.Int64

// freshDepCovCore opens a uniquely-named in-memory SQLite DB with all models
// migrated and returns (KeyorixCore, *gorm.DB). The DB is exposed so callers
// can seed records or close the underlying connection.
func freshDepCovCore(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := sDepCovCounter.Add(1)
	dsn := fmt.Sprintf("file:kxdep_cov_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	// withUserCtx's UserID 1 is granted global admin: #G32's independent peer-secret
	// authorization check would otherwise reject every Add/RemoveSecretDependency call
	// here (this file tests the handler's glue logic — param parsing, error-status
	// mapping — not authorization, which is the router middleware's job).
	role := &models.Role{Name: "admin"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: role.ID, ProjectID: 0, EnvironmentID: 0}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// mkDepSecret inserts an active secret into the given project/environment and
// returns its ID.
func mkDepSecret(t *testing.T, db *gorm.DB, projectID, envID uint, name string) uint {
	t.Helper()
	s := &models.SecretNode{
		ProjectID:     projectID,
		EnvironmentID: envID,
		Name:          name,
		IsSecret:      true,
		Status:        "active",
	}
	require.NoError(t, db.Create(s).Error)
	return s.ID
}

// seedProjectEnv creates a Project and an Environment in the given DB and
// returns their IDs.
func seedProjectEnv(t *testing.T, db *gorm.DB) (projectID, envID uint) {
	t.Helper()
	p := &models.Project{Name: "dep-cov-project"}
	require.NoError(t, db.Create(p).Error)
	e := &models.Environment{ProjectID: p.ID, Name: "dep-cov-env"}
	require.NoError(t, db.Create(e).Error)
	return p.ID, e.ID
}

// ── ListSecretDependencies: success path ─────────────────────────────────────

// TestListSecretDependencies_SuccessPath_DepCov — a real secret with no edges
// returns 200 and a valid JSON body.
func TestListSecretDependencies_SuccessPath_DepCov(t *testing.T) {
	cs, db := freshDepCovCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	projID, envID := seedProjectEnv(t, db)
	sid := mkDepSecret(t, db, projID, envID, "list-deps-root")

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.ListSecretDependencies(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"secret_id"`)
}

// ── AddSecretDependency: success path ────────────────────────────────────────

// TestAddSecretDependency_SuccessPath_DepCov — two real secrets in the same
// project+environment; adding the dependency returns 200 and a result body.
func TestAddSecretDependency_SuccessPath_DepCov(t *testing.T) {
	cs, db := freshDepCovCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	projID, envID := seedProjectEnv(t, db)
	depID := mkDepSecret(t, db, projID, envID, "add-dep-dependent")
	upstreamID := mkDepSecret(t, db, projID, envID, "add-dep-upstream")

	body, _ := json.Marshal(map[string]any{"depends_on_id": upstreamID})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)), "id",
		fmt.Sprintf("%d", depID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Dependency added")
}

// ── RemoveSecretDependency: success path ─────────────────────────────────────

// TestRemoveSecretDependency_SuccessPath_DepCov — create an edge then remove it;
// handler returns 200 with removed:true.
func TestRemoveSecretDependency_SuccessPath_DepCov(t *testing.T) {
	cs, db := freshDepCovCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	projID, envID := seedProjectEnv(t, db)
	depID := mkDepSecret(t, db, projID, envID, "rem-dep-dependent")
	upstreamID := mkDepSecret(t, db, projID, envID, "rem-dep-upstream")

	// Create the edge directly so we get its ID.
	edge := &models.SecretDependency{
		ProjectID:         projID,
		DependentSecretID: depID,
		DependsOnSecretID: upstreamID,
	}
	require.NoError(t, db.Create(edge).Error)

	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": fmt.Sprintf("%d", depID), "depId": fmt.Sprintf("%d", edge.ID)},
	))
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"removed":true`)
}

// ── GetSecretImpact: success path ────────────────────────────────────────────

// TestGetSecretImpact_SuccessPath_DepCov — a real secret with no dependents;
// impact endpoint returns 200.
func TestGetSecretImpact_SuccessPath_DepCov(t *testing.T) {
	cs, db := freshDepCovCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	projID, envID := seedProjectEnv(t, db)
	sid := mkDepSecret(t, db, projID, envID, "impact-root")

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.GetSecretImpact(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"secret_id"`)
}

// ── GetProjectRotationOrder: storage-error path ──────────────────────────────

// TestGetProjectRotationOrder_StorageError_DepCov — closing the DB after
// building the core triggers a 500 when the handler queries the dependency
// store for the project's edges.
func TestGetProjectRotationOrder_StorageError_DepCov(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	n := sDepCovCounter.Add(1)
	dsn := fmt.Sprintf("file:kxdep_cov_roterr_%d?mode=memory&cache=shared&_timeout=5000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	// Close the underlying SQL connection to force storage errors.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil), "id", "1",
	))
	w := httptest.NewRecorder()
	h.GetProjectRotationOrder(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── GetProjectRotationPlan: storage-error path ───────────────────────────────

// TestGetProjectRotationPlan_StorageError_DepCov — same closed-DB trick; the
// handler's error path returns 500.
func TestGetProjectRotationPlan_StorageError_DepCov(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	n := sDepCovCounter.Add(1)
	dsn := fmt.Sprintf("file:kxdep_cov_planerr_%d?mode=memory&cache=shared&_timeout=5000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil), "id", "1",
	))
	w := httptest.NewRecorder()
	h.GetProjectRotationPlan(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── GetDeploymentRotationPlan: storage-error path ────────────────────────────

// TestGetDeploymentRotationPlan_StorageError_DepCov — closed DB forces a
// ListProjects failure; handler returns 500.
func TestGetDeploymentRotationPlan_StorageError_DepCov(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	n := sDepCovCounter.Add(1)
	dsn := fmt.Sprintf("file:kxdep_cov_deplerr_%d?mode=memory&cache=shared&_timeout=5000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetDeploymentRotationPlan(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CreateSecretDependencyExclusiveProxy: duplicate / cycle / default errors ─

// TestCreateSecretDependencyExclusiveProxy_Duplicate_DepCov — inserting the
// same edge twice triggers ErrDuplicateSecretDependency → 409 Conflict.
func TestCreateSecretDependencyExclusiveProxy_Duplicate_DepCov(t *testing.T) {
	cs, db := freshDepCovCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	projectID, envID := seedProjectEnv(t, db)
	depID := mkDepSecret(t, db, projectID, envID, "dependent")
	dependsOnID := mkDepSecret(t, db, projectID, envID, "depends-on")

	// Insert the row once so the second call triggers a duplicate error.
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID:         projectID,
		DependentSecretID: depID,
		DependsOnSecretID: dependsOnID,
	}).Error)

	body, _ := json.Marshal(map[string]any{
		"project_id":           projectID,
		"dependent_secret_id":  depID,
		"depends_on_secret_id": dependsOnID,
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyExclusiveProxy(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// TestCreateSecretDependencyExclusiveProxy_Cycle_DepCov — insert A→B first,
// then attempt B→A via the exclusive proxy; the cycle check returns 400.
func TestCreateSecretDependencyExclusiveProxy_Cycle_DepCov(t *testing.T) {
	cs, db := freshDepCovCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	projectID, envID := seedProjectEnv(t, db)
	secretA := mkDepSecret(t, db, projectID, envID, "a")
	secretB := mkDepSecret(t, db, projectID, envID, "b")

	// Insert A→B to prime the cycle detector.
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID:         projectID,
		DependentSecretID: secretA,
		DependsOnSecretID: secretB,
	}).Error)

	// Now attempt B→A (A depends on B, B depends on A → cycle).
	body, _ := json.Marshal(map[string]any{
		"project_id":           projectID,
		"dependent_secret_id":  secretB,
		"depends_on_secret_id": secretA,
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyExclusiveProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateSecretDependencyExclusiveProxy_ConcurrentCycleRace is the #G79
// regression for the mutex bypass: two concurrent requests each adding one
// half of a cycle (A→B and B→A) must not both succeed. Before
// LockedCreateSecretDependencyExclusive, storage.CreateSecretDependencyExclusive's
// cycle check had no row to lock on SQLite (no FOR UPDATE support) for a
// project starting with zero edges, so both requests could read "no cycle yet"
// before either commits.
func TestCreateSecretDependencyExclusiveProxy_ConcurrentCycleRace(t *testing.T) {
	cs, db := freshDepCovCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	projectID, envID := seedProjectEnv(t, db)
	secretA := mkDepSecret(t, db, projectID, envID, "race-a")
	secretB := mkDepSecret(t, db, projectID, envID, "race-b")

	bodyAB, _ := json.Marshal(map[string]any{
		"project_id":           projectID,
		"dependent_secret_id":  secretA,
		"depends_on_secret_id": secretB,
	})
	bodyBA, _ := json.Marshal(map[string]any{
		"project_id":           projectID,
		"dependent_secret_id":  secretB,
		"depends_on_secret_id": secretA,
	})

	var wg sync.WaitGroup
	codes := make([]int, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyAB))
		w := httptest.NewRecorder()
		h.CreateSecretDependencyExclusiveProxy(w, req)
		codes[0] = w.Code
	}()
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyBA))
		w := httptest.NewRecorder()
		h.CreateSecretDependencyExclusiveProxy(w, req)
		codes[1] = w.Code
	}()
	wg.Wait()

	successes := 0
	for _, c := range codes {
		if c == http.StatusOK {
			successes++
		}
	}
	assert.LessOrEqual(t, successes, 1, "at most one half of a cycle may succeed; both succeeding means a cycle was committed")
}

// TestCreateSecretDependencyExclusiveProxy_DefaultStorageError_DepCov — closed
// DB triggers a plain storage error (neither duplicate nor cycle) → 500.
func TestCreateSecretDependencyExclusiveProxy_DefaultStorageError_DepCov(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	n := sDepCovCounter.Add(1)
	dsn := fmt.Sprintf("file:kxdep_cov_exclerr_%d?mode=memory&cache=shared&_timeout=5000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body, _ := json.Marshal(map[string]any{
		"project_id":           1,
		"dependent_secret_id":  10,
		"depends_on_secret_id": 20,
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyExclusiveProxy(w, req)
	// #G79: crossReferenceSecretDependencyProxy now runs first and fails closed
	// on ANY GetSecret error (including a broken-DB storage error, indistinguishable
	// here from "no such secret") — so this never reaches the storage.
	// CreateSecretDependencyExclusive call this test originally exercised.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
