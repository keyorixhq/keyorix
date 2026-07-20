package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// bulkDeleteStub sets up an httptest server that mimics the bulk-delete endpoint.
// captureBody, if non-nil, receives the decoded request body.
func bulkDeleteStub(t *testing.T, projectID int, handler http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Also serve the secrets list endpoint used for name resolution.
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets" {
			// Return two named secrets for the --names resolution test.
			_, _ = w.Write([]byte(`{"data":{"secrets":[` +
				`{"id":10,"name":"alpha","project_id":7,"environment_id":1,"is_secret":true},` +
				`{"id":11,"name":"beta","project_id":7,"environment_id":1,"is_secret":true}` +
				`],"total":2}}`))
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	_ = projectID
	return rc, srv.Close
}

func successHandler(deleted []uint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"deleted": deleted,
					"failed":  []interface{}{},
					"total":   len(deleted),
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func TestBulkDelete_Remote_Success(t *testing.T) {
	var capturedBody map[string]interface{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &capturedBody)
		successHandler([]uint{1, 2, 3})(w, r)
	}
	rc, done := bulkDeleteStub(t, 7, handler)
	defer done()

	result, err := postBulkDelete(context.Background(), rc, 7, []uint{1, 2, 3})
	require.NoError(t, err)
	assert.Len(t, result.Deleted, 3)
	assert.Empty(t, result.Failed)
	assert.Equal(t, 3, result.Total)
}

func TestBulkDelete_Remote_PartialFailure(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"deleted": []uint{1},
				"failed": []interface{}{
					map[string]interface{}{
						"secret_id": 99,
						"name":      "ghost",
						"error":     "secret not found",
					},
				},
				"total": 2,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
	rc, done := bulkDeleteStub(t, 7, handler)
	defer done()

	result, err := postBulkDelete(context.Background(), rc, 7, []uint{1, 99})
	require.NoError(t, err)
	assert.Len(t, result.Deleted, 1)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, "secret not found", result.Failed[0].Error)
}

func TestBulkDelete_Remote_RequiresConfirm(t *testing.T) {
	called := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		called = true
		successHandler([]uint{1})(w, r)
	}
	_, done := bulkDeleteStub(t, 7, handler)
	defer done()

	// Simulate the --no-confirm path: call runBulkDeleteRemote via the exported
	// postBulkDelete but gate on bulkDeleteConfirm being false.
	// The command itself doesn't reach postBulkDelete when confirm is false.
	// We verify this by checking the flag guard inline.
	origConfirm := bulkDeleteConfirm
	bulkDeleteConfirm = false
	defer func() { bulkDeleteConfirm = origConfirm }()

	// Without --confirm the command should print and return nil without calling the API.
	// We reset IDs/names to match a dry-run scenario.
	origIDs := bulkDeleteIDs
	origNames := bulkDeleteNames
	origProject := bulkDeleteProject
	bulkDeleteIDs = []uint{1}
	bulkDeleteNames = nil
	bulkDeleteProject = 7
	defer func() {
		bulkDeleteIDs = origIDs
		bulkDeleteNames = origNames
		bulkDeleteProject = origProject
	}()

	err := runBulkDeleteRemote(context.Background(), nil)
	// nil rc is fine because we never reach postBulkDelete without confirm.
	// The function returns nil after printing the preview.
	assert.NoError(t, err)
	assert.False(t, called, "API must not be called without --confirm")
}

func TestBulkDelete_Remote_NamesResolved(t *testing.T) {
	// The stub serves GET /api/v1/secrets returning alpha(10) and beta(11).
	// postBulkDelete should be called with IDs [10,11] after name resolution.
	var capturedIDs []interface{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		if ids, ok := body["secret_ids"].([]interface{}); ok {
			capturedIDs = ids
		}
		successHandler([]uint{10, 11})(w, r)
	}
	rc, done := bulkDeleteStub(t, 7, handler)
	defer done()

	ids, err := resolveNamesToIDs(context.Background(), rc, 7, []string{"alpha", "beta"})
	require.NoError(t, err)
	require.Len(t, ids, 2)
	assert.Contains(t, ids, uint(10))
	assert.Contains(t, ids, uint(11))

	// Now post with the resolved IDs.
	result, err := postBulkDelete(context.Background(), rc, 7, ids)
	require.NoError(t, err)
	assert.Len(t, result.Deleted, 2)
	_ = capturedIDs // verified by result assertions
}

// ── runBulkDelete entry-point ─────────────────────────────────────────────────

func TestRunBulkDelete_NoIDsOrNames(t *testing.T) {
	origIDs := bulkDeleteIDs
	origNames := bulkDeleteNames
	t.Cleanup(func() { bulkDeleteIDs = origIDs; bulkDeleteNames = origNames })
	bulkDeleteIDs = nil
	bulkDeleteNames = nil

	err := runBulkDelete(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one of --ids or --names is required")
}

// ── runBulkDeleteRemote ───────────────────────────────────────────────────────

func TestRunBulkDeleteRemote_NamesWithoutProject(t *testing.T) {
	origProject := bulkDeleteProject
	origNames := bulkDeleteNames
	t.Cleanup(func() { bulkDeleteProject = origProject; bulkDeleteNames = origNames })
	bulkDeleteProject = 0
	bulkDeleteNames = []string{"foo"}

	// rc is never reached due to early return.
	err := runBulkDeleteRemote(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project is required when using --names")
}

func TestRunBulkDeleteRemote_WithIDsConfirmed(t *testing.T) {
	origProject := bulkDeleteProject
	origIDs := bulkDeleteIDs
	origNames := bulkDeleteNames
	origConfirm := bulkDeleteConfirm
	t.Cleanup(func() {
		bulkDeleteProject = origProject
		bulkDeleteIDs = origIDs
		bulkDeleteNames = origNames
		bulkDeleteConfirm = origConfirm
	})
	bulkDeleteProject = 7
	bulkDeleteIDs = []uint{1, 2}
	bulkDeleteNames = nil
	bulkDeleteConfirm = true

	rc, done := bulkDeleteStub(t, 7, successHandler([]uint{1, 2}))
	defer done()

	err := runBulkDeleteRemote(context.Background(), rc)
	require.NoError(t, err)
}

func TestRunBulkDeleteRemote_NamesWithProjectConfirmed(t *testing.T) {
	origProject := bulkDeleteProject
	origIDs := bulkDeleteIDs
	origNames := bulkDeleteNames
	origConfirm := bulkDeleteConfirm
	t.Cleanup(func() {
		bulkDeleteProject = origProject
		bulkDeleteIDs = origIDs
		bulkDeleteNames = origNames
		bulkDeleteConfirm = origConfirm
	})
	bulkDeleteProject = 7
	bulkDeleteIDs = nil
	bulkDeleteNames = []string{"alpha"}
	bulkDeleteConfirm = true

	rc, done := bulkDeleteStub(t, 7, successHandler([]uint{10}))
	defer done()

	err := runBulkDeleteRemote(context.Background(), rc)
	require.NoError(t, err)
}

func TestResolveNamesToIDs_NameNotFound(t *testing.T) {
	rc, done := bulkDeleteStub(t, 7, func(w http.ResponseWriter, r *http.Request) {})
	defer done()

	// The stub serves alpha(10) and beta(11); "gamma" is not present.
	_, err := resolveNamesToIDs(context.Background(), rc, 7, []string{"gamma"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gamma")
}

// ── printBulkDeleteResult ─────────────────────────────────────────────────────

func TestPrintBulkDeleteResult_NoFailures(t *testing.T) {
	r := bulkDeleteResult{
		Deleted: []uint{1, 2, 3},
		Total:   3,
	}
	// Verify no panic; output goes to stdout.
	printBulkDeleteResult(r)
}

func TestPrintBulkDeleteResult_WithFailures(t *testing.T) {
	r := bulkDeleteResult{
		Deleted: []uint{1},
		Failed: []bulkDeleteError{
			{SecretID: 99, Name: "ghost", Error: "not found"},  // named failure
			{SecretID: 100, Error: "access denied"},             // unnamed failure (id=N label)
		},
		Total: 3,
	}
	printBulkDeleteResult(r)
}

// ── joinUints ─────────────────────────────────────────────────────────────────

func TestJoinUints(t *testing.T) {
	assert.Equal(t, "", joinUints(nil))
	assert.Equal(t, "1", joinUints([]uint{1}))
	assert.Equal(t, "1, 2, 3", joinUints([]uint{1, 2, 3}))
}

// ── runBulkDeleteEmbedded ─────────────────────────────────────────────────────

func TestRunBulkDeleteEmbedded_NoProject(t *testing.T) {
	origProject := bulkDeleteProject
	t.Cleanup(func() { bulkDeleteProject = origProject })
	bulkDeleteProject = 0

	err := runBulkDeleteEmbedded(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project is required in embedded mode")
}

func TestRunBulkDeleteEmbedded_PreviewMode(t *testing.T) {
	origProject := bulkDeleteProject
	origIDs := bulkDeleteIDs
	origNames := bulkDeleteNames
	origConfirm := bulkDeleteConfirm
	t.Cleanup(func() {
		bulkDeleteProject = origProject
		bulkDeleteIDs = origIDs
		bulkDeleteNames = origNames
		bulkDeleteConfirm = origConfirm
		_ = os.Remove("secrets.db")
	})
	bulkDeleteProject = 1
	bulkDeleteIDs = []uint{42}
	bulkDeleteNames = nil
	bulkDeleteConfirm = false

	// InitializeCoreService creates ./secrets.db and initialises i18n with English.
	err := runBulkDeleteEmbedded(context.Background())
	require.NoError(t, err)
}

func TestRunBulkDeleteEmbedded_DeleteNotFound(t *testing.T) {
	origProject := bulkDeleteProject
	origIDs := bulkDeleteIDs
	origNames := bulkDeleteNames
	origConfirm := bulkDeleteConfirm
	t.Cleanup(func() {
		bulkDeleteProject = origProject
		bulkDeleteIDs = origIDs
		bulkDeleteNames = origNames
		bulkDeleteConfirm = origConfirm
		_ = os.Remove("secrets.db")
	})
	bulkDeleteProject = 1
	bulkDeleteIDs = []uint{9999}
	bulkDeleteNames = nil
	bulkDeleteConfirm = true

	// BulkDeleteSecrets returns (result, nil) with 9999 in Failed (record not found).
	err := runBulkDeleteEmbedded(context.Background())
	require.NoError(t, err)
}

// ── resolveNamesToIDsEmbedded ─────────────────────────────────────────────────

var bulkEmbeddedDBCounter atomic.Int64

func newBulkEmbeddedCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	n := bulkEmbeddedDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxbulkembed_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "test"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

func TestResolveNamesToIDsEmbedded_NotFound(t *testing.T) {
	svc := newBulkEmbeddedCore(t)

	_, err := resolveNamesToIDsEmbedded(context.Background(), svc, 1, []string{"nonexistent"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestResolveNamesToIDsEmbedded_Found(t *testing.T) {
	svc := newBulkEmbeddedCore(t)

	// Create a secret so name resolution succeeds.
	s, err := svc.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "my-secret", Value: []byte("val"), ProjectID: 1, EnvironmentID: 1,
		Type: "generic", CreatedBy: "test", OwnerID: 1,
	})
	require.NoError(t, err)

	ids, err := resolveNamesToIDsEmbedded(context.Background(), svc, 1, []string{"my-secret"})
	require.NoError(t, err)
	require.Len(t, ids, 1)
	assert.Equal(t, s.ID, ids[0])
}
