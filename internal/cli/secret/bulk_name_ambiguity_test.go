// bulk_name_ambiguity_test.go — red test for the #2013 sweep follow-up:
// bulk-delete and bulk-rotate resolve --names to secret IDs via a name->ID
// map built from a listing that isn't scoped by environment (bulk-delete) or
// can be left unscoped when --env is omitted (bulk-rotate). A same-named
// secret in two environments of the same project silently loses to whichever
// entry a map insert happens to land on last, instead of refusing like
// `secret rotate` already does (inventory #2012 S2).
//
// Each test below documents the DESIRED (post-fix) behavior — refuse rather
// than silently pick — so it fails today against the pre-fix code for the
// right reason (a wrong/arbitrary ID silently proceeds) and passes once
// --env is required for --names and the resolvers refuse an ambiguous name.
package secret

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── bulk-delete ──────────────────────────────────────────────────────────────

// crossEnvDeleteStub serves GET /api/v1/secrets. When the query carries
// environment_id=1, it returns ONE secret ("db-password", id 10) — the
// correctly-scoped case. Otherwise (no environment_id, i.e. the pre-fix
// unscoped call, or any other value) it returns the SAME name in id 10 (env 1)
// AND id 11 (env 2) — simulating the real cross-environment collision.
// POST /api/v1/projects/7/secrets/bulk-delete records which IDs were deleted.
func crossEnvDeleteStub(t *testing.T, deletedIDs *[]float64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets" && r.URL.Query().Get("environment_id") == "1":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"id":10,"name":"db-password","project_id":7,"environment_id":1,"is_secret":true}],"total":1}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[` +
				`{"id":10,"name":"db-password","project_id":7,"environment_id":1,"is_secret":true},` +
				`{"id":11,"name":"db-password","project_id":7,"environment_id":2,"is_secret":true}` +
				`],"total":2}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/7/secrets/bulk-delete":
			b, _ := io.ReadAll(r.Body)
			var body struct {
				SecretIDs []float64 `json:"secret_ids"`
			}
			_ = json.Unmarshal(b, &body)
			if deletedIDs != nil {
				*deletedIDs = body.SecretIDs
			}
			_, _ = w.Write([]byte(`{"data":{"deleted":` + string(b) + `,"failed":[],"total":1}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestBulkDelete_NameAmbiguousAcrossEnvironments_WithoutEnvFlag_Refuses is the
// primary red test: --names without --env, against a project holding the same
// secret name in two environments, must be refused — not silently resolve to
// whichever environment's secret a map insert lands on last.
func TestBulkDelete_NameAmbiguousAcrossEnvironments_WithoutEnvFlag_Refuses(t *testing.T) {
	var deletedIDs []float64
	srv := crossEnvDeleteStub(t, &deletedIDs)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origEnv, origIDs, origNames, origConfirm := bulkDeleteProject, bulkDeleteEnv, bulkDeleteIDs, bulkDeleteNames, bulkDeleteConfirm
	t.Cleanup(func() {
		bulkDeleteProject, bulkDeleteEnv, bulkDeleteIDs, bulkDeleteNames, bulkDeleteConfirm = origProject, origEnv, origIDs, origNames, origConfirm
	})
	bulkDeleteProject = 7
	bulkDeleteEnv = 0 // deliberately omitted -- the vulnerable case
	bulkDeleteIDs = nil
	bulkDeleteNames = []string{"db-password"}
	bulkDeleteConfirm = true

	err := runBulkDelete(nil, nil)
	require.Error(t, err, "bulk-delete --names without --env must be refused when the project holds the same name in more than one environment")
	assert.Empty(t, deletedIDs, "no delete request may reach the server before the ambiguity is caught")
}

// TestBulkDelete_NameAmbiguousWithinScopedEnvironment_Refuses is the
// defense-in-depth case: even WITH a correct --project/--env scope, if that
// exact scope somehow still holds two secrets sharing a name, bulk-delete must
// refuse and list both IDs rather than delete an arbitrary one of them.
func TestBulkDelete_NameAmbiguousWithinScopedEnvironment_Refuses(t *testing.T) {
	var deletedIDs []float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets":
			// Same (project_id=7, environment_id=1) scope, two secrets named the same.
			_, _ = w.Write([]byte(`{"data":{"secrets":[` +
				`{"id":20,"name":"db-password","project_id":7,"environment_id":1,"is_secret":true},` +
				`{"id":21,"name":"db-password","project_id":7,"environment_id":1,"is_secret":true}` +
				`],"total":2}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/7/secrets/bulk-delete":
			b, _ := io.ReadAll(r.Body)
			var body struct {
				SecretIDs []float64 `json:"secret_ids"`
			}
			_ = json.Unmarshal(b, &body)
			deletedIDs = body.SecretIDs
			_, _ = w.Write([]byte(`{"data":{"deleted":[],"failed":[],"total":0}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origEnv, origIDs, origNames, origConfirm := bulkDeleteProject, bulkDeleteEnv, bulkDeleteIDs, bulkDeleteNames, bulkDeleteConfirm
	t.Cleanup(func() {
		bulkDeleteProject, bulkDeleteEnv, bulkDeleteIDs, bulkDeleteNames, bulkDeleteConfirm = origProject, origEnv, origIDs, origNames, origConfirm
	})
	bulkDeleteProject = 7
	bulkDeleteEnv = 1
	bulkDeleteIDs = nil
	bulkDeleteNames = []string{"db-password"}
	bulkDeleteConfirm = true

	err := runBulkDelete(nil, nil)
	require.Error(t, err, "two secrets sharing a name within the SAME scoped project+environment must be refused, not silently reduced to one")
	assert.Empty(t, deletedIDs)
}

// ── bulk-rotate ──────────────────────────────────────────────────────────────

func crossEnvRotateStub(t *testing.T, triggeredIDs *[]float64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets" && r.URL.Query().Get("environment_id") == "1":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":30,"Name":"db-password"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":30,"Name":"db-password"},{"ID":31,"Name":"db-password"}]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/7/secrets/bulk-rotate":
			b, _ := io.ReadAll(r.Body)
			var body struct {
				SecretIDs []float64 `json:"secret_ids"`
			}
			_ = json.Unmarshal(b, &body)
			if triggeredIDs != nil {
				*triggeredIDs = body.SecretIDs
			}
			_, _ = w.Write([]byte(`{"data":{"triggered":` + string(b) + `,"failed":[],"total":1}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestBulkRotate_NameAmbiguousAcrossEnvironments_WithoutEnvFlag_Refuses mirrors
// the bulk-delete case above for bulk-rotate.
func TestBulkRotate_NameAmbiguousAcrossEnvironments_WithoutEnvFlag_Refuses(t *testing.T) {
	var triggeredIDs []float64
	srv := crossEnvRotateStub(t, &triggeredIDs)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origEnv, origNames, origConfirm := bulkRotateProject, bulkRotateEnv, bulkRotateNames, bulkRotateConfirm
	t.Cleanup(func() {
		bulkRotateProject, bulkRotateEnv, bulkRotateNames, bulkRotateConfirm = origProject, origEnv, origNames, origConfirm
	})
	bulkRotateProject = 7
	bulkRotateEnv = 0 // deliberately omitted
	bulkRotateNames = "db-password"
	bulkRotateConfirm = true

	err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
	require.Error(t, err, "bulk-rotate --names without --env must be refused when the project holds the same name in more than one environment")
	assert.Empty(t, triggeredIDs, "no rotate request may reach the server before the ambiguity is caught")
}

// TestBulkRotate_NameAmbiguousWithinScopedEnvironment_Refuses is the
// defense-in-depth case for bulk-rotate.
func TestBulkRotate_NameAmbiguousWithinScopedEnvironment_Refuses(t *testing.T) {
	var triggeredIDs []float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":40,"Name":"db-password"},{"ID":41,"Name":"db-password"}]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/7/secrets/bulk-rotate":
			b, _ := io.ReadAll(r.Body)
			var body struct {
				SecretIDs []float64 `json:"secret_ids"`
			}
			_ = json.Unmarshal(b, &body)
			triggeredIDs = body.SecretIDs
			_, _ = w.Write([]byte(`{"data":{"triggered":[],"failed":[],"total":0}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origEnv, origNames, origConfirm := bulkRotateProject, bulkRotateEnv, bulkRotateNames, bulkRotateConfirm
	t.Cleanup(func() {
		bulkRotateProject, bulkRotateEnv, bulkRotateNames, bulkRotateConfirm = origProject, origEnv, origNames, origConfirm
	})
	bulkRotateProject = 7
	bulkRotateEnv = 1
	bulkRotateNames = "db-password"
	bulkRotateConfirm = true

	err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
	require.Error(t, err, "two secrets sharing a name within the SAME scoped project+environment must be refused, not silently reduced to one")
	assert.Empty(t, triggeredIDs)
}
