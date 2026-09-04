// bulk_rotate_rune_test.go — covers splitNames, resolveSecretNamesToIDs, and the
// bulkRotateCmd.RunE closure itself (bulk_rotate_test.go only exercises
// postBulkRotate and the early --confirm guard).
package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitNames(t *testing.T) {
	assert.Equal(t, []string{"a", "b", "c"}, splitNames("a,b,c"))
	assert.Equal(t, []string{"a", "b"}, splitNames(" a , b "))
	assert.Equal(t, []string{"solo"}, splitNames("solo"))
	assert.Empty(t, splitNames(""))
	assert.Equal(t, []string{"a", "b"}, splitNames("a,,b"))
}

func bulkRotateNamesStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":10,"Name":"alpha"},{"ID":11,"Name":"beta"}]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/7/secrets/bulk-rotate":
			_, _ = w.Write([]byte(`{"data":{"triggered":[10,11],"total":2}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

func TestResolveSecretNamesToIDs_Found(t *testing.T) {
	rc, done := bulkRotateNamesStub(t)
	defer done()

	ids, err := resolveSecretNamesToIDs(context.Background(), rc, 7, 0, []string{"alpha", "beta"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{10, 11}, ids)
}

func TestResolveSecretNamesToIDs_NotFound_Skipped(t *testing.T) {
	rc, done := bulkRotateNamesStub(t)
	defer done()

	out := captureStdoutForFolder(t, func() {
		ids, err := resolveSecretNamesToIDs(context.Background(), rc, 7, 0, []string{"alpha", "ghost"})
		require.NoError(t, err)
		assert.Equal(t, []uint{10}, ids)
	})
	assert.Contains(t, out, "ghost")
	assert.Contains(t, out, "not found")
}

func TestResolveSecretNamesToIDs_WithEnvFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := resolveSecretNamesToIDs(context.Background(), rc, 7, 3, []string{"x"})
	require.NoError(t, err)
	assert.Contains(t, gotQuery, "environment_id=3")
}

func TestResolveSecretNamesToIDs_GetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := resolveSecretNamesToIDs(context.Background(), rc, 7, 0, []string{"x"})
	require.Error(t, err)
}

// ── bulkRotateCmd.RunE ────────────────────────────────────────────────────────

func resetBulkRotateFlags(t *testing.T) {
	t.Helper()
	origProject, origEnv, origClass, origNames, origConfirm :=
		bulkRotateProject, bulkRotateEnv, bulkRotateClassification, bulkRotateNames, bulkRotateConfirm
	t.Cleanup(func() {
		bulkRotateProject = origProject
		bulkRotateEnv = origEnv
		bulkRotateClassification = origClass
		bulkRotateNames = origNames
		bulkRotateConfirm = origConfirm
	})
}

func TestBulkRotateCmd_MissingProject(t *testing.T) {
	resetBulkRotateFlags(t)
	bulkRotateProject = 0
	bulkRotateConfirm = true
	err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project")
}

func TestBulkRotateCmd_NoServer(t *testing.T) {
	resetBulkRotateFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	bulkRotateProject = 7
	bulkRotateConfirm = true
	err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestBulkRotateCmd_Success_NoNames(t *testing.T) {
	resetBulkRotateFlags(t)
	_, done := bulkRotateStub(t, http.StatusOK, `{"data":{"triggered":[1,2],"total":2}}`, nil)
	defer done()

	bulkRotateProject = 7
	bulkRotateConfirm = true
	bulkRotateNames = ""

	out := captureStdoutForFolder(t, func() {
		err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "2 scheduled")
}

func TestBulkRotateCmd_Success_WithNames(t *testing.T) {
	resetBulkRotateFlags(t)
	_, done := bulkRotateNamesStub(t)
	defer done()

	bulkRotateProject = 7
	bulkRotateConfirm = true
	bulkRotateNames = "alpha,beta"

	out := captureStdoutForFolder(t, func() {
		err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "2 scheduled")
}

func TestBulkRotateCmd_ResolveNamesError(t *testing.T) {
	resetBulkRotateFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	bulkRotateProject = 7
	bulkRotateConfirm = true
	bulkRotateNames = "alpha"

	err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve secret names")
}

func TestBulkRotateCmd_PartialFailure_PrintsFailed(t *testing.T) {
	resetBulkRotateFlags(t)
	_, done := bulkRotateStub(t, http.StatusOK, `{"data":{"triggered":[1],"failed":[{"secret_id":2,"name":"broken","error":"no rotation config"},{"secret_id":3,"error":"denied"}],"total":3}}`, nil)
	defer done()

	bulkRotateProject = 7
	bulkRotateConfirm = true
	bulkRotateNames = ""

	out := captureStdoutForFolder(t, func() {
		err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "broken")
	assert.Contains(t, out, "no rotation config")
	assert.Contains(t, out, "id:3")
	assert.Contains(t, out, "denied")
}

func TestBulkRotateCmd_PostError(t *testing.T) {
	resetBulkRotateFlags(t)
	_, done := bulkRotateStub(t, http.StatusInternalServerError, `boom`, nil)
	defer done()

	bulkRotateProject = 7
	bulkRotateConfirm = true
	bulkRotateNames = ""

	err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
	require.Error(t, err)
}
