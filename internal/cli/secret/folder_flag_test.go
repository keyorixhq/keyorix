// folder_flag_test.go — CLI tests for --folder flag on create and list.
//
// Covers:
//   - buildCreateRequest with --folder sets ParentID
//   - buildCreateRequest with --folder=0 leaves ParentID nil
//   - runListRemote sends ?parent_id=N when --folder is set
//   - runListRemote does NOT send parent_id when --folder=0
package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── buildCreateRequest: --folder sets ParentID ────────────────────────────────

func TestBuildCreateRequest_FolderFlag(t *testing.T) {
	origName := createName
	origValue := createValue
	origFolder := createFolderID
	origEnv := createEnvironmentID
	origProject := createProjectID
	t.Cleanup(func() {
		createName = origName
		createValue = origValue
		createFolderID = origFolder
		createEnvironmentID = origEnv
		createProjectID = origProject
	})

	createName = "my-secret"
	createValue = "secret-value"
	createFolderID = 42
	createEnvironmentID = 10
	createProjectID = 1

	req, err := buildCreateRequest()
	require.NoError(t, err)
	require.NotNil(t, req.ParentID, "expected ParentID to be set when --folder is given")
	assert.Equal(t, uint(42), *req.ParentID)
}

func TestBuildCreateRequest_FolderFlag_Zero(t *testing.T) {
	origName := createName
	origValue := createValue
	origFolder := createFolderID
	t.Cleanup(func() {
		createName = origName
		createValue = origValue
		createFolderID = origFolder
	})

	createName = "my-secret"
	createValue = "secret-value"
	createFolderID = 0 // zero means root level — no parent

	req, err := buildCreateRequest()
	require.NoError(t, err)
	assert.Nil(t, req.ParentID, "ParentID should be nil when --folder=0")
}

// ── runListRemote: --folder sends ?parent_id= query param ────────────────────

// TestRunListRemote_FolderFlag_AddsParentID verifies that ?parent_id=N is
// appended to the secrets request when --folder N is provided.
func TestRunListRemote_FolderFlag_AddsParentID(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[],"total":0,"page":1,"page_size":50,"total_pages":1}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origFolder := listFolderID
	origLimit := listLimit
	origOffset := listOffset
	origFormat := listFormat
	origProject := listProjectName
	origEnv := listEnv
	t.Cleanup(func() {
		listFolderID = origFolder
		listLimit = origLimit
		listOffset = origOffset
		listFormat = origFormat
		listProjectName = origProject
		listEnv = origEnv
	})

	listFolderID = 7
	listLimit = 50
	listOffset = 0
	listFormat = "table"
	listProjectName = ""
	listEnv = 0

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(context.Background(), rc))
	assert.True(t, strings.Contains(gotQuery, "parent_id=7"),
		"expected parent_id=7 in query string, got: %s", gotQuery)
}

// TestRunListRemote_FolderFlag_Zero_NoParentID verifies that parent_id is NOT
// added to the query when --folder=0 (the default).
func TestRunListRemote_FolderFlag_Zero_NoParentID(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[],"total":0,"page":1,"page_size":50,"total_pages":1}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origFolder := listFolderID
	origLimit := listLimit
	origOffset := listOffset
	origFormat := listFormat
	origProject := listProjectName
	origEnv := listEnv
	t.Cleanup(func() {
		listFolderID = origFolder
		listLimit = origLimit
		listOffset = origOffset
		listFormat = origFormat
		listProjectName = origProject
		listEnv = origEnv
	})

	listFolderID = 0 // no folder filter
	listLimit = 50
	listOffset = 0
	listFormat = "table"
	listProjectName = ""
	listEnv = 0

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(context.Background(), rc))
	assert.False(t, strings.Contains(gotQuery, "parent_id"),
		"expected no parent_id in query when --folder=0, got: %s", gotQuery)
}
