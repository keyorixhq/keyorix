package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunGet_NoSelector(t *testing.T) {
	origID, origName, origRef := getID, getName, getRef
	defer func() { getID = origID; getName = origName; getRef = origRef }()
	getID = 0
	getName = ""
	getRef = ""

	err := runGet(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one of --id, --name, or --ref is required")
}

func TestRunGet_MultipleSelectors(t *testing.T) {
	origID, origName, origRef := getID, getName, getRef
	defer func() { getID = origID; getName = origName; getRef = origRef }()
	getID = 1
	getName = "db-pass"
	getRef = ""

	err := runGet(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestRunGet_ByIDRemote(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"id":5,"name":"db-pass","type":"password","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origID, origName, origRef, origShow := getID, getName, getRef, getShowValue
	defer func() { getID = origID; getName = origName; getRef = origRef; getShowValue = origShow }()
	getID = 5
	getName = ""
	getRef = ""
	getShowValue = false

	require.NoError(t, runGet(nil, nil))
	assert.Equal(t, "/api/v1/secrets/5", gotPath)
}

func TestRunGet_ByRefRemote(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		// Return a minimal secret + value so displaySecret does not nil-deref.
		_, _ = w.Write([]byte(`{"data":{"secret":{"id":1,"name":"db-pass","type":"password","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},"value":"supersecret"}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origID, origName, origRef, origShow := getID, getName, getRef, getShowValue
	defer func() { getID = origID; getName = origName; getRef = origRef; getShowValue = origShow }()
	getID = 0
	getName = ""
	getRef = "myproject/prod/db-pass"
	getShowValue = false

	require.NoError(t, runGet(nil, nil))
	// The ref is passed as a query param to /api/v1/secrets/value
	assert.Equal(t, "/api/v1/secrets/value", gotPath)
}

func TestRunDelete_NoIDOrName(t *testing.T) {
	origID, origName := deleteID, deleteName
	defer func() { deleteID = origID; deleteName = origName }()
	deleteID = 0
	deleteName = ""

	err := runDelete(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "either --id or --name is required")
}

func TestRunList_RemoteMode(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"secrets":[],"total":0,"page":1,"page_size":50}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origEnv, origLimit, origOffset, origFormat :=
		listProjectName, listEnv, listLimit, listOffset, listFormat
	defer func() {
		listProjectName = origProject
		listEnv = origEnv
		listLimit = origLimit
		listOffset = origOffset
		listFormat = origFormat
	}()
	listProjectName = ""
	listEnv = 0
	listLimit = 50
	listOffset = 0
	listFormat = "table" // must be set; TestRunListRemote_ResolvesProjectScope leaves it ""

	require.NoError(t, runList(nil, nil))
	assert.Equal(t, "/api/v1/secrets", gotPath)
}

func TestBuildCreateRequest_NameRequired(t *testing.T) {
	// Test buildCreateRequest validation directly — avoids cobra cmd nil issue.
	origName, origValue, origInteractive := createName, createValue, createInteractive
	defer func() { createName = origName; createValue = origValue; createInteractive = origInteractive }()
	createName = ""
	createValue = ""
	createInteractive = false

	_, err := buildCreateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret name is required")
}

func TestBuildCreateRequest_ValueRequired(t *testing.T) {
	origName, origValue, origFile := createName, createValue, createFromFile
	defer func() { createName = origName; createValue = origValue; createFromFile = origFile }()
	createName = "my-secret"
	createValue = ""
	createFromFile = ""

	_, err := buildCreateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret value is required")
}
