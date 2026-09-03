// folder_test.go — CLI tests for `keyorix secret folder create` / `folder list`
// (runFolderCreate, printFolder, runFolderList, printFolderList): remote mode via
// httptest, embedded mode via a real InitializeCoreService-backed SQLite DB.
package secret

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdoutForFolder redirects os.Stdout to a pipe for the duration of fn and
// returns everything written to it.
func captureStdoutForFolder(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	os.Stdout = orig
	return buf.String()
}

func resetFolderCreateFlags(t *testing.T) {
	t.Helper()
	origName, origProject, origEnv, origParent := folderCreateName, folderCreateProject, folderCreateEnvID, folderCreateParent
	t.Cleanup(func() {
		folderCreateName = origName
		folderCreateProject = origProject
		folderCreateEnvID = origEnv
		folderCreateParent = origParent
	})
}

func resetFolderListFlags(t *testing.T) {
	t.Helper()
	origProject, origParent := folderListProject, folderListParent
	t.Cleanup(func() {
		folderListProject = origProject
		folderListParent = origParent
	})
}

// ── printFolder / printFolderList (direct) ──────────────────────────────────

func TestPrintFolder_NoParent(t *testing.T) {
	f := &models.SecretNode{ID: 5, Name: "configs", ProjectID: 1, EnvironmentID: 2}
	out := captureStdoutForFolder(t, func() { printFolder(f) })
	assert.Contains(t, out, "Folder created successfully!")
	assert.Contains(t, out, "configs")
	assert.NotContains(t, out, "Parent ID:")
}

func TestPrintFolder_WithParent(t *testing.T) {
	parent := uint(9)
	f := &models.SecretNode{ID: 6, Name: "nested/special chars äöü", ProjectID: 1, EnvironmentID: 2, ParentID: &parent}
	out := captureStdoutForFolder(t, func() { printFolder(f) })
	assert.Contains(t, out, "Parent ID:   9")
	assert.Contains(t, out, "nested/special chars äöü")
}

func TestPrintFolderList_Empty(t *testing.T) {
	out := captureStdoutForFolder(t, func() { printFolderList(nil) })
	assert.Contains(t, out, "No folders found.")
}

func TestPrintFolderList_Many(t *testing.T) {
	parent := uint(1)
	folders := []*models.SecretNode{
		{ID: 1, Name: "root-folder", ProjectID: 1, EnvironmentID: 1},
		{ID: 2, Name: "nested", ProjectID: 1, EnvironmentID: 1, ParentID: &parent},
	}
	out := captureStdoutForFolder(t, func() { printFolderList(folders) })
	assert.Contains(t, out, "root-folder")
	assert.Contains(t, out, "nested")
	assert.Contains(t, out, "-")
}

// ── runFolderCreate: validation ──────────────────────────────────────────────

func TestRunFolderCreate_MissingName(t *testing.T) {
	resetFolderCreateFlags(t)
	folderCreateName = ""
	err := runFolderCreate(folderCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--name")
}

// ── runFolderCreate: remote mode ─────────────────────────────────────────────

func folderRemoteStub(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func TestRunFolderCreate_Remote_Success(t *testing.T) {
	resetFolderCreateFlags(t)
	done := folderRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/folders", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":10,"name":"configs","project_id":1,"environment_id":1}}`))
	})
	defer done()

	folderCreateName = "configs"
	folderCreateProject = 1
	folderCreateEnvID = 1
	folderCreateParent = 0

	out := captureStdoutForFolder(t, func() {
		err := runFolderCreate(folderCreateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "configs")
}

func TestRunFolderCreate_Remote_WithParent_SendsParentID(t *testing.T) {
	resetFolderCreateFlags(t)
	var capturedBody map[string]interface{}
	done := folderRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":11,"name":"nested","project_id":1,"environment_id":1,"parent_id":9}}`))
	})
	defer done()

	folderCreateName = "nested"
	folderCreateProject = 1
	folderCreateEnvID = 1
	folderCreateParent = 9

	err := runFolderCreate(folderCreateCmd, nil)
	require.NoError(t, err)
	assert.Equal(t, float64(9), capturedBody["parent_id"])
}

func TestRunFolderCreate_Remote_APIError(t *testing.T) {
	resetFolderCreateFlags(t)
	done := folderRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()

	folderCreateName = "configs"
	folderCreateProject = 1
	folderCreateEnvID = 1

	err := runFolderCreate(folderCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create folder")
}

// ── runFolderList: remote mode ───────────────────────────────────────────────

func TestRunFolderList_Remote_Empty(t *testing.T) {
	resetFolderListFlags(t)
	done := folderRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	defer done()

	folderListProject = 0
	folderListParent = 0

	out := captureStdoutForFolder(t, func() {
		err := runFolderList(folderListCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No folders found.")
}

func TestRunFolderList_Remote_WithFilters(t *testing.T) {
	resetFolderListFlags(t)
	var gotQuery string
	done := folderRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":1,"name":"a","project_id":3,"environment_id":1},{"id":2,"name":"b","project_id":3,"environment_id":1}]}`))
	})
	defer done()

	folderListProject = 3
	folderListParent = 5

	out := captureStdoutForFolder(t, func() {
		err := runFolderList(folderListCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, gotQuery, "project_id=3")
	assert.Contains(t, gotQuery, "parent_id=5")
	assert.Contains(t, out, "a")
	assert.Contains(t, out, "b")
}

func TestRunFolderList_Remote_APIError(t *testing.T) {
	resetFolderListFlags(t)
	done := folderRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()

	err := runFolderList(folderListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list folders")
}

// ── embedded mode ─────────────────────────────────────────────────────────────

// folderEmbeddedEnv points InitializeCoreService at a fresh temp SQLite DB and
// clears any remote-mode env vars so common.NewRemoteClient() returns !ok.
func folderEmbeddedEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	dbPath := filepath.Join(dir, "folder_embedded.db")
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: local
  database:
    path: "`+dbPath+`"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Chdir(dir)
}

func TestRunFolderCreate_Embedded_Success(t *testing.T) {
	folderEmbeddedEnv(t)
	resetFolderCreateFlags(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	proj, err := svc.CreateProject(context.Background(), "embed-proj", "")
	require.NoError(t, err)
	env, err := svc.CreateEnvironment(context.Background(), proj.ID, "prod")
	require.NoError(t, err)

	folderCreateName = "embedded-folder"
	folderCreateProject = proj.ID
	folderCreateEnvID = env.ID
	folderCreateParent = 0

	out := captureStdoutForFolder(t, func() {
		err := runFolderCreate(folderCreateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "embedded-folder")
}

func TestRunFolderCreate_Embedded_WithParent(t *testing.T) {
	folderEmbeddedEnv(t)
	resetFolderCreateFlags(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	proj, err := svc.CreateProject(context.Background(), "embed-proj2", "")
	require.NoError(t, err)
	env, err := svc.CreateEnvironment(context.Background(), proj.ID, "prod")
	require.NoError(t, err)
	parent, err := svc.CreateFolder(context.Background(), 0, "parent-folder", proj.ID, env.ID, nil)
	require.NoError(t, err)

	folderCreateName = "child-folder"
	folderCreateProject = proj.ID
	folderCreateEnvID = env.ID
	folderCreateParent = parent.ID

	out := captureStdoutForFolder(t, func() {
		err := runFolderCreate(folderCreateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "child-folder")
	assert.Contains(t, out, "Parent ID:")
}

// TestRunFolderCreate_Embedded_DuplicateName exercises the CreateFolder conflict
// path: folders share secret_nodes' (project, environment, name) unique index, so
// creating the same name twice in the same project/environment must fail on the
// second attempt rather than silently succeeding.
func TestRunFolderCreate_Embedded_DuplicateName(t *testing.T) {
	folderEmbeddedEnv(t)
	resetFolderCreateFlags(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	proj, err := svc.CreateProject(context.Background(), "embed-proj3", "")
	require.NoError(t, err)
	env, err := svc.CreateEnvironment(context.Background(), proj.ID, "prod")
	require.NoError(t, err)

	folderCreateName = "dup-folder"
	folderCreateProject = proj.ID
	folderCreateEnvID = env.ID

	err = runFolderCreate(folderCreateCmd, nil)
	require.NoError(t, err, "first create should succeed")

	err = runFolderCreate(folderCreateCmd, nil)
	require.Error(t, err, "creating a folder with an already-existing name in the same project/environment must fail")
}

func TestRunFolderCreate_Embedded_InitError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	resetFolderCreateFlags(t)

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: local
  database:
    path: "`+dir+`/folder_init_err.db"
  encryption:
    enabled: true
    dek_path: "dek.json"
    salt_path: "salt.bin"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Chdir(dir)

	folderCreateName = "whatever"
	folderCreateProject = 1
	folderCreateEnvID = 1

	err := runFolderCreate(folderCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunFolderList_Embedded_EmptyAndPopulated(t *testing.T) {
	folderEmbeddedEnv(t)
	resetFolderListFlags(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	proj, err := svc.CreateProject(context.Background(), "embed-list-proj", "")
	require.NoError(t, err)
	env, err := svc.CreateEnvironment(context.Background(), proj.ID, "prod")
	require.NoError(t, err)

	folderListProject = proj.ID
	folderListParent = 0

	out := captureStdoutForFolder(t, func() {
		err := runFolderList(folderListCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No folders found.")

	_, err = svc.CreateFolder(context.Background(), 0, "embed-listed-folder", proj.ID, env.ID, nil)
	require.NoError(t, err)

	out = captureStdoutForFolder(t, func() {
		err := runFolderList(folderListCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "embed-listed-folder")
}

func TestRunFolderList_Embedded_InitError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	resetFolderListFlags(t)

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: local
  database:
    path: "`+dir+`/folder_list_init_err.db"
  encryption:
    enabled: true
    dek_path: "dek.json"
    salt_path: "salt.bin"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Chdir(dir)

	err := runFolderList(folderListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// ── runFolderDelete: embedded mode ───────────────────────────────────────────

func TestRunFolderDelete_Embedded_Force(t *testing.T) {
	folderEmbeddedEnv(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	proj, err := svc.CreateProject(context.Background(), "embed-del-proj", "")
	require.NoError(t, err)
	env, err := svc.CreateEnvironment(context.Background(), proj.ID, "prod")
	require.NoError(t, err)
	folder, err := svc.CreateFolder(context.Background(), 0, "to-delete", proj.ID, env.ID, nil)
	require.NoError(t, err)

	origID, origForce := folderDeleteID, folderDeleteForce
	t.Cleanup(func() { folderDeleteID = origID; folderDeleteForce = origForce })
	folderDeleteID = folder.ID
	folderDeleteForce = true

	out := captureStdoutForFolder(t, func() {
		err := runFolderDelete(folderDeleteCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "deleted")
}

func TestRunFolderDelete_MissingID(t *testing.T) {
	origID := folderDeleteID
	t.Cleanup(func() { folderDeleteID = origID })
	folderDeleteID = 0

	err := runFolderDelete(folderDeleteCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestRunFolderDelete_Remote_APIError(t *testing.T) {
	done := folderRemoteStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()

	origID, origForce := folderDeleteID, folderDeleteForce
	t.Cleanup(func() { folderDeleteID = origID; folderDeleteForce = origForce })
	folderDeleteID = 123
	folderDeleteForce = true

	err := runFolderDelete(folderDeleteCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete folder")
}

func TestRunFolderDelete_Embedded_InitError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: local
  database:
    path: "`+dir+`/folder_delete_init_err.db"
  encryption:
    enabled: true
    dek_path: "dek.json"
    salt_path: "salt.bin"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Chdir(dir)

	origID, origForce := folderDeleteID, folderDeleteForce
	t.Cleanup(func() { folderDeleteID = origID; folderDeleteForce = origForce })
	folderDeleteID = 1
	folderDeleteForce = true

	err := runFolderDelete(folderDeleteCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunFolderList_Embedded_WithParentFilter(t *testing.T) {
	folderEmbeddedEnv(t)
	resetFolderListFlags(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	proj, err := svc.CreateProject(context.Background(), "embed-parent-filter-proj", "")
	require.NoError(t, err)
	env, err := svc.CreateEnvironment(context.Background(), proj.ID, "prod")
	require.NoError(t, err)
	parent, err := svc.CreateFolder(context.Background(), 0, "parent", proj.ID, env.ID, nil)
	require.NoError(t, err)
	_, err = svc.CreateFolder(context.Background(), 0, "child", proj.ID, env.ID, &parent.ID)
	require.NoError(t, err)

	folderListProject = proj.ID
	folderListParent = parent.ID

	out := captureStdoutForFolder(t, func() {
		err := runFolderList(folderListCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "child")
}

func TestRunFolderDelete_Embedded_NotFound(t *testing.T) {
	folderEmbeddedEnv(t)

	_, err := common.InitializeCoreService()
	require.NoError(t, err)

	origID, origForce := folderDeleteID, folderDeleteForce
	t.Cleanup(func() { folderDeleteID = origID; folderDeleteForce = origForce })
	folderDeleteID = 999999
	folderDeleteForce = true

	err = runFolderDelete(folderDeleteCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete folder")
}
