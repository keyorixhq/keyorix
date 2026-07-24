package rbac

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// matrixPayload is the JSON body the fake server returns.
const matrixPayload = `{"data":{
	"rows":[
		{
			"user_id":1,"username":"alice","email":"alice@example.com",
			"role_id":10,"role_name":"admin",
			"permission_name":"secrets.read","resource":"secrets","action":"read",
			"scope":"global","project_id":0,"project_name":"","environment_id":0,"environment_name":"",
			"expires_at":null
		},
		{
			"user_id":2,"username":"bob","email":"bob@example.com",
			"role_id":20,"role_name":"viewer",
			"permission_name":"secrets.read","resource":"secrets","action":"read",
			"scope":"project","project_id":5,"project_name":"project-a","environment_id":0,"environment_name":"",
			"expires_at":null
		}
	],
	"total":2
}}`

func fakeMatrixServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/rbac/permission-matrix", func(w http.ResponseWriter, r *http.Request) {
		// Echo the project_id query param in a simple way; format=csv returns CSV.
		if r.URL.Query().Get("format") == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte(
				"username,email,role,permission,resource,action,scope,project,environment,expires_at\n" +
					"alice,alice@example.com,admin,secrets.read,secrets,read,global,,,never\n",
			))
			return
		}
		_, _ = w.Write([]byte(matrixPayload))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"project-a"}]}}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestExportMatrix_RemoteJSON — happy-path: JSON output from remote.
func TestExportMatrix_RemoteJSON(t *testing.T) {
	srv := fakeMatrixServer(t)
	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	// reset flags
	exportMatrixFormat = "json"
	exportMatrixProject = ""

	var buf bytes.Buffer
	err := runExportMatrixRemote(ctx, rc, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "bob")
	assert.Contains(t, out, "secrets.read")
}

// TestExportMatrix_RemoteCSV — happy-path: CSV output delegated to server.
func TestExportMatrix_RemoteCSV(t *testing.T) {
	srv := fakeMatrixServer(t)
	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	exportMatrixFormat = "csv"
	exportMatrixProject = ""

	var buf bytes.Buffer
	err := runExportMatrixRemote(ctx, rc, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "username,"), "expected CSV header")
	assert.Contains(t, out, "alice")
}

// TestExportMatrix_RemoteProjectFilter — project filter is passed to the server URL.
func TestExportMatrix_RemoteProjectFilter(t *testing.T) {
	var capturedPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/rbac/permission-matrix", func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":{"rows":[],"total":0}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"project-a"}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	exportMatrixFormat = "json"
	exportMatrixProject = "project-a"

	var buf bytes.Buffer
	err := runExportMatrixRemote(ctx, rc, &buf)
	require.NoError(t, err)

	// Verify the project_id=5 was forwarded to the server.
	assert.Contains(t, capturedPath, "project_id=5", "server should receive project_id filter")
}

// TestExportMatrix_RemoteTable — table format (default) renders without error.
func TestExportMatrix_RemoteTable(t *testing.T) {
	srv := fakeMatrixServer(t)
	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	exportMatrixFormat = "table"
	exportMatrixProject = ""

	var buf bytes.Buffer
	err := runExportMatrixRemote(ctx, rc, &buf)
	require.NoError(t, err)

	out := buf.String()
	// Header row and at least one data row expected.
	assert.Contains(t, out, "USERNAME")
	assert.Contains(t, out, "alice")
}

// TestWriteMatrixRemote_EmptyRows — empty result prints "No permission grants found."
func TestWriteMatrixRemote_EmptyRows(t *testing.T) {
	var buf bytes.Buffer
	err := writeMatrixRemote(&buf, []remoteMatrixRow{}, "table")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No permission grants found.")
}

// TestWriteMatrixRemote_ExpiresAt — a time-bound row formats the expiry correctly.
func TestWriteMatrixRemote_ExpiresAt(t *testing.T) {
	exp := time.Date(2027, 1, 15, 12, 0, 0, 0, time.UTC)
	rows := []remoteMatrixRow{{
		Username: "eve", Email: "eve@example.com", RoleName: "jit",
		PermissionName: "secrets.read", Resource: "secrets", Action: "read",
		Scope: "global", ExpiresAt: &exp,
	}}
	var buf bytes.Buffer
	err := writeMatrixRemote(&buf, rows, "csv")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "2027-01-15T12:00:00Z")
}

// ── writeMatrixEmbedded coverage ──────────────────────────────────────────────

// TestWriteMatrixEmbedded_JSON — JSON output path for embedded mode.
func TestWriteMatrixEmbedded_JSON(t *testing.T) {
	exp := time.Date(2028, 3, 10, 8, 0, 0, 0, time.UTC)
	rows := []*core.PermissionMatrixRow{
		{
			UserID: 1, Username: "alice", Email: "alice@example.com",
			RoleID: 10, RoleName: "admin",
			PermissionName: "secrets.read", Resource: "secrets", Action: "read",
			Scope: "global", ExpiresAt: &exp,
		},
	}
	var buf bytes.Buffer
	err := writeMatrixEmbedded(&buf, rows, "json")
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "secrets.read")
	assert.Contains(t, out, "2028-03-10T08:00:00Z")
}

// TestWriteMatrixEmbedded_CSV — CSV output path for embedded mode.
func TestWriteMatrixEmbedded_CSV(t *testing.T) {
	exp := time.Date(2028, 6, 15, 0, 0, 0, 0, time.UTC)
	rows := []*core.PermissionMatrixRow{
		{
			Username: "bob", Email: "bob@example.com",
			RoleName: "viewer", PermissionName: "secrets.read",
			Resource: "secrets", Action: "read",
			Scope: "project", ProjectName: "proj-alpha", ExpiresAt: &exp,
		},
		{
			Username: "carol", Email: "carol@example.com",
			RoleName: "admin", PermissionName: "secrets.write",
			Resource: "secrets", Action: "write",
			Scope: "global", ExpiresAt: nil,
		},
	}
	var buf bytes.Buffer
	err := writeMatrixEmbedded(&buf, rows, "csv")
	require.NoError(t, err)
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "username,"), "expected CSV header line")
	assert.Contains(t, out, "bob")
	assert.Contains(t, out, "carol")
	assert.Contains(t, out, "2028-06-15T00:00:00Z")
	assert.Contains(t, out, "never") // nil ExpiresAt → "never"
}

// TestWriteMatrixEmbedded_TableEmpty — empty rows print "No permission grants found."
func TestWriteMatrixEmbedded_TableEmpty(t *testing.T) {
	var buf bytes.Buffer
	err := writeMatrixEmbedded(&buf, []*core.PermissionMatrixRow{}, "table")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No permission grants found.")
}

// TestWriteMatrixEmbedded_TableNonEmpty — non-empty rows render a tabwriter header + data.
func TestWriteMatrixEmbedded_TableNonEmpty(t *testing.T) {
	rows := []*core.PermissionMatrixRow{
		{
			Username: "dave", Email: "dave@example.com",
			RoleName: "poweruser", PermissionName: "secrets.read",
			Scope: "global", ExpiresAt: nil,
		},
	}
	var buf bytes.Buffer
	err := writeMatrixEmbedded(&buf, rows, "table")
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "USERNAME")
	assert.Contains(t, out, "dave")
	assert.Contains(t, out, "never")
}

// TestWriteMatrixEmbedded_TableWithExpiry — a time-bound row formats the expiry in table mode.
func TestWriteMatrixEmbedded_TableWithExpiry(t *testing.T) {
	exp := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
	rows := []*core.PermissionMatrixRow{
		{
			Username: "eve", Email: "eve@example.com",
			RoleName: "jit", PermissionName: "secrets.read",
			Scope: "project", ProjectName: "proj-x", ExpiresAt: &exp,
		},
	}
	var buf bytes.Buffer
	err := writeMatrixEmbedded(&buf, rows, "table")
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "2029-01-01T00:00:00Z")
}

// TestExportMatrix_RemoteCSV_WithProject — CSV + project filter combination: the CSV
// path with a project resolves the project ID first, then requests CSV directly.
func TestExportMatrix_RemoteCSV_WithProject(t *testing.T) {
	var capturedQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/rbac/permission-matrix", func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(
			"username,email,role,permission,resource,action,scope,project,environment,expires_at\n" +
				"alice,alice@example.com,admin,secrets.read,secrets,read,project,proj-a,,never\n",
		))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":3,"name":"proj-a"}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	exportMatrixFormat = "csv"
	exportMatrixProject = "proj-a"
	defer func() { exportMatrixProject = "" }()

	var buf bytes.Buffer
	err := runExportMatrixRemote(ctx, rc, &buf)
	require.NoError(t, err)

	// Verify both project_id and format=csv were forwarded.
	assert.Contains(t, capturedQuery, "project_id=3", "project_id must be in the query")
	assert.Contains(t, capturedQuery, "format=csv", "format=csv must be in the query")
	assert.Contains(t, buf.String(), "alice")
}

// TestExportMatrix_RemoteProjectNotFound — resolveProjectIDByName returns an error
// when the project name does not exist.
func TestExportMatrix_RemoteProjectNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	exportMatrixFormat = "json"
	exportMatrixProject = "does-not-exist"
	defer func() { exportMatrixProject = "" }()

	var buf bytes.Buffer
	err := runExportMatrixRemote(ctx, rc, &buf)
	require.Error(t, err, "missing project must cause an error")
	assert.Contains(t, err.Error(), "does-not-exist")
}

// TestExportMatrix_OutputFile — writing to a file path populates the file.
func TestExportMatrix_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outPath := dir + "/matrix.json"

	// Set up a fake matrix server.
	srv := fakeMatrixServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	// Save and restore package-level flags.
	prevFormat := exportMatrixFormat
	prevProject := exportMatrixProject
	prevOutput := exportMatrixOutput
	t.Cleanup(func() {
		exportMatrixFormat = prevFormat
		exportMatrixProject = prevProject
		exportMatrixOutput = prevOutput
	})

	exportMatrixFormat = "json"
	exportMatrixProject = ""
	exportMatrixOutput = outPath

	// Run via the cobra RunE function.
	err := runExportMatrix(exportMatrixCmd, nil)
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "alice")
}

// TestWriteMatrixRemote_CSVFormat — explicit CSV via writeMatrixRemote validates
// header + data row with nil ExpiresAt → "never".
func TestWriteMatrixRemote_CSVFormat(t *testing.T) {
	rows := []remoteMatrixRow{
		{
			Username: "frank", Email: "frank@example.com",
			RoleName: "viewer", PermissionName: "secrets.read",
			Resource: "secrets", Action: "read",
			Scope: "project", ProjectName: "proj-b",
			EnvironmentName: "", ExpiresAt: nil,
		},
	}
	var buf bytes.Buffer
	err := writeMatrixRemote(&buf, rows, "csv")
	require.NoError(t, err)
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "username,"))
	assert.Contains(t, out, "frank")
	assert.Contains(t, out, "never")
}

// ── writeRemoteTable expiry + I/O error coverage ──────────────────────────────

// TestWriteRemoteTable_ExpiresAt — a time-bound remote row formats the expiry in
// table mode, exercising the ExpiresAt != nil branch.
func TestWriteRemoteTable_ExpiresAt(t *testing.T) {
	exp := time.Date(2030, 5, 20, 9, 0, 0, 0, time.UTC)
	rows := []remoteMatrixRow{
		{
			Username: "quentin", Email: "q@example.com",
			RoleName: "jit", PermissionName: "secrets.read",
			Scope: "global", ExpiresAt: &exp,
		},
	}
	var buf bytes.Buffer
	err := writeRemoteTable(&buf, rows)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "2030-05-20T09:00:00Z")
}

// failWriter is an io.Writer that always returns an error after n successful bytes.
type failWriter struct {
	written int
	failAt  int // fail when total written reaches this threshold (0 = fail immediately)
	err     error
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.written >= f.failAt {
		return 0, f.err
	}
	n := len(p)
	if f.written+n > f.failAt {
		n = f.failAt - f.written
	}
	f.written += n
	return n, nil
}

// TestWriteRemoteTable_HeaderWriteError — verifies that a write failure on the header
// line is propagated correctly.
func TestWriteRemoteTable_HeaderWriteError(t *testing.T) {
	rows := []remoteMatrixRow{
		{Username: "z", RoleName: "r", PermissionName: "p", Scope: "global"},
	}
	fw := &failWriter{failAt: 0, err: errors.New("disk full")}
	err := writeRemoteTable(fw, rows)
	require.Error(t, err)
}

// TestWriteEmbeddedTable_HeaderWriteError — verifies that a write failure on the
// header line is propagated from writeEmbeddedTable.
func TestWriteEmbeddedTable_HeaderWriteError(t *testing.T) {
	rows := []*core.PermissionMatrixRow{
		{Username: "z", RoleName: "r", PermissionName: "p", Scope: "global"},
	}
	fw := &failWriter{failAt: 0, err: errors.New("disk full")}
	err := writeEmbeddedTable(fw, rows)
	require.Error(t, err)
}

// ── runExportMatrixRemote error paths ─────────────────────────────────────────

// TestExportMatrix_RemoteGetError — rc.Get failure propagates when no project filter.
func TestExportMatrix_RemoteGetError(t *testing.T) {
	// Server closes the connection immediately to force an HTTP error.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/rbac/permission-matrix", func(w http.ResponseWriter, _ *http.Request) {
		// Return invalid JSON to trigger a decode error in rc.Get.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"oops"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	exportMatrixFormat = "json"
	exportMatrixProject = ""

	var buf bytes.Buffer
	err := runExportMatrixRemote(ctx, rc, &buf)
	require.Error(t, err, "HTTP 500 from server must propagate as error")
}

// TestExportMatrix_RemoteCSVNoProjectGetRawError — CSV (no project) GetRaw failure.
func TestExportMatrix_RemoteCSVNoProjectGetRawError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/rbac/permission-matrix", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"oops"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	exportMatrixFormat = "csv"
	exportMatrixProject = ""
	defer func() { exportMatrixProject = "" }()

	var buf bytes.Buffer
	err := runExportMatrixRemote(ctx, rc, &buf)
	require.Error(t, err, "GetRaw failure must propagate")
	assert.Contains(t, err.Error(), "permission matrix")
}

// TestExportMatrix_RemoteCSVWithProjectGetRawError — CSV + project, GetRaw failure.
func TestExportMatrix_RemoteCSVWithProjectGetRawError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/rbac/permission-matrix", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"oops"}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":7,"name":"proj-err"}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	exportMatrixFormat = "csv"
	exportMatrixProject = "proj-err"
	defer func() { exportMatrixProject = "" }()

	var buf bytes.Buffer
	err := runExportMatrixRemote(ctx, rc, &buf)
	require.Error(t, err, "GetRaw failure with project+csv must propagate")
	assert.Contains(t, err.Error(), "permission matrix")
}

// ── runExportMatrix embedded-mode coverage ────────────────────────────────────

// TestExportMatrix_EmbeddedTableEmpty — embedded mode with no grants prints "No
// permission grants found." in table format.
func TestExportMatrix_EmbeddedTableEmpty(t *testing.T) {
	setupEmbeddedMode(t)

	prevFormat := exportMatrixFormat
	prevProject := exportMatrixProject
	prevOutput := exportMatrixOutput
	t.Cleanup(func() {
		exportMatrixFormat = prevFormat
		exportMatrixProject = prevProject
		exportMatrixOutput = prevOutput
	})

	exportMatrixFormat = "table"
	exportMatrixProject = ""
	exportMatrixOutput = ""

	err := runExportMatrix(exportMatrixCmd, nil)
	require.NoError(t, err)
}

// TestExportMatrix_EmbeddedJSON — embedded mode returns JSON for empty DB.
func TestExportMatrix_EmbeddedJSON(t *testing.T) {
	setupEmbeddedMode(t)

	prevFormat := exportMatrixFormat
	prevProject := exportMatrixProject
	prevOutput := exportMatrixOutput
	t.Cleanup(func() {
		exportMatrixFormat = prevFormat
		exportMatrixProject = prevProject
		exportMatrixOutput = prevOutput
	})

	exportMatrixFormat = "json"
	exportMatrixProject = ""
	exportMatrixOutput = ""

	err := runExportMatrix(exportMatrixCmd, nil)
	require.NoError(t, err)
}

// TestExportMatrix_EmbeddedCSV — embedded mode returns CSV for empty DB.
func TestExportMatrix_EmbeddedCSV(t *testing.T) {
	setupEmbeddedMode(t)

	prevFormat := exportMatrixFormat
	prevProject := exportMatrixProject
	prevOutput := exportMatrixOutput
	t.Cleanup(func() {
		exportMatrixFormat = prevFormat
		exportMatrixProject = prevProject
		exportMatrixOutput = prevOutput
	})

	exportMatrixFormat = "csv"
	exportMatrixProject = ""
	exportMatrixOutput = ""

	err := runExportMatrix(exportMatrixCmd, nil)
	require.NoError(t, err)
}

// TestExportMatrix_EmbeddedOutputFile — embedded mode writes JSON to a file path.
func TestExportMatrix_EmbeddedOutputFile(t *testing.T) {
	setupEmbeddedMode(t)

	dir := t.TempDir()
	outPath := dir + "/matrix-embedded.json"

	prevFormat := exportMatrixFormat
	prevProject := exportMatrixProject
	prevOutput := exportMatrixOutput
	t.Cleanup(func() {
		exportMatrixFormat = prevFormat
		exportMatrixProject = prevProject
		exportMatrixOutput = prevOutput
	})

	exportMatrixFormat = "json"
	exportMatrixProject = ""
	exportMatrixOutput = outPath

	err := runExportMatrix(exportMatrixCmd, nil)
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	// Empty DB → JSON array "null" or "[]".
	assert.NotEmpty(t, string(content))
}

// TestExportMatrix_EmbeddedOutputFileCreateError — os.Create failure propagates.
func TestExportMatrix_EmbeddedOutputFileCreateError(t *testing.T) {
	setupEmbeddedMode(t)

	prevFormat := exportMatrixFormat
	prevProject := exportMatrixProject
	prevOutput := exportMatrixOutput
	t.Cleanup(func() {
		exportMatrixFormat = prevFormat
		exportMatrixProject = prevProject
		exportMatrixOutput = prevOutput
	})

	exportMatrixFormat = "json"
	exportMatrixProject = ""
	// A path that cannot be created (non-existent parent dir).
	exportMatrixOutput = "/nonexistent-dir/matrix.json"

	err := runExportMatrix(exportMatrixCmd, nil)
	require.Error(t, err, "invalid output path must cause an error")
	assert.Contains(t, err.Error(), "failed to open output file")
}

// TestExportMatrix_EmbeddedProjectNotFound — project filter with a missing project
// returns an error in embedded mode.
func TestExportMatrix_EmbeddedProjectNotFound(t *testing.T) {
	setupEmbeddedMode(t)

	prevFormat := exportMatrixFormat
	prevProject := exportMatrixProject
	prevOutput := exportMatrixOutput
	t.Cleanup(func() {
		exportMatrixFormat = prevFormat
		exportMatrixProject = prevProject
		exportMatrixOutput = prevOutput
	})

	exportMatrixFormat = "table"
	exportMatrixProject = "does-not-exist"
	exportMatrixOutput = ""

	err := runExportMatrix(exportMatrixCmd, nil)
	require.Error(t, err, "missing project must cause error in embedded mode")
	assert.Contains(t, err.Error(), "failed to resolve project")
}

// TestExportMatrix_EmbeddedInitStorageError — when no remote client and no config,
// InitializeStorage fails and the error is propagated.
func TestExportMatrix_EmbeddedInitStorageError(t *testing.T) {
	// Use a temp dir without a keyorix.yaml so config.Load("") fails.
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	// Do NOT write keyorix.yaml → config.Load("") returns an error.

	prevFormat := exportMatrixFormat
	prevProject := exportMatrixProject
	prevOutput := exportMatrixOutput
	t.Cleanup(func() {
		exportMatrixFormat = prevFormat
		exportMatrixProject = prevProject
		exportMatrixOutput = prevOutput
	})

	exportMatrixFormat = "table"
	exportMatrixProject = ""
	exportMatrixOutput = ""

	err := runExportMatrix(exportMatrixCmd, nil)
	// The error may come from config.Load or factory.CreateStorage.
	require.Error(t, err, "missing config must cause InitializeStorage error")
}

// TestExportMatrix_EmbeddedProjectFound — project filter resolves successfully when
// the project exists, covering the LookupProjectIDByName happy path.
func TestExportMatrix_EmbeddedProjectFound(t *testing.T) {
	setupEmbeddedMode(t)

	// Pre-seed a project by initializing the storage directly.
	st, err := common.InitializeStorage()
	require.NoError(t, err)
	ctx := context.Background()
	_, err = st.CreateProject(ctx, &models.Project{Name: "alpha-proj"})
	require.NoError(t, err)

	prevFormat := exportMatrixFormat
	prevProject := exportMatrixProject
	prevOutput := exportMatrixOutput
	t.Cleanup(func() {
		exportMatrixFormat = prevFormat
		exportMatrixProject = prevProject
		exportMatrixOutput = prevOutput
	})

	exportMatrixFormat = "table"
	exportMatrixProject = "alpha-proj"
	exportMatrixOutput = ""

	err = runExportMatrix(exportMatrixCmd, nil)
	require.NoError(t, err)
}
