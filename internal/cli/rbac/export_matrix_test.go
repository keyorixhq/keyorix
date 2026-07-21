package rbac

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
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
