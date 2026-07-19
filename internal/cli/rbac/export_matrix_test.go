package rbac

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
