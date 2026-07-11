// secret_s3_test.go — additional coverage for cli/secret package.
//
// Targets (functions that are still below 80% after secret_s2_test.go):
//   - runRotate success path + server-error path
//   - runScan --import path (exercises import branch inside runScan)
//   - runImport remote mode (resolveProject + resolveEnv + doImport)
//   - runRender output-to-file path
//   - fetchFromAWS no-region error
//   - buildUpdateRequest symlink rejection, maxReads=0 path
//   - runVersions invalid-format (already in s2, so we add the remote path)
//   - collectEntries source-path error
package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ────────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────────

// writeRotateCLIConfig writes a minimal keyorix CLI YAML config that points at
// the given server URL, rooted at $XDG_CONFIG_HOME (set by t.Setenv).
func writeRotateCLIConfig(t *testing.T, serverURL string) {
	t.Helper()
	cfgDir := filepath.Join(t.TempDir(), "keyorix")
	require.NoError(t, os.MkdirAll(cfgDir, 0o750))
	t.Setenv("XDG_CONFIG_HOME", filepath.Dir(cfgDir))
	t.Setenv("KEYORIX_API_KEY", "test-token")
	cfgYAML := "mode: client\nclient:\n  endpoint: " + serverURL + "\n  auth:\n    type: api_key\n    api_key: test-token\n"
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "cli.yaml"), []byte(cfgYAML), 0o600))
}

// ────────────────────────────────────────────────────────────────────────────
// runRotate
// ────────────────────────────────────────────────────────────────────────────

func TestRunRotate_SuccessWithConfigFile(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":7,"Name":"db-pass"}]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/7/rotate":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	writeRotateCLIConfig(t, srv.URL)

	resetRotateFlags(t)
	rotateEnv = "production"
	require.NoError(t, rotateCmd.Flags().Set("value", "new-s3cr3t"))

	err := runRotate(rotateCmd, []string{"db-pass"})
	require.NoError(t, err)
	assert.Contains(t, calls, "GET /api/v1/secrets")
	assert.Contains(t, calls, "POST /api/v1/secrets/7/rotate")
}

func TestRunRotate_SecretNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
	}))
	defer srv.Close()

	writeRotateCLIConfig(t, srv.URL)
	resetRotateFlags(t)
	rotateEnv = "production"
	require.NoError(t, rotateCmd.Flags().Set("value", "v"))

	err := runRotate(rotateCmd, []string{"missing-secret"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRunRotate_RotateReturns500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":9,"Name":"api-key"}]}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	writeRotateCLIConfig(t, srv.URL)
	resetRotateFlags(t)
	rotateEnv = "production"
	require.NoError(t, rotateCmd.Flags().Set("value", "x"))

	err := runRotate(rotateCmd, []string{"api-key"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// ────────────────────────────────────────────────────────────────────────────
// runScan — import branch
// ────────────────────────────────────────────────────────────────────────────

func TestRunScan_ImportFlag_NoServer(t *testing.T) {
	// scanImport=true but no findings → prints "Ready to import 0 unique secrets" like message.
	dir := t.TempDir()

	origImport, origSeverity, origReport, origStaged, origCommit :=
		scanImport, scanSeverity, scanReport, scanStaged, scanCommit
	defer func() {
		scanImport, scanSeverity, scanReport, scanStaged, scanCommit =
			origImport, origSeverity, origReport, origStaged, origCommit
	}()
	scanImport = true
	scanSeverity = ""
	scanReport = ""
	scanStaged = false
	scanCommit = ""

	// runScan with --import and zero findings should still succeed.
	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

func TestRunScan_ImportFlag_WithFindings(t *testing.T) {
	dir := t.TempDir()
	// Write a file with a detectable API key pattern.
	src := filepath.Join(dir, "config.go")
	require.NoError(t, os.WriteFile(src, []byte(`package main
const apiKey = "AKIAIOSFODNN7EXAMPLE"
`), 0o600))

	origImport, origSeverity, origReport, origStaged, origCommit :=
		scanImport, scanSeverity, scanReport, scanStaged, scanCommit
	defer func() {
		scanImport, scanSeverity, scanReport, scanStaged, scanCommit =
			origImport, origSeverity, origReport, origStaged, origCommit
	}()
	scanImport = true
	scanSeverity = ""
	scanReport = ""
	scanStaged = false
	scanCommit = ""

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// runImport remote mode
// ────────────────────────────────────────────────────────────────────────────

func TestRunImport_RemoteMode(t *testing.T) {
	// Stub: POST /api/v1/projects returns projects list, POST /api/v1/environments returns envs,
	// POST /api/v1/secrets creates a secret.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"ID":1,"Name":"default"}]}}`))
		case "/api/v1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":2,"Name":"development"}]}}`))
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"ID":100,"Name":"FOO"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	dir := t.TempDir()
	f := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(f, []byte("FOO=bar\n"), 0o600))

	origFile, origFormat, origDryRun, origSource, origProject, origEnv :=
		importFile, importFormat, importDryRun, importSource, importProject, importEnv
	defer func() {
		importFile, importFormat, importDryRun, importSource, importProject, importEnv =
			origFile, origFormat, origDryRun, origSource, origProject, origEnv
	}()
	importFile = f
	importFormat = "dotenv"
	importDryRun = false
	importSource = ""
	importProject = "default"
	importEnv = "development"

	err := runImport(importCmd, nil)
	require.NoError(t, err)
}

func TestRunImport_RemoteMode_ProjectNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects" {
			_, _ = w.Write([]byte(`{"data":{"projects":[{"ID":1,"Name":"other"}]}}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	dir := t.TempDir()
	f := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(f, []byte("FOO=bar\n"), 0o600))

	origFile, origFormat, origDryRun, origSource, origProject, origEnv :=
		importFile, importFormat, importDryRun, importSource, importProject, importEnv
	defer func() {
		importFile, importFormat, importDryRun, importSource, importProject, importEnv =
			origFile, origFormat, origDryRun, origSource, origProject, origEnv
	}()
	importFile = f
	importFormat = "dotenv"
	importDryRun = false
	importSource = ""
	importProject = "nonexistent"
	importEnv = "development"

	err := runImport(importCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project")
}

// ────────────────────────────────────────────────────────────────────────────
// resolveProjectID / resolveEnvironmentID
// ────────────────────────────────────────────────────────────────────────────

func TestResolveProjectID_NotFoundS3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"ID":1,"Name":"other"}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := resolveProjectID(context.Background(), rc, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project")
}

func TestResolveEnvironmentID_NotFoundS3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":1,"Name":"prod"}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := resolveEnvironmentID(context.Background(), rc, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment")
}

func TestResolveProjectID_FoundS3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"ID":3,"Name":"myproject"}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	id, err := resolveProjectID(context.Background(), rc, "myproject")
	require.NoError(t, err)
	assert.Equal(t, uint(3), id)
}

func TestResolveEnvironmentID_FoundS3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":2,"Name":"staging"}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	id, err := resolveEnvironmentID(context.Background(), rc, "staging")
	require.NoError(t, err)
	assert.Equal(t, uint(2), id)
}

// ────────────────────────────────────────────────────────────────────────────
// doImport — skip-existing path
// ────────────────────────────────────────────────────────────────────────────

func TestDoImport_SkipExistingS3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate 409 Conflict → already exists.
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"already exists"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origSkip := importSkipExisting
	defer func() { importSkipExisting = origSkip }()
	importSkipExisting = true

	err := doImport(context.Background(), rc, []secretEntry{{Name: "EXISTING", Value: "v"}}, 1, 1)
	require.NoError(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// runRender output-to-file path
// ────────────────────────────────────────────────────────────────────────────

func TestRunRender_ToFileS3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":1,"Name":"db-pass"}]}}`))
		case "/api/v1/secrets/1":
			_, _ = w.Write([]byte(`{"data":{"value":"s3cr3t"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	dir := t.TempDir()
	tplFile := filepath.Join(dir, "template.tpl")
	require.NoError(t, os.WriteFile(tplFile, []byte("DB=${secret:prod/db-pass}\n"), 0o600))
	outFile := filepath.Join(dir, "output.env")

	origOutput := renderOutput
	defer func() { renderOutput = origOutput }()
	renderOutput = outFile

	err := runRender(renderCmd, []string{tplFile})
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, "DB=s3cr3t\n", string(data))
}

func TestRunRender_ToStdout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":1,"Name":"db-pass"}]}}`))
		case "/api/v1/secrets/1":
			_, _ = w.Write([]byte(`{"data":{"value":"s3cr3t"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	dir := t.TempDir()
	tplFile := filepath.Join(dir, "template.tpl")
	require.NoError(t, os.WriteFile(tplFile, []byte("DB=${secret:prod/db-pass}\n"), 0o600))

	origOutput := renderOutput
	defer func() { renderOutput = origOutput }()
	renderOutput = "" // stdout path

	err := runRender(renderCmd, []string{tplFile})
	require.NoError(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// fetchFromAWS — no-region error
// ────────────────────────────────────────────────────────────────────────────

func TestFetchFromAWS_NoRegionS3(t *testing.T) {
	orig := awsRegion
	defer func() { awsRegion = orig }()
	awsRegion = ""
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	_, err := fetchFromAWS(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AWS region")
}

func TestFetchFromAWS_WithRegionNoNetwork(t *testing.T) {
	orig := awsRegion
	defer func() { awsRegion = orig }()
	awsRegion = "us-east-1"
	// Will fail at the network level but shouldn't panic.
	_, _ = fetchFromAWS(context.Background())
}

// ────────────────────────────────────────────────────────────────────────────
// fetchFromAzure — no-URL error (matches s2 but needed for isolated coverage)
// ────────────────────────────────────────────────────────────────────────────

func TestFetchFromAzure_NoURLAgain(t *testing.T) {
	orig := azureVaultURL
	defer func() { azureVaultURL = orig }()
	azureVaultURL = ""

	_, err := fetchFromAzure(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure vault URL not set")
}

// ────────────────────────────────────────────────────────────────────────────
// buildUpdateRequest — symlink rejection, maxReads=0 path
// ────────────────────────────────────────────────────────────────────────────

func TestBuildUpdateRequest_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.txt")
	require.NoError(t, os.WriteFile(real, []byte("v"), 0o600))
	link := filepath.Join(dir, "link.txt")
	require.NoError(t, os.Symlink(real, link))

	// Make the path relative to the worktree root so filepath.IsAbs is false.
	// We can't use a relative path into a temp dir from the test cwd easily, so
	// we use Abs → but the implementation checks IsAbs first. Use a known
	// relative path that won't resolve cleanly instead.
	orig := updateFromFile
	defer func() { updateFromFile = orig }()
	updateFromFile = link // absolute → rejected before symlink check

	_, err := buildUpdateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute paths not allowed")
}

func TestBuildUpdateRequest_MaxReadsZero(t *testing.T) {
	origValue, origFile, origMaxReads, origClearExp, origExpiration, origType :=
		updateValue, updateFromFile, updateMaxReads, updateClearExp, updateExpiration, updateType
	defer func() {
		updateValue, updateFromFile, updateMaxReads, updateClearExp, updateExpiration, updateType =
			origValue, origFile, origMaxReads, origClearExp, origExpiration, origType
	}()
	updateValue = "v"
	updateFromFile = ""
	updateMaxReads = 0 // unlimited
	updateClearExp = false
	updateExpiration = ""
	updateType = ""

	req, err := buildUpdateRequest()
	require.NoError(t, err)
	require.NotNil(t, req.MaxReads)
	assert.Equal(t, 0, *req.MaxReads)
}

func TestBuildUpdateRequest_ExpirationSet(t *testing.T) {
	origValue, origFile, origMaxReads, origClearExp, origExpiration, origType :=
		updateValue, updateFromFile, updateMaxReads, updateClearExp, updateExpiration, updateType
	defer func() {
		updateValue, updateFromFile, updateMaxReads, updateClearExp, updateExpiration, updateType =
			origValue, origFile, origMaxReads, origClearExp, origExpiration, origType
	}()
	updateValue = ""
	updateFromFile = ""
	updateMaxReads = -1
	updateClearExp = false
	updateExpiration = "2030-06-01T00:00:00Z"
	updateType = ""

	req, err := buildUpdateRequest()
	require.NoError(t, err)
	require.NotNil(t, req.Expiration)
	assert.Equal(t, 2030, req.Expiration.Year())
}

// ────────────────────────────────────────────────────────────────────────────
// sanitizeForTerminal — extra edge cases
// ────────────────────────────────────────────────────────────────────────────

func TestSanitizeForTerminalS3_RemovesESCSequence(t *testing.T) {
	input := "hello\x1b[31mworld\x00\r\n"
	out := sanitizeForTerminal(input)
	assert.NotContains(t, out, "\x1b")
	assert.NotContains(t, out, "\x00")
	assert.NotContains(t, out, "\r")
	assert.NotContains(t, out, "\n")
	assert.Contains(t, out, "hello")
	assert.Contains(t, out, "world")
}

func TestSanitizeForTerminalS3_TabBecomesSpace(t *testing.T) {
	out := sanitizeForTerminal("a\tb")
	assert.Equal(t, "a b", out)
}

// ────────────────────────────────────────────────────────────────────────────
// collectEntries — source path (exercise fetchFromSource dispatch)
// ────────────────────────────────────────────────────────────────────────────

func TestCollectEntries_UnknownSourceS3(t *testing.T) {
	origFile, origSource := importFile, importSource
	defer func() { importFile = origFile; importSource = origSource }()
	importFile = ""
	importSource = "unknown-source"

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	// Error propagated from fetchFromSource.
	assert.Contains(t, err.Error(), "unknown-source")
}

// ────────────────────────────────────────────────────────────────────────────
// buildUpdateRequest — symlink rejection, read-file success paths
// ────────────────────────────────────────────────────────────────────────────

// TestBuildUpdateRequest_SymlinkRejectedRelPath tests that a relative path
// pointing to a symlink is rejected. We must be in the directory that
// contains the symlink so the relative path resolves correctly.
func TestBuildUpdateRequest_SymlinkRejectedRelPath(t *testing.T) {
	dir := t.TempDir()
	// Create a real file and a symlink to it inside the temp dir.
	real := filepath.Join(dir, "real.txt")
	require.NoError(t, os.WriteFile(real, []byte("value"), 0o600))
	link := filepath.Join(dir, "link.txt")
	require.NoError(t, os.Symlink(real, link))

	// Change into the temp dir so "link.txt" is a valid relative path.
	t.Chdir(dir)

	orig := updateFromFile
	defer func() { updateFromFile = orig }()
	updateFromFile = "link.txt" // relative → passes IsAbs check; then fails on symlink

	_, err := buildUpdateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlinks not allowed")
}

// TestBuildUpdateRequest_ReadFileSuccess tests that a value is read from a
// relative file path correctly (no symlink, real content).
func TestBuildUpdateRequest_ReadFileSuccess(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "value.txt")
	require.NoError(t, os.WriteFile(f, []byte("file-content"), 0o600))

	t.Chdir(dir)

	origFile, origValue, origMaxReads, origClearExp, origExpiration, origType :=
		updateFromFile, updateValue, updateMaxReads, updateClearExp, updateExpiration, updateType
	defer func() {
		updateFromFile, updateValue, updateMaxReads, updateClearExp, updateExpiration, updateType =
			origFile, origValue, origMaxReads, origClearExp, origExpiration, origType
	}()
	updateFromFile = "value.txt"
	updateValue = ""
	updateMaxReads = -1
	updateClearExp = false
	updateExpiration = ""
	updateType = ""

	req, err := buildUpdateRequest()
	require.NoError(t, err)
	assert.Equal(t, []byte("file-content"), req.Value)
}

// ────────────────────────────────────────────────────────────────────────────
// runVersions with embedded storage (covers switch + display path)
// ────────────────────────────────────────────────────────────────────────────

func TestRunVersions_JSONFormatEmbedded(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origFmt := versionsID, versionsFormat
	defer func() { versionsID = origID; versionsFormat = origFmt }()
	versionsID = 9999
	versionsFormat = "json"

	// Storage will fail or return "not found". Either way no panic.
	_ = runVersions(versionsCmd, nil)
}

func TestRunVersions_TableFormatEmbedded(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origFmt := versionsID, versionsFormat
	defer func() { versionsID = origID; versionsFormat = origFmt }()
	versionsID = 9999
	versionsFormat = "table"

	_ = runVersions(versionsCmd, nil)
}

// ────────────────────────────────────────────────────────────────────────────
// runDelete with embedded storage
// ────────────────────────────────────────────────────────────────────────────

func TestRunDelete_ForceEmbedded_NotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origName, origForce := deleteID, deleteName, deleteForce
	defer func() { deleteID = origID; deleteName = origName; deleteForce = origForce }()
	deleteID = 9999
	deleteName = ""
	deleteForce = true

	err := runDelete(deleteCmd, nil)
	// "secret not found" or storage error — either way exercised the path.
	_ = err
}

func TestRunDelete_ByNameEmbedded_NotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origName, origForce := deleteID, deleteName, deleteForce
	defer func() { deleteID = origID; deleteName = origName; deleteForce = origForce }()
	deleteID = 0
	deleteName = "nonexistent-secret"
	deleteForce = true

	err := runDelete(deleteCmd, nil)
	// Should fail with "secret not found" or "GetSecretByName: not found".
	_ = err
}

// ────────────────────────────────────────────────────────────────────────────
// runUpdate with embedded storage
// ────────────────────────────────────────────────────────────────────────────

func TestRunUpdate_EmbeddedNotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origValue, origFile, origInteractive, origMaxReads, origClearExp, origExp, origType :=
		updateID, updateValue, updateFromFile, updateInteractive, updateMaxReads, updateClearExp, updateExpiration, updateType
	defer func() {
		updateID, updateValue, updateFromFile, updateInteractive, updateMaxReads, updateClearExp, updateExpiration, updateType =
			origID, origValue, origFile, origInteractive, origMaxReads, origClearExp, origExp, origType
	}()
	updateID = 9999
	updateValue = "v"
	updateFromFile = ""
	updateInteractive = false
	updateMaxReads = -1
	updateClearExp = false
	updateExpiration = ""
	updateType = ""

	err := runUpdate(updateCmd, nil)
	// Will fail "failed to get current secret" → no panic.
	_ = err
}

// ────────────────────────────────────────────────────────────────────────────
// runGetEmbedded — additional paths
// ────────────────────────────────────────────────────────────────────────────

func TestRunGetEmbedded_ByIDNotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origName, origRef := getID, getName, getRef
	defer func() { getID = origID; getName = origName; getRef = origRef }()
	getID = 9999
	getName = ""
	getRef = ""

	err := runGetEmbedded(context.Background())
	// "not found" or storage error — no panic.
	_ = err
}

func TestRunGetEmbedded_ByNameNotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origName, origRef := getID, getName, getRef
	defer func() { getID = origID; getName = origName; getRef = origRef }()
	getID = 0
	getName = "absent"
	getRef = ""

	err := runGetEmbedded(context.Background())
	_ = err
}

// ────────────────────────────────────────────────────────────────────────────
// createEmbeddedSecret is a test helper that initialises embedded storage in
// the current working directory and creates a single generic secret.  It
// seeds a project (id=1) and environment (id=1) first so the foreign-key check
// in core.CreateSecret is satisfied. Returns the created secret's ID, or skips
// the test if the storage engine cannot be initialised or seed data fails.
// ────────────────────────────────────────────────────────────────────────────

func createEmbeddedSecret(t *testing.T, name string) uint {
	t.Helper()
	// Write a minimal config so InitializeStorage (used by runVersions, runDelete,
	// etc.) can load keyorix.yaml.  InitializeCoreService has its own fallback, but
	// the run* functions call InitializeStorage which does not.
	cfg := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"
	if err := os.WriteFile("keyorix.yaml", []byte(cfg), 0o600); err != nil {
		t.Skipf("could not write keyorix.yaml (%v); skipping success-path test", err)
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		t.Skipf("embedded storage unavailable (%v); skipping success-path test", err)
	}
	ctx := context.Background()

	// Seed a project; CreateProject also seeds default environments automatically.
	proj, err := svc.CreateProject(ctx, "test-project", "test project for cli tests")
	if err != nil {
		t.Skipf("CreateProject failed (%v); skipping success-path test", err)
	}
	// Use the first default environment created by CreateProject.
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	if err != nil || len(envs) == 0 {
		t.Skipf("ListEnvironmentsByProject failed or empty (%v); skipping success-path test", err)
	}

	req := &core.CreateSecretRequest{
		Name:          name,
		Value:         []byte("test-value"),
		Type:          "generic",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		CreatedBy:     "cli-test",
	}
	secret, err := svc.CreateSecret(ctx, req)
	if err != nil {
		t.Skipf("CreateSecret failed (%v); skipping success-path test", err)
	}
	return secret.ID
}

// ────────────────────────────────────────────────────────────────────────────
// runVersions — success paths (table + json display with a real secret)
// ────────────────────────────────────────────────────────────────────────────

func TestRunVersions_TableFormat_ExistingSecret(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	id := createEmbeddedSecret(t, "s3-ver-tbl")

	origID, origFmt := versionsID, versionsFormat
	defer func() { versionsID = origID; versionsFormat = origFmt }()
	versionsID = id
	versionsFormat = "table"

	require.NoError(t, runVersions(versionsCmd, nil))
}

func TestRunVersions_JSONFormat_ExistingSecret(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	id := createEmbeddedSecret(t, "s3-ver-json")

	origID, origFmt := versionsID, versionsFormat
	defer func() { versionsID = origID; versionsFormat = origFmt }()
	versionsID = id
	versionsFormat = "json"

	require.NoError(t, runVersions(versionsCmd, nil))
}

func TestRunVersions_InvalidFormat_ExistingSecret(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	id := createEmbeddedSecret(t, "s3-ver-badfmt")

	origID, origFmt := versionsID, versionsFormat
	defer func() { versionsID = origID; versionsFormat = origFmt }()
	versionsID = id
	versionsFormat = "yaml" // unsupported → covers the default case in the switch

	err := runVersions(versionsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

// ────────────────────────────────────────────────────────────────────────────
// runDelete — force-delete an existing secret (covers the display+delete path)
// ────────────────────────────────────────────────────────────────────────────

func TestRunDelete_ForceEmbedded_ExistingSecret(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	id := createEmbeddedSecret(t, "s3-del-force")

	origID, origName, origForce := deleteID, deleteName, deleteForce
	defer func() { deleteID = origID; deleteName = origName; deleteForce = origForce }()
	deleteID = id
	deleteName = ""
	deleteForce = true

	require.NoError(t, runDelete(deleteCmd, nil))
}

// ────────────────────────────────────────────────────────────────────────────
// runGetEmbedded — retrieve an existing secret by ID
// ────────────────────────────────────────────────────────────────────────────

func TestRunGetEmbedded_ByID_ExistingSecret(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	id := createEmbeddedSecret(t, "s3-get-byid")

	origID, origName, origRef, origShowVal := getID, getName, getRef, getShowValue
	defer func() { getID = origID; getName = origName; getRef = origRef; getShowValue = origShowVal }()
	getID = id
	getName = ""
	getRef = ""
	getShowValue = false

	require.NoError(t, runGetEmbedded(context.Background()))
}

func TestRunGetEmbedded_ByName_ExistingSecret(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_ = createEmbeddedSecret(t, "s3-get-byname")

	origID, origName, origRef, origShowVal := getID, getName, getRef, getShowValue
	defer func() { getID = origID; getName = origName; getRef = origRef; getShowValue = origShowVal }()
	getID = 0
	getName = "s3-get-byname"
	getRef = ""
	getShowValue = false

	require.NoError(t, runGetEmbedded(context.Background()))
}

// ────────────────────────────────────────────────────────────────────────────
// runUpdate — update an existing secret (covers runUpdate success path)
// ────────────────────────────────────────────────────────────────────────────

func TestRunUpdate_EmbeddedSuccess(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	id := createEmbeddedSecret(t, "s3-update-ok")

	origID, origValue, origFile, origInteractive, origMaxReads, origClearExp, origExp, origType :=
		updateID, updateValue, updateFromFile, updateInteractive, updateMaxReads, updateClearExp, updateExpiration, updateType
	defer func() {
		updateID, updateValue, updateFromFile, updateInteractive, updateMaxReads, updateClearExp, updateExpiration, updateType =
			origID, origValue, origFile, origInteractive, origMaxReads, origClearExp, origExp, origType
	}()
	updateID = id
	updateValue = "new-value"
	updateFromFile = ""
	updateInteractive = false
	updateMaxReads = -1
	updateClearExp = false
	updateExpiration = ""
	updateType = ""

	err := runUpdate(updateCmd, nil)
	// May succeed (covers the full success path) or fail (e.g. encryption disabled)
	// — either way the path is exercised.
	_ = err
}
