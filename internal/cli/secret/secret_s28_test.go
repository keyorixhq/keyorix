// secret_s28_test.go — coverage sprint S28.
//
// Targets (uncovered / low-coverage paths not yet hit by previous test rounds):
//
//   - runScan: invalid --severity flag, scanCommit with valid commit (files path),
//     scanImport with no findings (no deduplication needed), scanSeverity filter
//   - runGetRemote: getID with show-value, getID without show-value, getName not found,
//     getName with show-value path
//   - runGetEmbedded: getName not found (exhausted pages), getRef error paths
//   - runUpdateRemote: GET error, PUT error
//   - runUpdate: updateID == 0 error
//   - buildUpdateRequest: fromFile absolute path, fromFile symlink, fromFile happy path
//   - fetchAccessLog: days > 0 path (covers the query-string branch)
//   - interactiveUpdate: stdin-driven non-interactive skip (exercises the reader)
//   - runRender: template file read error, splitSecretRef error branches
//   - runDelete: --id and --name both empty (error path)
//   - collectEntries: both source + file set, neither set
//   - isPlaceholder: short string branch, placeholder keyword branches
//   - sanitizeName: special chars
//   - printScanReport: no-findings branch, hardcoded/env/config source buckets
//   - runVersions: missing id error
package secret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helper: save and restore all scan package-vars ────────────────────────────

func saveScanVars_S28(t *testing.T) {
	t.Helper()
	origReport, origSeverity, origStaged, origCommit, origImport :=
		scanReport, scanSeverity, scanStaged, scanCommit, scanImport
	t.Cleanup(func() {
		scanReport = origReport
		scanSeverity = origSeverity
		scanStaged = origStaged
		scanCommit = origCommit
		scanImport = origImport
	})
}

// ── runScan: invalid --severity ────────────────────────────────────────────────

func TestRunScan_S28_InvalidSeverityReturnsError(t *testing.T) {
	saveScanVars_S28(t)
	dir := t.TempDir()
	scanSeverity = "critical" // not one of low/medium/high
	scanStaged = false
	scanCommit = ""
	scanReport = ""
	scanImport = false

	err := runScan(scanCmd, []string{dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --severity value")
	assert.Contains(t, err.Error(), "critical")
}

// ── runScan: severity filter hits the recounting branches ────────────────────

func TestRunScan_S28_SeverityFilterHigh(t *testing.T) {
	saveScanVars_S28(t)
	dir := t.TempDir()
	// Write a file that triggers a HIGH finding (AWS access key pattern).
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "creds.yaml"),
		[]byte("aws_access_key_id: AKIAIOSFODNN7EXAMPLE\n"),
		0o600,
	))
	scanSeverity = "high"
	scanStaged = false
	scanCommit = ""
	scanReport = ""
	scanImport = false

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

// TestRunScan_S28_SeverityFilterMedium exercises the medium-only filter branch.
func TestRunScan_S28_SeverityFilterMedium(t *testing.T) {
	saveScanVars_S28(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".env"),
		[]byte("DB_PASSWORD=supersecret123\n"),
		0o600,
	))
	scanSeverity = "medium"
	scanStaged = false
	scanCommit = ""
	scanReport = ""
	scanImport = false

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

// TestRunScan_S28_SeverityFilterLow exercises the low-only filter.
func TestRunScan_S28_SeverityFilterLow(t *testing.T) {
	saveScanVars_S28(t)
	dir := t.TempDir()
	// Generic "secret = ..." in a source file → low → re-classified as medium in source
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "app.go"),
		[]byte(`package main
const secret = "a-pretty-long-token-value-here"
`),
		0o600,
	))
	scanSeverity = "low"
	scanStaged = false
	scanCommit = ""
	scanReport = ""
	scanImport = false

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

// TestRunScan_S28_ScanImportNoFindings exercises the scanImport branch when
// the scan produces zero findings (the import block should be skipped silently).
func TestRunScan_S28_ScanImportNoFindings(t *testing.T) {
	saveScanVars_S28(t)
	dir := t.TempDir()
	// No secret patterns in the file.
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "README.md"),
		[]byte("# Hello world\n"),
		0o600,
	))
	scanImport = true
	scanStaged = false
	scanReport = ""
	scanSeverity = ""
	scanCommit = ""

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

// TestRunScan_S28_SourceFileHighRisk exercises the hardcoded→high path and
// the hardcoded bucket in printScanReport.
func TestRunScan_S28_SourceFileHighRisk(t *testing.T) {
	saveScanVars_S28(t)
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.json")
	// Use a Go file with an explicit aws_access_key_id assignment to hit the high pattern.
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "main.go"),
		[]byte(`package main
const aws_access_key_id = "AKIAIOSFODNN7EXAM"
const db_password = "myrealdbpassword123"
`),
		0o600,
	))
	scanSeverity = ""
	scanStaged = false
	scanCommit = ""
	scanReport = reportPath
	scanImport = false

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)

	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	var report ScanReport
	require.NoError(t, json.Unmarshal(data, &report))
	assert.Greater(t, report.TotalFound, 0)
}

// ── printScanReport: no-findings branch ───────────────────────────────────────

func TestPrintScanReport_S28_NoFindings(t *testing.T) {
	// Should print "No secrets found." without panicking.
	report := &ScanReport{
		ScannedPath: "/tmp/test",
		TotalFound:  0,
	}
	printScanReport(report) // must not panic
}

// TestPrintScanReport_S28_AllBuckets covers hardcoded + env_file + config_file branches.
func TestPrintScanReport_S28_AllBuckets(t *testing.T) {
	report := &ScanReport{
		ScannedPath: "/tmp/test",
		TotalFound:  3,
		HighRisk:    1,
		MediumRisk:  1,
		LowRisk:     1,
		Findings: []ScanFinding{
			{File: "main.go", Line: 1, Name: "API_KEY", Source: "hardcoded", RiskLevel: "high", RiskReason: "reason"},
			{File: ".env", Line: 2, Name: "DB_PASS", Source: "env_file", RiskLevel: "medium"},
			{File: "config.yaml", Line: 3, Name: "SECRET", Source: "config_file", RiskLevel: "low"},
		},
	}
	printScanReport(report) // must not panic
}

// ── isPlaceholder ─────────────────────────────────────────────────────────────

func TestIsPlaceholder_S28_ShortString(t *testing.T) {
	assert.True(t, isPlaceholder("ab"))  // len < 4
	assert.True(t, isPlaceholder(""))    // len 0
	assert.True(t, isPlaceholder("abc")) // len 3, still < 4
}

func TestIsPlaceholder_S28_PlaceholderKeywords(t *testing.T) {
	assert.True(t, isPlaceholder("changeme"))
	assert.True(t, isPlaceholder("your_secret_key"))
	assert.True(t, isPlaceholder("xxxsomething"))
	assert.True(t, isPlaceholder("example_value"))
	assert.True(t, isPlaceholder("placeholder123"))
	assert.True(t, isPlaceholder("TODO_FIX_THIS"))
	assert.True(t, isPlaceholder("fixme-later"))
	assert.True(t, isPlaceholder("replace_me"))
	assert.True(t, isPlaceholder("insert_here"))
	assert.True(t, isPlaceholder("your-token"))
	assert.True(t, isPlaceholder("<your-secret>"))
	assert.True(t, isPlaceholder("${SECRET_VAR}"))
	assert.True(t, isPlaceholder("%(secret)s"))
}

func TestIsPlaceholder_S28_RealValue(t *testing.T) {
	// These must NOT be flagged as placeholders — real-looking secret values.
	assert.False(t, isPlaceholder("AKIAIOSFODNN7GHIJ")) // 18 chars, no placeholder keyword
	assert.False(t, isPlaceholder("longpassword1234"))  // 16 chars, no placeholder keyword
	assert.False(t, isPlaceholder("s3cr3t-token-val")) // 16 chars
}

// ── sanitizeName ─────────────────────────────────────────────────────────────

func TestSanitizeName_S28(t *testing.T) {
	assert.Equal(t, "API_KEY", sanitizeName("api-key"))
	assert.Equal(t, "DB_PASSWORD", sanitizeName("db_password"))
	assert.Equal(t, "MY_SECRET_VAR", sanitizeName("my.secret.var"))
	assert.Equal(t, "HELLO_WORLD", sanitizeName("hello world"))
}

// ── scanEnvFile ───────────────────────────────────────────────────────────────

func TestScanEnvFile_S28_SkipsCommentAndEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(p, []byte(`
# comment
EMPTY=
PLACEHOLDER=changeme
REAL_SECRET=longvalue123
`), 0o600))
	findings := scanEnvFile(p, ".env")
	require.Len(t, findings, 1)
	assert.Equal(t, "REAL_SECRET", findings[0].Name)
}

func TestScanEnvFile_S28_NonExistentFileReturnsNil(t *testing.T) {
	findings := scanEnvFile("/nonexistent/path/.env", ".env")
	assert.Nil(t, findings)
}

// ── scanConfigFile ────────────────────────────────────────────────────────────

func TestScanConfigFile_S28_NonExistentFileReturnsNil(t *testing.T) {
	findings := scanConfigFile("/nonexistent/config.yaml", "config.yaml")
	assert.Nil(t, findings)
}

func TestScanConfigFile_S28_PlaceholderSkipped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(`api_key: changeme`), 0o600))
	findings := scanConfigFile(p, "config.yaml")
	assert.Empty(t, findings)
}

// ── scanSourceFile ────────────────────────────────────────────────────────────

func TestScanSourceFile_S28_NonExistentFileReturnsNil(t *testing.T) {
	findings := scanSourceFile("/nonexistent/source.go", "source.go")
	assert.Nil(t, findings)
}

func TestScanSourceFile_S28_HighRiskPattern(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(p, []byte(`package main
const db_password = "mysupersecret123"
`), 0o600))
	findings := scanSourceFile(p, "main.go")
	assert.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Equal(t, "high", f.RiskLevel, "source file findings should be escalated to high")
		assert.Equal(t, "hardcoded", f.Source)
	}
}

// ── runGetRemote: getID paths ─────────────────────────────────────────────────

func getRemoteStub_S28(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	expiry := time.Now().Add(24 * time.Hour)
	secret := models.SecretNode{
		ID:            42,
		Name:          "db-pass",
		Type:          "password",
		Status:        "active",
		ProjectID:     1,
		EnvironmentID: 1,
		CreatedBy:     "user",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Expiration:    &expiry,
	}
	secretJSON, _ := json.Marshal(secret)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/secrets/42" && r.URL.Query().Get("include_value") == "true":
			body := map[string]interface{}{
				"data": map[string]interface{}{
					"secret": secret,
					"value":  "s3cr3t-val",
				},
			}
			_ = json.NewEncoder(w).Encode(body)
		case r.URL.Path == "/api/v1/secrets/42":
			_, _ = w.Write([]byte(`{"data":` + string(secretJSON) + `}`))
		case r.URL.Path == "/api/v1/secrets":
			body := map[string]interface{}{
				"data": map[string]interface{}{
					"secrets": []models.SecretNode{secret},
				},
			}
			_ = json.NewEncoder(w).Encode(body)
		case r.URL.Path == "/api/v1/secrets/99" && r.URL.Query().Get("include_value") == "true":
			body := map[string]interface{}{
				"data": map[string]interface{}{
					"secret": secret,
					"value":  "byname-val",
				},
			}
			_ = json.NewEncoder(w).Encode(body)
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

// saveGetVars_S28 saves/restores runGet package vars.
func saveGetVars_S28(t *testing.T) {
	t.Helper()
	origID, origName, origRef, origShow, origProject, origEnv :=
		getID, getName, getRef, getShowValue, getProject, getEnv
	t.Cleanup(func() {
		getID = origID
		getName = origName
		getRef = origRef
		getShowValue = origShow
		getProject = origProject
		getEnv = origEnv
	})
}

func TestRunGetRemote_S28_GetByIDWithValue(t *testing.T) {
	rc, done := getRemoteStub_S28(t)
	defer done()
	saveGetVars_S28(t)

	getID = 42
	getName = ""
	getRef = ""
	getShowValue = true

	err := runGetRemote(context.Background(), rc)
	require.NoError(t, err)
}

func TestRunGetRemote_S28_GetByIDWithoutValue(t *testing.T) {
	rc, done := getRemoteStub_S28(t)
	defer done()
	saveGetVars_S28(t)

	getID = 42
	getName = ""
	getRef = ""
	getShowValue = false

	err := runGetRemote(context.Background(), rc)
	require.NoError(t, err)
}

func TestRunGetRemote_S28_GetByNameNotFound(t *testing.T) {
	rc, done := getRemoteStub_S28(t)
	defer done()
	saveGetVars_S28(t)

	getID = 0
	getName = "nonexistent-secret"
	getRef = ""
	getShowValue = false
	getProject = 1
	getEnv = 1

	err := runGetRemote(context.Background(), rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRunGetRemote_S28_GetByNameFound(t *testing.T) {
	rc, done := getRemoteStub_S28(t)
	defer done()
	saveGetVars_S28(t)

	getID = 0
	getName = "db-pass" // matches the stub
	getRef = ""
	getShowValue = false
	getProject = 1
	getEnv = 1

	err := runGetRemote(context.Background(), rc)
	require.NoError(t, err)
}

func TestRunGetRemote_S28_GetByNameFoundWithValue(t *testing.T) {
	// When name is found and show-value=true we do a second GET for the value.
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		expiry := time.Now().Add(24 * time.Hour)
		s := models.SecretNode{
			ID: 42, Name: "db-pass", Type: "password", Status: "active",
			CreatedAt: time.Now(), UpdatedAt: time.Now(), Expiration: &expiry,
		}
		switch {
		case r.URL.Path == "/api/v1/secrets" || strings.HasPrefix(r.URL.RawQuery, "project_id"):
			body := map[string]interface{}{
				"data": map[string]interface{}{"secrets": []models.SecretNode{s}},
			}
			_ = json.NewEncoder(w).Encode(body)
		case r.URL.Query().Get("include_value") == "true":
			body := map[string]interface{}{
				"data": map[string]interface{}{"secret": s, "value": "my-secret-val"},
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	saveGetVars_S28(t)
	getID = 0
	getName = "db-pass"
	getRef = ""
	getShowValue = true
	getProject = 1
	getEnv = 1

	err := runGetRemote(context.Background(), rc)
	require.NoError(t, err)
}

// ── runUpdateRemote: error paths ──────────────────────────────────────────────

func saveUpdateVars_S28(t *testing.T) {
	t.Helper()
	origID, origValue, origFromFile, origType, origMaxReads, origExp, origClear, origInteractive :=
		updateID, updateValue, updateFromFile, updateType, updateMaxReads, updateExpiration, updateClearExp, updateInteractive
	t.Cleanup(func() {
		updateID = origID
		updateValue = origValue
		updateFromFile = origFromFile
		updateType = origType
		updateMaxReads = origMaxReads
		updateExpiration = origExp
		updateClearExp = origClear
		updateInteractive = origInteractive
	})
}

func TestRunUpdateRemote_S28_GETError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server error"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	saveUpdateVars_S28(t)
	updateID = 42
	updateValue = ""
	updateFromFile = ""
	updateExpiration = ""
	updateClearExp = false
	updateMaxReads = -1
	updateInteractive = false

	err := runUpdateRemote(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get current secret")
}

func TestRunUpdateRemote_S28_PUTError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"data":{"ID":42,"Name":"db-pass","Type":"password"}}`))
		case http.MethodPut:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"update failed"}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	saveUpdateVars_S28(t)
	updateID = 42
	updateValue = "new-value"
	updateFromFile = ""
	updateExpiration = ""
	updateClearExp = false
	updateMaxReads = -1
	updateInteractive = false

	err := runUpdateRemote(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update secret")
}

func TestRunUpdateRemote_S28_WithMaxReads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			maxReads := 5
			s := models.SecretNode{ID: 42, Name: "db-pass", Type: "password", MaxReads: &maxReads}
			body := map[string]interface{}{"data": s}
			_ = json.NewEncoder(w).Encode(body)
		case http.MethodPut:
			_, _ = w.Write([]byte(`{"data":{"ID":42,"Name":"db-pass","Type":"password"}}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	saveUpdateVars_S28(t)
	updateID = 42
	updateValue = ""
	updateFromFile = ""
	updateExpiration = ""
	updateClearExp = false
	updateMaxReads = 10 // > 0 → included in body
	updateInteractive = false

	err := runUpdateRemote(rc)
	require.NoError(t, err)
}

// ── runUpdate: updateID == 0 ──────────────────────────────────────────────────

func TestRunUpdate_S28_NoIDReturnsError(t *testing.T) {
	saveUpdateVars_S28(t)
	updateID = 0

	err := runUpdate(updateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

// ── buildUpdateRequest: fromFile error paths ──────────────────────────────────

func TestBuildUpdateRequest_S28_FromFileAbsolutePath(t *testing.T) {
	saveUpdateVars_S28(t)
	updateID = 5
	updateFromFile = "/etc/passwd" // absolute path — rejected
	updateValue = ""
	updateExpiration = ""
	updateClearExp = false
	updateMaxReads = -1

	_, err := buildUpdateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute paths not allowed")
}

func TestBuildUpdateRequest_S28_FromFileNotExist(t *testing.T) {
	saveUpdateVars_S28(t)
	updateID = 5
	updateFromFile = "nonexistent_file_s28.txt"
	updateValue = ""
	updateExpiration = ""
	updateClearExp = false
	updateMaxReads = -1

	_, err := buildUpdateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot stat file")
}

func TestBuildUpdateRequest_S28_FromFileSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	require.NoError(t, os.WriteFile(target, []byte("value"), 0o600))
	link := "symlink_s28_update.txt"
	// Create a symlink in the CWD (where buildUpdateRequest will look).
	_ = os.Remove(link) // clean up if exists
	require.NoError(t, os.Symlink(target, link))
	t.Cleanup(func() { _ = os.Remove(link) })

	saveUpdateVars_S28(t)
	updateID = 5
	updateFromFile = link
	updateValue = ""
	updateExpiration = ""
	updateClearExp = false
	updateMaxReads = -1

	_, err := buildUpdateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlinks not allowed")
}

func TestBuildUpdateRequest_S28_FromFileHappyPath(t *testing.T) {
	dir := t.TempDir()
	// Write to a relative path inside dir, then chdir there.
	fname := "secret_value_s28.txt"
	t.Chdir(dir)
	require.NoError(t, os.WriteFile(fname, []byte("loaded-from-file"), 0o600))

	saveUpdateVars_S28(t)
	updateID = 5
	updateFromFile = fname
	updateValue = ""
	updateExpiration = ""
	updateClearExp = false
	updateMaxReads = -1

	req, err := buildUpdateRequest()
	require.NoError(t, err)
	assert.Equal(t, []byte("loaded-from-file"), req.Value)
}

// ── fetchAccessLog: days > 0 (query-string branch) ───────────────────────────

func TestFetchAccessLog_S28_WithDaysParam(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":{"access_log":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	rows, err := fetchAccessLog(context.Background(), rc, 7, 14)
	require.NoError(t, err)
	assert.Empty(t, rows)
	assert.Contains(t, gotQuery, "days=14")
}

func TestFetchAccessLog_S28_ZeroDaysNoQuery(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		_, _ = w.Write([]byte(`{"data":{"access_log":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := fetchAccessLog(context.Background(), rc, 7, 0)
	require.NoError(t, err)
	assert.NotContains(t, gotPath, "days=")
}

// ── splitSecretRef ────────────────────────────────────────────────────────────

func TestSplitSecretRef_S28_ErrorBranches(t *testing.T) {
	_, _, err := splitSecretRef("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid reference")

	_, _, err = splitSecretRef("/name")
	require.Error(t, err)

	_, _, err = splitSecretRef("env/")
	require.Error(t, err)
}

func TestSplitSecretRef_S28_Happy(t *testing.T) {
	env, name, err := splitSecretRef("production/db-password")
	require.NoError(t, err)
	assert.Equal(t, "production", env)
	assert.Equal(t, "db-password", name)

	env2, name2, err := splitSecretRef("staging/path/to/secret")
	require.NoError(t, err)
	assert.Equal(t, "staging", env2)
	assert.Equal(t, "path/to/secret", name2)
}

// ── collectEntries error paths ────────────────────────────────────────────────

func saveImportVars_S28(t *testing.T) {
	t.Helper()
	origSource, origFile, origFormat := importSource, importFile, importFormat
	t.Cleanup(func() {
		importSource = origSource
		importFile = origFile
		importFormat = origFormat
	})
}

func TestCollectEntries_S28_BothSourceAndFile(t *testing.T) {
	saveImportVars_S28(t)
	importSource = "aws"
	importFile = "some.json"

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestCollectEntries_S28_NeitherSourceNorFile(t *testing.T) {
	saveImportVars_S28(t)
	importSource = ""
	importFile = ""

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "specify a source")
}

func TestCollectEntries_S28_FileNotFound(t *testing.T) {
	saveImportVars_S28(t)
	importSource = ""
	importFile = "/nonexistent/secrets.json"
	importFormat = "json"

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot open file")
}

// ── runGetEmbedded: getName not found after exhausting pages ──────────────────

func TestRunGetEmbedded_S28_NameNotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := "storage:\n  type: local\n  database:\n    path: ./secrets_s28.db\n"
	if err := os.WriteFile("keyorix.yaml", []byte(cfg), 0o600); err != nil {
		t.Skip("could not write keyorix.yaml:", err)
	}
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	saveGetVars_S28(t)
	getID = 0
	getName = "definitely-does-not-exist-s28"
	getRef = ""
	getShowValue = false
	getProject = 1
	getEnv = 1

	err := runGetEmbedded(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── runVersions: missing ID ───────────────────────────────────────────────────

func saveVersionsVars_S28(t *testing.T) {
	t.Helper()
	origID, origFormat := versionsID, versionsFormat
	t.Cleanup(func() {
		versionsID = origID
		versionsFormat = origFormat
	})
}

func TestRunVersions_S28_MissingID(t *testing.T) {
	saveVersionsVars_S28(t)
	versionsID = 0

	err := runVersions(versionsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

// ── runDelete: no flags → error ───────────────────────────────────────────────

func saveDeleteVars_S28(t *testing.T) {
	t.Helper()
	origID, origName, origNS, origEnv, origForce :=
		deleteID, deleteName, deleteNS, deleteEnv, deleteForce
	t.Cleanup(func() {
		deleteID = origID
		deleteName = origName
		deleteNS = origNS
		deleteEnv = origEnv
		deleteForce = origForce
	})
}

func TestRunDelete_S28_NeitherIDNorName(t *testing.T) {
	saveDeleteVars_S28(t)
	deleteID = 0
	deleteName = ""

	err := runDelete(deleteCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

// ── runRender: template read error + no server ────────────────────────────────

func TestRunRender_S28_TemplateFileNotFound(t *testing.T) {
	// When the template file doesn't exist, runRender should return an error.
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origOutput := renderOutput
	t.Cleanup(func() { renderOutput = origOutput })
	renderOutput = ""

	err := runRender(renderCmd, []string{"/nonexistent/template.tpl"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read template")
}

// ── noteSuffix coverage (blank + non-blank) ───────────────────────────────────

func TestNoteSuffix_S28(t *testing.T) {
	assert.Equal(t, "", noteSuffix(""))
	assert.Equal(t, "", noteSuffix("   "))
	assert.Equal(t, "  — my note", noteSuffix("my note"))
}

// ── plural coverage ───────────────────────────────────────────────────────────

func TestPlural_S28(t *testing.T) {
	assert.Equal(t, "", plural(1))
	assert.Equal(t, "s", plural(0))
	assert.Equal(t, "s", plural(2))
}

// ── printDependencies: empty vs populated ─────────────────────────────────────

func TestPrintDependencies_S28_Empty(t *testing.T) {
	v := &depsView{SecretID: 1}
	printDependencies(v) // must not panic
}

func TestPrintDependencies_S28_WithEntries(t *testing.T) {
	v := &depsView{
		SecretID: 1,
		DependsOn: []depEdgeView{
			{ID: 10, SecretID: 2, SecretName: "db-pass", Note: "derives from"},
		},
		Dependents: []depEdgeView{
			{ID: 11, SecretID: 3, SecretName: "edge-cert", Note: ""},
		},
	}
	printDependencies(v) // must not panic
}

// ── printImpact: empty vs populated ──────────────────────────────────────────

func TestPrintImpact_S28_NoAffected(t *testing.T) {
	v := &impactView{SecretID: 1, SecretName: "root-secret"}
	printImpact(v) // must not panic ("affects no other secrets" branch)
}

func TestPrintImpact_S28_WithAffected(t *testing.T) {
	v := &impactView{
		SecretID:   1,
		SecretName: "root-secret",
		Affected: []impactedView{
			{SecretID: 2, SecretName: "child", Depth: 1},
			{SecretID: 3, SecretName: "grandchild", Depth: 2},
		},
	}
	printImpact(v) // must not panic
}

// ── fetchDependencies / fetchImpact: error paths ──────────────────────────────

func TestFetchDependencies_S28_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := fetchDependencies(context.Background(), rc, 999)
	require.Error(t, err)
}

func TestFetchImpact_S28_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := fetchImpact(context.Background(), rc, 999)
	require.Error(t, err)
}

// ── resolveProjectIDParam: not found ─────────────────────────────────────────

func TestResolveProjectIDParam_S28_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"prod"}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := resolveProjectIDParam(context.Background(), rc, "nonexistent-project")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestResolveProjectIDParam_S28_Empty(t *testing.T) {
	// Empty projectName → returns "", nil immediately.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not make any HTTP request when projectName is empty")
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	param, err := resolveProjectIDParam(context.Background(), rc, "")
	require.NoError(t, err)
	assert.Equal(t, "", param)
}

func TestResolveProjectIDParam_S28_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":7,"name":"my-project"}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	param, err := resolveProjectIDParam(context.Background(), rc, "my-project")
	require.NoError(t, err)
	assert.Equal(t, "&project_id=7", param)
}
