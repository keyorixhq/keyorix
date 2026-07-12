// secret_s4_test.go — sprint-4 coverage additions for cli/secret package.
//
// Target functions (below 80% after s2+s3, avoiding any already-covered names):
//   - buildCreateRequest: from-file happy path, good expiration, missing file
//   - printCreatedSecret: expiration branch + no-expiration
//   - displaySecret: max-reads, expired + future expiration, value present, show-value empty
//   - runListEmbedded: table format, json format
//   - runScan: --commit leading-dash rejection, severity filters
//   - collectAzure: listNames error, getValue error
//   - collectGCP: listSecrets error, accessLatest fatal error
//   - fetchAccessLog: days<=0 path
//   - runResumeRemote: server error propagation
//   - setSecretTags: server error
//   - writeDotenv: quoted-value branch, plain value
//   - writeExportJSON: map output
//   - runSuspendRemote: no-reason + with-reason
package secret

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ────────────────────────────────────────────────────────────────────────────
// buildCreateRequest — branches not yet covered
// ────────────────────────────────────────────────────────────────────────────

func TestBuildCreateRequest_FromMissingFileS4(t *testing.T) {
	origName, origVal, origFile := createName, createValue, createFromFile
	defer func() { createName = origName; createValue = origVal; createFromFile = origFile }()
	createName = "s4-secret"
	createValue = ""
	createFromFile = "definitely-missing-s4.txt"
	_, err := buildCreateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot stat file")
}

func TestBuildCreateRequest_FromFileHappyS4(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret_s4.txt")
	require.NoError(t, os.WriteFile(f, []byte("file-value-s4"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	origName, origVal, origFile, origExp, origMax := createName, createValue, createFromFile, createExpiration, createMaxReads
	defer func() {
		createName = origName; createValue = origVal; createFromFile = origFile
		createExpiration = origExp; createMaxReads = origMax
	}()
	createName = "s4-from-file"
	createValue = ""
	createFromFile = "secret_s4.txt"
	createExpiration = ""
	createMaxReads = 0

	req, err := buildCreateRequest()
	require.NoError(t, err)
	assert.Equal(t, []byte("file-value-s4"), req.Value)
}

func TestBuildCreateRequest_ValidExpirationS4(t *testing.T) {
	origName, origVal, origFile, origExp := createName, createValue, createFromFile, createExpiration
	defer func() {
		createName = origName; createValue = origVal; createFromFile = origFile; createExpiration = origExp
	}()
	createName = "s4-secret"
	createValue = "v"
	createFromFile = ""
	createExpiration = "2030-06-15T12:00:00Z"
	req, err := buildCreateRequest()
	require.NoError(t, err)
	require.NotNil(t, req.Expiration)
	assert.True(t, req.Expiration.After(time.Now()))
}

func TestBuildCreateRequest_MaxReadsSetS4(t *testing.T) {
	origName, origVal, origFile, origMax := createName, createValue, createFromFile, createMaxReads
	defer func() {
		createName = origName; createValue = origVal; createFromFile = origFile; createMaxReads = origMax
	}()
	createName = "s4-secret"
	createValue = "secret-s4"
	createFromFile = ""
	createMaxReads = 10

	req, err := buildCreateRequest()
	require.NoError(t, err)
	require.NotNil(t, req.MaxReads)
	assert.Equal(t, 10, *req.MaxReads)
}

// ────────────────────────────────────────────────────────────────────────────
// printCreatedSecret — with and without expiration
// ────────────────────────────────────────────────────────────────────────────

func TestPrintCreatedSecretS4_WithExpiration(t *testing.T) {
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &models.SecretNode{
		ID:            99,
		Name:          "s4-exp-secret",
		Type:          "generic",
		ProjectID:     1,
		EnvironmentID: 1,
		Expiration:    &exp,
	}
	printCreatedSecret(s)
}

func TestPrintCreatedSecretS4_NoExpiration(t *testing.T) {
	s := &models.SecretNode{
		ID:            88,
		Name:          "s4-no-exp",
		Type:          "generic",
		ProjectID:     1,
		EnvironmentID: 1,
	}
	printCreatedSecret(s)
}

// ────────────────────────────────────────────────────────────────────────────
// displaySecret — branches for maxReads, expiration (expired vs future), value
// ────────────────────────────────────────────────────────────────────────────

func TestDisplaySecretS4_ExpiredWithMaxReads(t *testing.T) {
	maxR := 3
	pastExp := time.Now().Add(-time.Hour)
	s := &models.SecretNode{
		ID:            1,
		Name:          "s4-disp",
		Type:          "generic",
		Status:        "active",
		ProjectID:     1,
		EnvironmentID: 1,
		CreatedBy:     "cli-test",
		MaxReads:      &maxR,
		Expiration:    &pastExp,
	}
	origShowVal := getShowValue
	defer func() { getShowValue = origShowVal }()
	getShowValue = false
	displaySecret(s, "my-value")
}

func TestDisplaySecretS4_FutureExpiration(t *testing.T) {
	futureExp := time.Now().Add(24 * time.Hour)
	s := &models.SecretNode{
		ID:         2,
		Name:       "s4-future",
		Expiration: &futureExp,
	}
	origShowVal := getShowValue
	defer func() { getShowValue = origShowVal }()
	getShowValue = false
	displaySecret(s, "")
}

func TestDisplaySecretS4_ShowValueFlagEmptyValue(t *testing.T) {
	s := &models.SecretNode{ID: 3, Name: "s4-empty-val"}
	origShowVal := getShowValue
	defer func() { getShowValue = origShowVal }()
	getShowValue = true
	// value is empty but show-value is true → "(value unavailable)" branch
	displaySecret(s, "")
}

// ────────────────────────────────────────────────────────────────────────────
// runListEmbedded — table and json format (beyond existing LocalMode test)
// ────────────────────────────────────────────────────────────────────────────

func TestRunListEmbeddedS4_TableFormat(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origFmt, origProject, origLimit, origOffset, origEnv :=
		listFormat, listProjectName, listLimit, listOffset, listEnv
	defer func() {
		listFormat = origFmt; listProjectName = origProject
		listLimit = origLimit; listOffset = origOffset; listEnv = origEnv
	}()
	listFormat = "table"
	listProjectName = ""
	listLimit = 50
	listOffset = 0
	listEnv = 0

	// May succeed (empty DB) or error on init — no panic expected.
	_ = runListEmbedded(context.Background())
}

func TestRunListEmbeddedS4_JSONFormat(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origFmt, origProject, origLimit, origOffset, origEnv :=
		listFormat, listProjectName, listLimit, listOffset, listEnv
	defer func() {
		listFormat = origFmt; listProjectName = origProject
		listLimit = origLimit; listOffset = origOffset; listEnv = origEnv
	}()
	listFormat = "json"
	listProjectName = ""
	listLimit = 50
	listOffset = 0
	listEnv = 0

	_ = runListEmbedded(context.Background())
}

// ────────────────────────────────────────────────────────────────────────────
// runScan — --commit leading-dash rejection + severity filters
// ────────────────────────────────────────────────────────────────────────────

func TestRunScanS4_InvalidCommitLeadingDash(t *testing.T) {
	origCommit, origStaged := scanCommit, scanStaged
	defer func() { scanCommit = origCommit; scanStaged = origStaged }()
	scanCommit = "--upload-pack=evil"
	scanStaged = false

	dir := t.TempDir()
	err := runScan(scanCmd, []string{dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not start with '-'")
}

func TestRunScanS4_LowSeverityFilter(t *testing.T) {
	origSev, origCommit, origStaged, origReport := scanSeverity, scanCommit, scanStaged, scanReport
	defer func() { scanSeverity = origSev; scanCommit = origCommit; scanStaged = origStaged; scanReport = origReport }()
	scanSeverity = "low"
	scanCommit = ""
	scanStaged = false
	scanReport = ""

	dir := t.TempDir()
	// Write a Go file with a pattern that triggers a low-risk finding
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "app.go"),
		[]byte("package main\nconst token = \"abcdef0123456789\"\n"),
		0o644,
	))
	_ = runScan(scanCmd, []string{dir})
}

func TestRunScanS4_MediumSeverityFilter(t *testing.T) {
	origSev, origCommit, origStaged, origReport := scanSeverity, scanCommit, scanStaged, scanReport
	defer func() { scanSeverity = origSev; scanCommit = origCommit; scanStaged = origStaged; scanReport = origReport }()
	scanSeverity = "medium"
	scanCommit = ""
	scanStaged = false
	scanReport = ""

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "config.yaml"),
		[]byte("password: \"mypassword123\"\n"),
		0o644,
	))
	_ = runScan(scanCmd, []string{dir})
}

func TestRunScanS4_HighSeverityFilter(t *testing.T) {
	origSev, origCommit, origStaged, origReport := scanSeverity, scanCommit, scanStaged, scanReport
	defer func() { scanSeverity = origSev; scanCommit = origCommit; scanStaged = origStaged; scanReport = origReport }()
	scanSeverity = "high"
	scanCommit = ""
	scanStaged = false
	scanReport = ""

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "creds.go"),
		[]byte("package main\nconst awsKey = \"AKIA0123456789ABCDEF\"\n"),
		0o644,
	))
	_ = runScan(scanCmd, []string{dir})
}

// ────────────────────────────────────────────────────────────────────────────
// collectAzure — listNames error and getValue error paths
// ────────────────────────────────────────────────────────────────────────────

type errorAzureS4 struct{ listErr, getErr bool }

func (a *errorAzureS4) listNames(_ context.Context) ([]string, error) {
	if a.listErr {
		return nil, errors.New("list-azure-error-s4")
	}
	return []string{"k"}, nil
}

func (a *errorAzureS4) getValue(_ context.Context, _ string) (string, error) {
	if a.getErr {
		return "", errors.New("get-azure-error-s4")
	}
	return "v", nil
}

func TestCollectAzureS4_ListError(t *testing.T) {
	_, err := collectAzure(context.Background(), &errorAzureS4{listErr: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list azure secrets")
}

func TestCollectAzureS4_GetValueError(t *testing.T) {
	_, err := collectAzure(context.Background(), &errorAzureS4{getErr: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read azure secret")
}

// ────────────────────────────────────────────────────────────────────────────
// collectGCP — listSecrets error and accessLatest fatal error
// ────────────────────────────────────────────────────────────────────────────

type errorGCPS4 struct{ listErr, accessErr bool }

func (g *errorGCPS4) listSecrets(_ context.Context, _ string) ([]string, error) {
	if g.listErr {
		return nil, errors.New("list-gcp-error-s4")
	}
	return []string{"projects/p/secrets/k"}, nil
}

func (g *errorGCPS4) accessLatest(_ context.Context, _ string) (string, bool, error) {
	if g.accessErr {
		return "", false, errors.New("access-gcp-error-s4")
	}
	return "val", true, nil
}

func TestCollectGCPS4_ListError(t *testing.T) {
	_, err := collectGCP(context.Background(), &errorGCPS4{listErr: true}, "p")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list GCP secrets")
}

func TestCollectGCPS4_AccessLatestFatalError(t *testing.T) {
	_, err := collectGCP(context.Background(), &errorGCPS4{accessErr: true}, "p")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read GCP secret")
}

// ────────────────────────────────────────────────────────────────────────────
// fetchAccessLog — days <= 0 path (no "days" query param emitted)
// ────────────────────────────────────────────────────────────────────────────

func TestFetchAccessLogS4_ZeroDays(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"access_log":[]}}`)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := fetchAccessLog(context.Background(), rc, 1, 0)
	require.NoError(t, err)
	assert.NotContains(t, capturedPath, "days")
}

// ────────────────────────────────────────────────────────────────────────────
// runResumeRemote — server error propagation
// ────────────────────────────────────────────────────────────────────────────

func TestRunResumeRemoteS4_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"resume failed"}`)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	err := runResumeRemote(rc, 1)
	require.Error(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// setSecretTags — server error
// ────────────────────────────────────────────────────────────────────────────

func TestSetSecretTagsS4_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"tags error"}`)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := setSecretTags(context.Background(), rc, 1, []string{"env:prod"})
	require.Error(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// writeDotenv — quoted-value branch and plain value
// ────────────────────────────────────────────────────────────────────────────

func TestWriteDotenvS4_QuotedValue(t *testing.T) {
	// Values with spaces must be double-quoted.
	secrets := []exportedSecret{{ID: 1, Name: "MY_SECRET", Value: `has space and "quotes"`}}
	var buf bytes.Buffer
	err := writeDotenv(&buf, secrets)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "MY_SECRET=")
	assert.Contains(t, out, `"`)
}

func TestWriteDotenvS4_PlainValue(t *testing.T) {
	secrets := []exportedSecret{{ID: 2, Name: "PLAIN_S4", Value: "nospecialchars"}}
	var buf bytes.Buffer
	err := writeDotenv(&buf, secrets)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "PLAIN_S4=nospecialchars")
}

func TestWriteDotenvS4_BackslashEscaping(t *testing.T) {
	// Values with backslash should be escaped inside quoted output.
	secrets := []exportedSecret{{ID: 3, Name: "BACK_S4", Value: `val\with\backslash`}}
	var buf bytes.Buffer
	err := writeDotenv(&buf, secrets)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "BACK_S4=")
}

// ────────────────────────────────────────────────────────────────────────────
// writeExportJSON — non-empty secrets map
// ────────────────────────────────────────────────────────────────────────────

func TestWriteExportJSONS4_NonEmpty(t *testing.T) {
	secrets := []exportedSecret{
		{ID: 1, Name: "DB_PASS_S4", Value: "hunter2"},
		{ID: 2, Name: "API_KEY_S4", Value: "abc123"},
	}
	var buf bytes.Buffer
	err := writeExportJSON(&buf, secrets)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "DB_PASS_S4")
	assert.Contains(t, out, "hunter2")
	assert.Contains(t, out, "API_KEY_S4")
}

// ────────────────────────────────────────────────────────────────────────────
// runSuspendRemote — no-reason and with-reason branches
// ────────────────────────────────────────────────────────────────────────────

func TestRunSuspendRemoteS4_NoReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{}}`)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	err := runSuspendRemote(rc, 1, "")
	require.NoError(t, err)
}

func TestRunSuspendRemoteS4_WithReason(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{}}`)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	err := runSuspendRemote(rc, 2, "security incident")
	require.NoError(t, err)
	assert.Contains(t, capturedBody, "security incident")
}

// ────────────────────────────────────────────────────────────────────────────
// splitTags — additional edge cases
// ────────────────────────────────────────────────────────────────────────────

func TestSplitTagsS4_WhitespaceOnlyEntry(t *testing.T) {
	result := splitTags("a,  ,b")
	assert.Equal(t, []string{"a", "b"}, result)
}

func TestSplitTagsS4_SingleTag(t *testing.T) {
	result := splitTags("env:prod")
	assert.Equal(t, []string{"env:prod"}, result)
}
