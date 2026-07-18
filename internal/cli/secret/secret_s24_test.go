// secret_s24_test.go — coverage sprint S24.
//
// Targets functions with <90% coverage that have pure-logic branches testable
// without httptest/network and that are NOT already covered by s2–s23 tests:
//
//   - buildCreateRequest: absolute-path rejection, symlink rejection,
//     from-file success, expiration parse error (unique variant names)
//   - buildUpdateRequest: from-file absolute rejection, from-file success
//   - collectEntries: both-set error, neither-set error, file-not-exist
//   - runScan: invalid-severity error, severity-filter branch, scanImport path
//   - splitSecretRef: happy path + error variants (unique names)
//   - displayVersionsTable: with versions + unknown algorithm
//   - sanitizeForTerminal: control-char stripping (unique names)
//   - runVersions: zero-id guard (unique name)
//   - runUpdate: zero-ID guard (unique name)
//   - runListEmbedded: unsupported format error
//   - runGetEmbedded: getID=0 + getName → not-found
//   - formatBytes: small/KB/MB (unique names)
package secret

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── buildCreateRequest ────────────────────────────────────────────────────────

func TestBuildCreateRequest_FromFile_AbsolutePathRejected(t *testing.T) {
	origFromFile, origName, origValue := createFromFile, createName, createValue
	t.Cleanup(func() { createFromFile = origFromFile; createName = origName; createValue = origValue })
	createName = "my-secret" // must be non-empty to get past name check
	createValue = ""
	createFromFile = "/etc/passwd"

	_, err := buildCreateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute paths are not allowed")
}

func TestBuildCreateRequest_FromFile_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.txt")
	require.NoError(t, os.WriteFile(realFile, []byte("secret"), 0o600))
	linkFile := filepath.Join(dir, "link.txt")
	require.NoError(t, os.Symlink(realFile, linkFile))

	t.Chdir(dir)

	origFromFile, origName, origValue := createFromFile, createName, createValue
	t.Cleanup(func() {
		createFromFile = origFromFile
		createName = origName
		createValue = origValue
	})
	createFromFile = "link.txt"
	createName = "test-secret"
	createValue = ""

	_, err := buildCreateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlinks are not allowed")
}

func TestBuildCreateRequest_FromFile_Success_S24(t *testing.T) {
	dir := t.TempDir()
	valFile := filepath.Join(dir, "value.txt")
	require.NoError(t, os.WriteFile(valFile, []byte("file-secret-value"), 0o600))

	t.Chdir(dir)

	origFromFile, origName, origValue, origMaxReads, origExp := createFromFile, createName, createValue, createMaxReads, createExpiration
	t.Cleanup(func() {
		createFromFile = origFromFile
		createName = origName
		createValue = origValue
		createMaxReads = origMaxReads
		createExpiration = origExp
	})
	createFromFile = "value.txt"
	createName = "my-secret"
	createValue = ""
	createMaxReads = 5 // exercises the MaxReads branch
	createExpiration = ""

	req, err := buildCreateRequest()
	require.NoError(t, err)
	assert.Equal(t, "my-secret", req.Name)
	assert.Equal(t, []byte("file-secret-value"), req.Value)
	require.NotNil(t, req.MaxReads)
	assert.Equal(t, 5, *req.MaxReads)
}

func TestBuildCreateRequest_ExpirationParseError_S24(t *testing.T) {
	origName, origValue, origFromFile, origExp := createName, createValue, createFromFile, createExpiration
	t.Cleanup(func() {
		createName = origName
		createValue = origValue
		createFromFile = origFromFile
		createExpiration = origExp
	})
	createName = "my-secret"
	createValue = "the-value"
	createFromFile = ""
	createExpiration = "not-a-valid-rfc3339"

	_, err := buildCreateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid expiration format")
}

// ── buildUpdateRequest ────────────────────────────────────────────────────────

func TestBuildUpdateRequest_FromFile_AbsolutePathRejected_S24(t *testing.T) {
	origFromFile, origID := updateFromFile, updateID
	t.Cleanup(func() { updateFromFile = origFromFile; updateID = origID })
	updateFromFile = "/etc/passwd"
	updateID = 42

	_, err := buildUpdateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute paths not allowed")
}

func TestBuildUpdateRequest_FromFile_Success_S24(t *testing.T) {
	dir := t.TempDir()
	valFile := filepath.Join(dir, "newval.txt")
	require.NoError(t, os.WriteFile(valFile, []byte("updated-value"), 0o600))
	t.Chdir(dir)

	origFromFile, origID, origValue, origType, origMaxReads, origExp, origClear := updateFromFile, updateID, updateValue, updateType, updateMaxReads, updateExpiration, updateClearExp
	t.Cleanup(func() {
		updateFromFile = origFromFile
		updateID = origID
		updateValue = origValue
		updateType = origType
		updateMaxReads = origMaxReads
		updateExpiration = origExp
		updateClearExp = origClear
	})
	updateFromFile = "newval.txt"
	updateID = 10
	updateValue = ""
	updateType = ""
	updateMaxReads = -1
	updateExpiration = ""
	updateClearExp = false

	req, err := buildUpdateRequest()
	require.NoError(t, err)
	assert.Equal(t, []byte("updated-value"), req.Value)
}

// ── collectEntries ────────────────────────────────────────────────────────────

func TestCollectEntries_BothSourceAndFileError_S24(t *testing.T) {
	origSource, origFile := importSource, importFile
	t.Cleanup(func() { importSource = origSource; importFile = origFile })
	importSource = "vault"
	importFile = "/some/file.env"

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestCollectEntries_NeitherSourceNorFileError_S24(t *testing.T) {
	origSource, origFile := importSource, importFile
	t.Cleanup(func() { importSource = origSource; importFile = origFile })
	importSource = ""
	importFile = ""

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "specify a source")
}

func TestCollectEntries_FileNotExistError_S24(t *testing.T) {
	origSource, origFile, origFormat := importSource, importFile, importFormat
	t.Cleanup(func() { importSource = origSource; importFile = origFile; importFormat = origFormat })
	importSource = ""
	importFile = "/no/such/file-s24.env"
	importFormat = "dotenv"

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot open file")
}

// ── runScan ───────────────────────────────────────────────────────────────────

func TestRunScan_InvalidSeverity_S24(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	origSeverity := scanSeverity
	t.Cleanup(func() { scanSeverity = origSeverity })
	scanSeverity = "critical" // not one of low/medium/high

	err := runScan(scanCmd, []string{dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --severity")
}

func TestRunScan_SeverityFilter_HitsHighAndFilters_S24(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Write a file with an AWS key (high risk).
	require.NoError(t, os.WriteFile(filepath.Join(dir, "creds.go"), []byte(`
package main
const awsKey = "AKIAIOSFODNN7EXAMPLE"
`), 0o600))

	origSeverity, origStaged := scanSeverity, scanStaged
	t.Cleanup(func() { scanSeverity = origSeverity; scanStaged = origStaged })
	scanSeverity = "high"
	scanStaged = false

	err := runScan(scanCmd, []string{dir})
	assert.NoError(t, err)
}

func TestRunScan_ScanImportPath_S24(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`api_key = "STRIPE_KEY_EXAMPLE_sk_live_XXXX"`), 0o600))

	origImport, origStaged, origReport := scanImport, scanStaged, scanReport
	t.Cleanup(func() { scanImport = origImport; scanStaged = origStaged; scanReport = origReport })
	scanImport = true
	scanStaged = false
	scanReport = ""

	// Should not error — the scan-import path just prints a readiness message.
	err := runScan(scanCmd, []string{dir})
	assert.NoError(t, err)
}

// ── splitSecretRef: unique-name variants ─────────────────────────────────────

func TestSplitSecretRef_HappyPath_S24(t *testing.T) {
	env, name, err := splitSecretRef("production/my-db-pass")
	require.NoError(t, err)
	assert.Equal(t, "production", env)
	assert.Equal(t, "my-db-pass", name)
}

func TestSplitSecretRef_Empty_S24(t *testing.T) {
	_, _, err := splitSecretRef("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid reference")
}

// ── displayVersionsTable: with versions + unknown algorithm ──────────────────

func TestDisplayVersionsTable_WithVersionsUnknownAlgorithm_S24(t *testing.T) {
	secret := &models.SecretNode{ID: 3, Name: "my-key", Type: "generic"}
	versions := []*models.SecretVersion{
		{
			ID:            20,
			VersionNumber: 1,
			ReadCount:     0,
			CreatedAt:     time.Now(),
		},
	}
	out := captureStdout(t, func() {
		displayVersionsTable(secret, versions)
	})
	assert.Contains(t, out, "my-key")
	assert.Contains(t, out, "Unknown")
}

// ── sanitizeForTerminal ───────────────────────────────────────────────────────

func TestSanitizeForTerminal_ControlCharsDropped_S24(t *testing.T) {
	// ESC (0x1b) and NUL (0x00) are control chars — dropped.
	// The visible chars "[31m" and "null" that follow remain.
	input := "safe\x1b[31mcolored\x00null"
	out := sanitizeForTerminal(input)
	// ESC and NUL are stripped; the surrounding printable chars survive.
	assert.NotContains(t, out, "\x1b")
	assert.NotContains(t, out, "\x00")
	assert.Contains(t, out, "safe")
	assert.Contains(t, out, "colored")
}

func TestSanitizeForTerminal_TabReplacedWithSpace_S24(t *testing.T) {
	out := sanitizeForTerminal("col1\tcol2")
	assert.Equal(t, "col1 col2", out)
}

func TestSanitizeForTerminal_PlainStringUnchanged_S24(t *testing.T) {
	out := sanitizeForTerminal("hello world")
	assert.Equal(t, "hello world", out)
}

// ── runVersions: zero-id guard (unique suffix) ────────────────────────────────

func TestRunVersions_ZeroIDError_S24(t *testing.T) {
	origID := versionsID
	t.Cleanup(func() { versionsID = origID })
	versionsID = 0

	err := runVersions(versionsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

// ── runUpdate: zero-ID guard (unique suffix) ──────────────────────────────────

func TestRunUpdate_ZeroIDError_S24(t *testing.T) {
	origID := updateID
	t.Cleanup(func() { updateID = origID })
	updateID = 0

	err := runUpdate(updateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

// ── runListEmbedded: unsupported format error (unique name) ──────────────────

func TestRunListEmbedded_UnsupportedFormat_S24(t *testing.T) {
	// Use a temp dir with a valid keyorix.yaml so InitializeCoreService works.
	t.Chdir(t.TempDir())
	cfg := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"
	if err := os.WriteFile("keyorix.yaml", []byte(cfg), 0o600); err != nil {
		t.Skip("could not write keyorix.yaml:", err)
	}
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origFormat, origLimit := listFormat, listLimit
	t.Cleanup(func() { listFormat = origFormat; listLimit = origLimit })
	listFormat = "xml" // unsupported
	listLimit = 50     // avoid divide-by-zero in (listOffset/listLimit)+1

	err := runListEmbedded(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

// ── runGetEmbedded: getID=0 and getName="" → not-found ───────────────────────

func TestRunGetEmbedded_NoIDNoName_S24(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"
	if err := os.WriteFile("keyorix.yaml", []byte(cfg), 0o600); err != nil {
		t.Skip("could not write keyorix.yaml:", err)
	}
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origName, origRef := getID, getName, getRef
	t.Cleanup(func() { getID = origID; getName = origName; getRef = origRef })
	getID = 0
	getName = "nonexistent-s24-secret"
	getRef = ""

	err := runGetEmbedded(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── formatBytes coverage (unique names) ────────────────────────────────────────

func TestFormatBytes_SmallValue_S24(t *testing.T) {
	out := formatBytes(512)
	assert.Contains(t, out, "B")
}

func TestFormatBytes_Kilobytes_S24(t *testing.T) {
	out := formatBytes(2048)
	assert.Contains(t, out, "KB")
}

func TestFormatBytes_Megabytes_S24(t *testing.T) {
	out := formatBytes(2 * 1024 * 1024)
	assert.Contains(t, out, "MB")
}
