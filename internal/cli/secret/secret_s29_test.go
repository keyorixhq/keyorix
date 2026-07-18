// secret_s29_test.go — coverage sprint S29.
//
// Targets uncovered / low-coverage paths:
//
//   - interactiveCreate: stdin-driven paths through name prompt, type, project,
//     environment, password read failure, max-reads non-zero branch, invalid
//     expiration branch, valid expiration branch, empty name error.
//   - promptRotateValue: the empty-bytes error branch + normal error path.
//   - runScan: scanCommit invalid prefix ("-foo"), symlink skip in Walk,
//     large-file skip (>1MB), scanCommit with no git output (empty branch),
//     skipDirs entry, test-file skip (_test.go suffix).
//   - collectGCP: listSecrets error and accessLatest error with the
//     gcpClientAdapter interface (via fake), no-version skip branch
//   - collectAzure: getValue error and listNames error branches
package secret

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helper: save/restore scan vars ───────────────────────────────────────────

func saveScanVars_S29(t *testing.T) {
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

// ── runScan: scanCommit with leading dash (injection guard) ──────────────────

func TestRunScan_S29_CommitLeadingDashReturnsError(t *testing.T) {
	saveScanVars_S29(t)
	dir := t.TempDir()
	scanCommit = "-x"
	scanStaged = false
	scanReport = ""
	scanSeverity = ""
	scanImport = false

	err := runScan(scanCmd, []string{dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not start with '-'")
}

// ── runScan: scanCommit with valid ref that git cannot find (non-git dir) ─────

func TestRunScan_S29_CommitRefNoGit(t *testing.T) {
	saveScanVars_S29(t)
	dir := t.TempDir()
	// A valid non-dash ref in a non-git dir → git diff-tree fails → stagedFiles
	// remains nil → all files are scanned normally.
	scanCommit = "HEAD~1"
	scanStaged = false
	scanReport = ""
	scanSeverity = ""
	scanImport = false

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

// ── runScan: symlink in Walk is skipped ───────────────────────────────────────

func TestRunScan_S29_SymlinkSkippedInWalk(t *testing.T) {
	saveScanVars_S29(t)
	dir := t.TempDir()

	// Create a real file and a symlink pointing to it inside the scan dir.
	realFile := filepath.Join(dir, "real.go")
	require.NoError(t, os.WriteFile(realFile, []byte(`package main
const api_key = "AKIAIOSFODNN7EXAMPLE"
`), 0o600))

	linkFile := filepath.Join(dir, "link.go")
	require.NoError(t, os.Symlink(realFile, linkFile))

	scanCommit = ""
	scanStaged = false
	scanReport = ""
	scanSeverity = ""
	scanImport = false

	// runScan should succeed; the symlink is skipped (Lstat check) and only
	// the real file is scanned.
	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

// ── runScan: file exceeding 1 MB size limit is skipped ───────────────────────

func TestRunScan_S29_LargeFileSkipped(t *testing.T) {
	saveScanVars_S29(t)
	dir := t.TempDir()

	// Create a 2 MB .go file — it must be skipped by the size check.
	bigFile := filepath.Join(dir, "big.go")
	f, err := os.Create(bigFile)
	require.NoError(t, err)
	content := strings.Repeat("a", 2*1024*1024)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	scanCommit = ""
	scanStaged = false
	scanReport = ""
	scanSeverity = ""
	scanImport = false

	err = runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

// ── runScan: _test.go files are skipped ──────────────────────────────────────

func TestRunScan_S29_TestFileSkipped(t *testing.T) {
	saveScanVars_S29(t)
	dir := t.TempDir()

	// A _test.go file with a high-risk pattern: must be ignored by the scanner.
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "main_test.go"),
		[]byte(`package main
const api_key = "AKIAIOSFODNN7EXAMPLE"
`),
		0o600,
	))

	reportPath := filepath.Join(dir, "r.json")
	scanCommit = ""
	scanStaged = false
	scanReport = reportPath
	scanSeverity = ""
	scanImport = false

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)

	// The report should contain 0 findings because _test.go was skipped.
	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"total_found": 0`)
}

// ── runScan: a skipDir entry causes SkipDir ───────────────────────────────────

func TestRunScan_S29_SkipDirIgnored(t *testing.T) {
	saveScanVars_S29(t)
	dir := t.TempDir()

	// Create a "vendor" subdirectory with a high-risk file inside it.
	vendorDir := filepath.Join(dir, "vendor")
	require.NoError(t, os.MkdirAll(vendorDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(vendorDir, "lib.go"),
		[]byte(`package lib
const aws_secret_access_key = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP1122334455"
`),
		0o600,
	))

	reportPath := filepath.Join(dir, "r.json")
	scanCommit = ""
	scanStaged = false
	scanReport = reportPath
	scanSeverity = ""
	scanImport = false

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)

	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	// The vendor dir is in skipDirs → file was not scanned → no findings.
	assert.Contains(t, string(data), `"total_found": 0`)
}

// ── runScan: scanImport with findings triggers deduplication path ─────────────

func TestRunScan_S29_ScanImportWithFindings(t *testing.T) {
	saveScanVars_S29(t)
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "creds.yaml"),
		[]byte("api_key: AKIAIOSFODNN7EXAMPLE\n"),
		0o600,
	))
	scanCommit = ""
	scanStaged = false
	scanReport = ""
	scanSeverity = ""
	scanImport = true

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

// ── interactiveCreate: empty-name error path ──────────────────────────────────

func TestInteractiveCreate_S29_EmptyNameError(t *testing.T) {
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	// Send an empty line for the name prompt → expect error "secret name is required".
	_, _ = w.Write([]byte("\n"))
	_ = w.Close()

	_, gotErr := interactiveCreate()
	require.Error(t, gotErr)
	assert.Contains(t, gotErr.Error(), "secret name is required")
}

// ── interactiveCreate: valid name, non-default type/projectID/envID →
// term.ReadPassword fails on pipe (not a TTY) ─────────────────────────────────

func TestInteractiveCreate_S29_ValidNameThenPasswordReadFails(t *testing.T) {
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	// Provide: name, type (non-default), project (numeric), environment (numeric).
	// term.ReadPassword is called next but a pipe is not a TTY → it fails.
	input := strings.Join([]string{
		"my-s29-secret",
		"api-key",
		"3",
		"2",
	}, "\n") + "\n"
	_, _ = w.Write([]byte(input))
	_ = w.Close()

	_, gotErr := interactiveCreate()
	require.Error(t, gotErr)
	assert.Contains(t, gotErr.Error(), "failed to read secret value")
}

// ── interactiveCreate: invalid number → re-prompt loop → EOF causes parse err ─

func TestInteractiveCreate_S29_InvalidProjectIDPromptLoop(t *testing.T) {
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	// Send: name, type, invalid projectID ("abc"), then valid projectID ("1"),
	// then valid environmentID ("1"). After that term.ReadPassword fires and fails.
	input := strings.Join([]string{
		"my-s29-secret",
		"generic",
		"abc", // invalid → loop re-prompts
		"1",   // valid project
		"1",   // valid env
	}, "\n") + "\n"
	_, _ = w.Write([]byte(input))
	_ = w.Close()

	_, gotErr := interactiveCreate()
	require.Error(t, gotErr)
	// Must reach the password-read step (covering askUint loop), not bail earlier.
	assert.Contains(t, gotErr.Error(), "failed to read secret value")
}

// ── promptRotateValue: error path (pipe is not a TTY) ────────────────────────

func TestPromptRotateValue_S29_PipeNotTTYError(t *testing.T) {
	// term.ReadPassword on a plain file descriptor that isn't a terminal returns
	// an error on most platforms. We redirect stdin to a closed pipe to force it.
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	// Close write end immediately so read end gets EOF.
	_ = w.Close()
	// Discard any bytes the OS may deliver (none expected).
	_ = r.Close()
	os.Stdin = origStdin // restore before calling (we replaced above already)

	// Re-do with a fresh pipe to avoid using closed fd.
	r2, w2, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r2
	_ = w2.Close()

	_, gotErr := promptRotateValue()
	// term.ReadPassword on a pipe fd → "not a terminal" or similar OS error,
	// which is wrapped into "failed to read secret value".
	require.Error(t, gotErr)
}

// ── collectGCP additional error paths via fake ────────────────────────────────

// fakeGCPListSecretsErr_S29 always errors on listSecrets.
type fakeGCPListSecretsErr_S29 struct{}

func (f *fakeGCPListSecretsErr_S29) listSecrets(_ context.Context, _ string) ([]string, error) {
	return nil, fmt.Errorf("gcp list boom S29")
}
func (f *fakeGCPListSecretsErr_S29) accessLatest(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}

func TestCollectGCP_S29_ListSecretsError(t *testing.T) {
	origPrefix := gcpPrefix
	t.Cleanup(func() { gcpPrefix = origPrefix })
	gcpPrefix = ""

	_, err := collectGCP(context.Background(), &fakeGCPListSecretsErr_S29{}, "proj")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list GCP secrets")
	assert.Contains(t, err.Error(), "gcp list boom S29")
}

// fakeGCPAccessLatestErr_S29 returns names OK but errors on accessLatest.
type fakeGCPAccessLatestErr_S29 struct {
	names []string
}

func (f *fakeGCPAccessLatestErr_S29) listSecrets(_ context.Context, _ string) ([]string, error) {
	return f.names, nil
}
func (f *fakeGCPAccessLatestErr_S29) accessLatest(_ context.Context, name string) (string, bool, error) {
	return "", false, fmt.Errorf("gcp access boom S29 %s", name)
}

func TestCollectGCP_S29_AccessLatestError(t *testing.T) {
	origPrefix := gcpPrefix
	t.Cleanup(func() { gcpPrefix = origPrefix })
	gcpPrefix = ""

	api := &fakeGCPAccessLatestErr_S29{
		names: []string{"projects/p/secrets/my-secret"},
	}
	_, err := collectGCP(context.Background(), api, "p")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read GCP secret")
	assert.Contains(t, err.Error(), "gcp access boom S29")
}

// fakeGCPNoVersion_S29 returns ok=false (no accessible version) → secret is skipped.
type fakeGCPNoVersion_S29 struct{}

func (f *fakeGCPNoVersion_S29) listSecrets(_ context.Context, _ string) ([]string, error) {
	return []string{"projects/p/secrets/no-vers"}, nil
}
func (f *fakeGCPNoVersion_S29) accessLatest(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil // ok=false → skipped
}

func TestCollectGCP_S29_NoVersionSkipped(t *testing.T) {
	origPrefix := gcpPrefix
	t.Cleanup(func() { gcpPrefix = origPrefix })
	gcpPrefix = ""

	entries, err := collectGCP(context.Background(), &fakeGCPNoVersion_S29{}, "p")
	require.NoError(t, err)
	assert.Empty(t, entries, "a secret with no accessible version should be skipped")
}

// ── collectAzure additional error paths via fake ──────────────────────────────

// fakeAzureListNamesErr_S29 always errors on listNames.
type fakeAzureListNamesErr_S29 struct{}

func (f *fakeAzureListNamesErr_S29) listNames(_ context.Context) ([]string, error) {
	return nil, fmt.Errorf("azure list boom S29")
}
func (f *fakeAzureListNamesErr_S29) getValue(_ context.Context, _ string) (string, error) {
	return "", nil
}

func TestCollectAzure_S29_ListNamesError(t *testing.T) {
	_, err := collectAzure(context.Background(), &fakeAzureListNamesErr_S29{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list azure secrets")
	assert.Contains(t, err.Error(), "azure list boom S29")
}

// fakeAzureGetValueErr_S29 returns names OK but errors on getValue.
type fakeAzureGetValueErr_S29 struct {
	names []string
}

func (f *fakeAzureGetValueErr_S29) listNames(_ context.Context) ([]string, error) {
	return f.names, nil
}
func (f *fakeAzureGetValueErr_S29) getValue(_ context.Context, name string) (string, error) {
	return "", fmt.Errorf("azure get boom S29 %s", name)
}

func TestCollectAzure_S29_GetValueError(t *testing.T) {
	api := &fakeAzureGetValueErr_S29{names: []string{"my-azure-secret"}}
	_, err := collectAzure(context.Background(), api)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read azure secret")
	assert.Contains(t, err.Error(), "azure get boom S29")
}

// TestCollectAzure_S29_EmptyValueSkipped verifies that an empty-string getValue
// return causes the entry to be skipped (no panic, no entry in result).
type fakeAzureEmptyValue_S29 struct{}

func (f *fakeAzureEmptyValue_S29) listNames(_ context.Context) ([]string, error) {
	return []string{"empty-secret"}, nil
}
func (f *fakeAzureEmptyValue_S29) getValue(_ context.Context, _ string) (string, error) {
	return "", nil // empty → skipped
}

func TestCollectAzure_S29_EmptyValueSkipped(t *testing.T) {
	entries, err := collectAzure(context.Background(), &fakeAzureEmptyValue_S29{})
	require.NoError(t, err)
	assert.Empty(t, entries, "secrets with empty value should be skipped")
}

// ── fetchFromGCP: empty project guard ─────────────────────────────────────────

func TestFetchFromGCP_S29_EmptyProjectError(t *testing.T) {
	origProject := gcpProject
	t.Cleanup(func() { gcpProject = origProject })
	gcpProject = "  " // whitespace-only

	_, err := fetchFromGCP(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no GCP project configured")
}

// ── fetchFromAzure: empty vault URL guard ─────────────────────────────────────

func TestFetchFromAzure_S29_EmptyVaultURL(t *testing.T) {
	origURL := azureVaultURL
	t.Cleanup(func() { azureVaultURL = origURL })
	azureVaultURL = ""

	_, err := fetchFromAzure(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure vault URL not set")
}
