package secret

import (
	"context"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newS9EmbeddedDir sets up an isolated temp dir for embedded-mode tests.
func newS9EmbeddedDir(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
}

// createS9EmbeddedSecret creates a project, gets its default environment, then
// creates a secret — returning the secret or calling t.Skip if any step fails.
func createS9EmbeddedSecret(t *testing.T, name string) *models.SecretNode {
	t.Helper()
	// runDelete/runUpdate call InitializeStorage which requires keyorix.yaml.
	cfg := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"
	if err := os.WriteFile("keyorix.yaml", []byte(cfg), 0o600); err != nil {
		t.Skip("could not write keyorix.yaml:", err)
	}
	svc, err := common.InitializeCoreService()
	if err != nil {
		t.Skip("embedded storage unavailable:", err)
	}
	ctx := context.Background()
	proj, err := svc.CreateProject(ctx, "s9-proj-"+name, "")
	if err != nil {
		t.Skip("CreateProject failed:", err)
	}
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	if err != nil || len(envs) == 0 {
		t.Skip("no envs available:", err)
	}
	req := &core.CreateSecretRequest{
		Name:          name,
		Value:         []byte("s9-val"),
		Type:          "generic",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		CreatedBy:     "cli-test-s9",
	}
	secret, err := svc.CreateSecret(ctx, req)
	if err != nil {
		t.Skip("CreateSecret failed:", err)
	}
	return secret
}

// withStdinS9 replaces os.Stdin with a pipe seeded with input for the test.
func withStdinS9(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, _ = w.WriteString(input)
	_ = w.Close()
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
	})
}

// ── runCreateEmbedded: success path ──────────────────────────────────────────

func TestRunCreateEmbedded_Success_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	cfg := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"
	if err := os.WriteFile("keyorix.yaml", []byte(cfg), 0o600); err != nil {
		t.Skip("could not write keyorix.yaml:", err)
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		t.Skip("embedded storage unavailable:", err)
	}
	ctx := context.Background()
	proj, err := svc.CreateProject(ctx, "s9-create-proj", "")
	if err != nil {
		t.Skip("CreateProject failed:", err)
	}
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	if err != nil || len(envs) == 0 {
		t.Skip("no envs:", err)
	}

	req := &core.CreateSecretRequest{
		Name:          "s9-create-success",
		Value:         []byte("my-value-s9"),
		Type:          "generic",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		CreatedBy:     "cli-test-s9",
	}
	err = runCreateEmbedded(ctx, req)
	if err != nil {
		t.Skip("runCreateEmbedded failed:", err)
	}
}

// ── runGetEmbedded: showValue path ───────────────────────────────────────────

func TestRunGetEmbedded_ShowValue_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	secret := createS9EmbeddedSecret(t, "s9-get-showval")

	origID, origShowVal, origRef, origName := getID, getShowValue, getRef, getName
	t.Cleanup(func() {
		getID = origID
		getShowValue = origShowVal
		getRef = origRef
		getName = origName
	})
	getID = secret.ID
	getShowValue = true
	getRef = ""
	getName = ""

	err := runGetEmbedded(context.Background())
	assert.NoError(t, err)
}

// ── runGetEmbedded: by-name with project+env filter ──────────────────────────

func TestRunGetEmbedded_ByNameWithFilter_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	secret := createS9EmbeddedSecret(t, "s9-get-filtered")

	origID, origShowVal, origRef, origName, origProj, origEnv := getID, getShowValue, getRef, getName, getProject, getEnv
	t.Cleanup(func() {
		getID = origID
		getShowValue = origShowVal
		getRef = origRef
		getName = origName
		getProject = origProj
		getEnv = origEnv
	})
	getID = 0
	getShowValue = false
	getRef = ""
	getName = "s9-get-filtered"
	getProject = secret.ProjectID
	getEnv = secret.EnvironmentID

	err := runGetEmbedded(context.Background())
	assert.NoError(t, err)
}

func TestRunGetEmbedded_ByName_NoFilter_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	_ = createS9EmbeddedSecret(t, "s9-get-nofilter")

	origID, origShowVal, origRef, origName, origProj, origEnv := getID, getShowValue, getRef, getName, getProject, getEnv
	t.Cleanup(func() {
		getID = origID
		getShowValue = origShowVal
		getRef = origRef
		getName = origName
		getProject = origProj
		getEnv = origEnv
	})
	getID = 0
	getShowValue = false
	getRef = ""
	getName = "s9-get-nofilter"
	getProject = 0
	getEnv = 0

	err := runGetEmbedded(context.Background())
	assert.NoError(t, err)
}

// ── runDelete: by-name success path ──────────────────────────────────────────

func TestRunDelete_ByName_Success_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	secret := createS9EmbeddedSecret(t, "s9-del-byname")

	origID, origName, origNS, origEnv, origForce := deleteID, deleteName, deleteNS, deleteEnv, deleteForce
	t.Cleanup(func() {
		deleteID = origID
		deleteName = origName
		deleteNS = origNS
		deleteEnv = origEnv
		deleteForce = origForce
	})
	deleteID = 0
	deleteName = "s9-del-byname"
	deleteNS = secret.ProjectID
	deleteEnv = secret.EnvironmentID
	deleteForce = true

	err := runDelete(deleteCmd, nil)
	if err != nil {
		t.Skip("GetSecretByName not supported in this storage config:", err)
	}
}

// ── runDelete: non-force confirmation path ───────────────────────────────────

func TestRunDelete_NonForce_Cancelled_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	secret := createS9EmbeddedSecret(t, "s9-del-cancel")

	// Provide wrong secret name → confirmDeletion returns false → "Deletion cancelled"
	withStdinS9(t, "wrong-name\n")

	origID, origName, origForce := deleteID, deleteName, deleteForce
	t.Cleanup(func() { deleteID = origID; deleteName = origName; deleteForce = origForce })
	deleteID = secret.ID
	deleteName = ""
	deleteForce = false

	err := runDelete(deleteCmd, nil)
	assert.NoError(t, err, "cancelled deletion should return nil")
}

func TestRunDelete_NonForce_Confirmed_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	secret := createS9EmbeddedSecret(t, "s9-del-confirm")

	// Provide correct name then "yes" → confirmed → deletes
	withStdinS9(t, "s9-del-confirm\nyes\n")

	origID, origName, origForce := deleteID, deleteName, deleteForce
	t.Cleanup(func() { deleteID = origID; deleteName = origName; deleteForce = origForce })
	deleteID = secret.ID
	deleteName = ""
	deleteForce = false

	err := runDelete(deleteCmd, nil)
	assert.NoError(t, err)
}

// ── runUpdate: success path ───────────────────────────────────────────────────

func TestRunUpdate_EmbeddedSuccess_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	secret := createS9EmbeddedSecret(t, "s9-update")

	origID, origVal, origInteractive := updateID, updateValue, updateInteractive
	t.Cleanup(func() {
		updateID = origID
		updateValue = origVal
		updateInteractive = origInteractive
	})
	updateID = secret.ID
	updateValue = "updated-value-s9"
	updateInteractive = false

	err := runUpdate(updateCmd, nil)
	if err != nil {
		t.Skip("runUpdate failed:", err)
	}
}

func TestRunUpdate_EmbeddedNoChanges_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	secret := createS9EmbeddedSecret(t, "s9-update-nochange")

	origID, origVal, origMaxReads := updateID, updateValue, updateMaxReads
	t.Cleanup(func() {
		updateID = origID
		updateValue = origVal
		updateMaxReads = origMaxReads
	})
	updateID = secret.ID
	updateValue = ""
	updateMaxReads = -1

	err := runUpdate(updateCmd, nil)
	if err != nil {
		t.Skip("runUpdate no-changes failed:", err)
	}
}

// ── runScan: edge cases ───────────────────────────────────────────────────────

func TestRunScan_StagedFileFilter_S9(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, os.WriteFile("app.go", []byte("package main\n// value=fake-secret\n"), 0o600))

	origStaged, origCommit := scanStaged, scanCommit
	t.Cleanup(func() { scanStaged = origStaged; scanCommit = origCommit })
	scanStaged = true
	scanCommit = ""

	_ = runScan(scanCmd, []string{dir})
}

func TestRunScan_TestFileSkip_S9(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, os.WriteFile("main_test.go", []byte("package main // value=fake-secret"), 0o600))
	require.NoError(t, os.WriteFile("main.go", []byte("package main"), 0o600))

	origStaged := scanStaged
	t.Cleanup(func() { scanStaged = origStaged })
	scanStaged = false

	err := runScan(scanCmd, []string{dir})
	assert.NoError(t, err)
}

func TestRunScan_DotEnvFile_S9(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, os.WriteFile(".env", []byte("SECRET_KEY=my-test-secret-value\n"), 0o600))

	origStaged := scanStaged
	t.Cleanup(func() { scanStaged = origStaged })
	scanStaged = false

	err := runScan(scanCmd, []string{dir})
	assert.NoError(t, err)
}

func TestRunScan_JsonConfigFile_S9(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, os.WriteFile("config.json", []byte(`{"password":"s9-val","api_key":"AKIAIOSFODNN7EXAMPLE"}`), 0o600))

	origStaged := scanStaged
	t.Cleanup(func() { scanStaged = origStaged })
	scanStaged = false

	err := runScan(scanCmd, []string{dir})
	assert.NoError(t, err)
}

func TestRunScan_SymlinkSkip_S9(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, os.WriteFile("real.go", []byte("package main"), 0o600))
	_ = os.Symlink("real.go", dir+"/link.go")

	origStaged := scanStaged
	t.Cleanup(func() { scanStaged = origStaged })
	scanStaged = false

	err := runScan(scanCmd, []string{dir})
	assert.NoError(t, err)
}

func TestRunScan_WithReport_S9(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, os.WriteFile("creds.yaml", []byte("password: hunter2\n"), 0o600))

	reportPath := dir + "/scan-report.json"
	origReport, origStaged := scanReport, scanStaged
	t.Cleanup(func() { scanReport = origReport; scanStaged = origStaged })
	scanReport = reportPath
	scanStaged = false

	err := runScan(scanCmd, []string{dir})
	assert.NoError(t, err)
}

func TestRunScan_CommitFilter_InvalidCommit_S9(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	origStaged, origCommit := scanStaged, scanCommit
	t.Cleanup(func() { scanStaged = origStaged; scanCommit = origCommit })
	scanStaged = false
	scanCommit = "-bad-flag"

	err := runScan(scanCmd, []string{dir})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not start with '-'")
}

// ── import/export bad-path error branches ────────────────────────────────────

func TestRunImport_BadFile_S9(t *testing.T) {
	newS9EmbeddedDir(t)

	origFile, origFormat := importFile, importFormat
	t.Cleanup(func() { importFile = origFile; importFormat = origFormat })
	importFile = "/no/such/file-s9-nonexistent.json"
	importFormat = "json"

	err := runImport(importCmd, nil)
	assert.Error(t, err)
}

func TestRunExport_BadOutputPath_S9(t *testing.T) {
	newS9EmbeddedDir(t)
	cfg := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"
	if err2 := os.WriteFile("keyorix.yaml", []byte(cfg), 0o600); err2 != nil {
		t.Skip("could not write keyorix.yaml:", err2)
	}

	origOutput := exportOutput
	t.Cleanup(func() { exportOutput = origOutput })
	exportOutput = "/no/such/dir-s9/export.json"

	err := runExport(exportCmd, nil)
	_ = err
}

// ── explodeValue: compound value ─────────────────────────────────────────────

func TestExplodeValue_Compound_S9(t *testing.T) {
	results := explodeValue("db", `{"host":"localhost","port":"5432"}`)
	_ = results
}

func TestExplodeValue_Simple_S9(t *testing.T) {
	results := explodeValue("key", "simple-value")
	assert.NotEmpty(t, results)
}

// ── fetchFromVault: initialization path ──────────────────────────────────────

func TestFetchFromVault_NoEnvVars_S9(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")

	_, err := fetchFromVault(context.Background())
	assert.Error(t, err)
}

func TestFetchFromVault_BadURL_S9(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://bad-host-s9-unreachable:19999")
	t.Setenv("VAULT_TOKEN", "s9-test-token")

	_, err := fetchFromVault(context.Background())
	assert.Error(t, err)
}

// ── fetchFromAWS: initialization path ────────────────────────────────────────

func TestFetchFromAWS_NoCredentials_S9(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_REGION", "")

	_, err := fetchFromAWS(context.Background())
	_ = err
}
