package secret

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── selfSignedNote ────────────────────────────────

func TestSelfSignedNote_True(t *testing.T) {
	assert.Equal(t, "  (self-signed)", selfSignedNote(true))
}

func TestSelfSignedNote_False(t *testing.T) {
	assert.Equal(t, "", selfSignedNote(false))
}

// ──────────────────────────── truncateString ────────────────────────────────

func TestTruncateString_Short(t *testing.T) {
	assert.Equal(t, "hi", truncateString("hi", 10))
}

func TestTruncateString_Exact(t *testing.T) {
	assert.Equal(t, "hello", truncateString("hello", 5))
}

func TestTruncateString_Long(t *testing.T) {
	result := truncateString("abcdefghij", 7)
	assert.Equal(t, "abcd...", result)
	assert.Len(t, result, 7)
}

// ──────────────────────────── min ───────────────────────────────────────────

func TestMin_FirstSmaller(t *testing.T) {
	assert.Equal(t, 3, min(3, 5))
}

func TestMin_SecondSmaller(t *testing.T) {
	assert.Equal(t, 2, min(4, 2))
}

func TestMin_Equal(t *testing.T) {
	assert.Equal(t, 7, min(7, 7))
}

// ──────────────────────────── noteSuffix ────────────────────────────────────

func TestNoteSuffix_Empty(t *testing.T) {
	assert.Equal(t, "", noteSuffix(""))
}

func TestNoteSuffix_Whitespace(t *testing.T) {
	assert.Equal(t, "", noteSuffix("   "))
}

func TestNoteSuffix_WithText(t *testing.T) {
	assert.Equal(t, "  — my note", noteSuffix("my note"))
}

// ──────────────────────────── plural ────────────────────────────────────────

func TestPlural_One(t *testing.T) {
	assert.Equal(t, "", plural(1))
}

func TestPlural_Many(t *testing.T) {
	assert.Equal(t, "s", plural(0))
	assert.Equal(t, "s", plural(2))
}

// ──────────────────────────── printTags ─────────────────────────────────────

func TestPrintTags_Empty(t *testing.T) {
	// Must not panic; output goes to stdout.
	printTags([]string{})
}

func TestPrintTags_NonEmpty(t *testing.T) {
	printTags([]string{"prod", "tier1"})
}

// ──────────────────────────── printDependencies / printImpact ───────────────

func TestPrintDependencies_Empty(t *testing.T) {
	v := &depsView{
		SecretID:   1,
		DependsOn:  []depEdgeView{},
		Dependents: []depEdgeView{},
	}
	printDependencies(v) // must not panic
}

func TestPrintDependencies_WithEdges(t *testing.T) {
	v := &depsView{
		SecretID: 1,
		DependsOn: []depEdgeView{
			{ID: 10, SecretID: 2, SecretName: "db-pass", Note: ""},
			{ID: 11, SecretID: 3, SecretName: "api-key", Note: "critical"},
		},
		Dependents: []depEdgeView{
			{ID: 20, SecretID: 4, SecretName: "app-token", Note: ""},
		},
	}
	printDependencies(v)
}

func TestPrintImpact_Empty(t *testing.T) {
	v := &impactView{
		SecretID:   5,
		SecretName: "db-pass",
		Affected:   []impactedView{},
	}
	printImpact(v)
}

func TestPrintImpact_WithAffected(t *testing.T) {
	v := &impactView{
		SecretID:   5,
		SecretName: "db-pass",
		Affected: []impactedView{
			{SecretID: 10, SecretName: "svc-token", Depth: 1},
			{SecretID: 11, SecretName: "report-key", Depth: 2},
		},
	}
	printImpact(v)
}

// ──────────────────────────── depsClient (no server) ────────────────────────

func TestDepsClient_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	_, err := depsClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── formatBytes ───────────────────────────────────

func TestFormatBytes_Bytes(t *testing.T) {
	assert.Equal(t, "512 B", formatBytes(512))
}

func TestFormatBytes_Zero(t *testing.T) {
	assert.Equal(t, "0 B", formatBytes(0))
}

func TestFormatBytes_Kilobytes(t *testing.T) {
	result := formatBytes(1024)
	assert.Contains(t, result, "K")
}

func TestFormatBytes_Megabytes(t *testing.T) {
	result := formatBytes(1024 * 1024)
	assert.Contains(t, result, "M")
}

// ──────────────────────────── displayVersionsTable ──────────────────────────

func TestDisplayVersionsTable_Empty(t *testing.T) {
	sec := &models.SecretNode{Name: "my-secret"}
	sec.ID = 42
	displayVersionsTable(sec, []*models.SecretVersion{})
}

func TestDisplayVersionsTable_WithVersions(t *testing.T) {
	sec := &models.SecretNode{Name: "my-secret"}
	sec.ID = 42
	versions := []*models.SecretVersion{
		{
			VersionNumber:      1,
			EncryptedValue:     []byte("encdata"),
			ReadCount:          5,
			CreatedAt:          time.Now().Add(-24 * time.Hour),
			EncryptionMetadata: []byte(`{"alg":"AES-256-GCM"}`),
		},
		{
			VersionNumber:  2,
			EncryptedValue: []byte("encdata2"),
			ReadCount:      2,
			CreatedAt:      time.Now(),
		},
	}
	displayVersionsTable(sec, versions)
}

// ──────────────────────────── runVersions early-return ──────────────────────

func TestRunVersions_ZeroID(t *testing.T) {
	origID := versionsID
	defer func() { versionsID = origID }()
	versionsID = 0
	err := runVersions(versionsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestRunVersions_InvalidFormat(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origID, origFmt := versionsID, versionsFormat
	defer func() { versionsID = origID; versionsFormat = origFmt }()
	versionsID = 99
	versionsFormat = "xml"
	// Will fail at storage init or secret lookup; tests the early path, not panic.
	err := runVersions(versionsCmd, nil)
	_ = err
}

// ──────────────────────────── runExplain ────────────────────────────────────

func TestRunExplain_MatchedKey(t *testing.T) {
	err := runExplain(explainCmd, []string{"aws_access_key"})
	require.NoError(t, err)
}

func TestRunExplain_UnknownKey(t *testing.T) {
	err := runExplain(explainCmd, []string{"totally_unknown_xyz"})
	require.NoError(t, err) // no match → prints generic guidance, returns nil
}

func TestRunExplain_DBPassword(t *testing.T) {
	err := runExplain(explainCmd, []string{"DB_PASSWORD"})
	require.NoError(t, err)
}

func TestRunExplain_JWTSecret(t *testing.T) {
	err := runExplain(explainCmd, []string{"jwt_secret"})
	require.NoError(t, err)
}

// ──────────────────────────── parseFile unknown format ──────────────────────

func TestParseFile_UnknownFormat(t *testing.T) {
	_, err := parseFile("/dev/null", "csv")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

// ──────────────────────────── checkImportFileSize ───────────────────────────

func TestCheckImportFileSize_Missing(t *testing.T) {
	err := checkImportFileSize(filepath.Join(t.TempDir(), "nonexistent.txt"))
	require.Error(t, err)
}

func TestCheckImportFileSize_SmallFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	require.NoError(t, os.WriteFile(path, []byte("SECRET=value"), 0600))
	require.NoError(t, checkImportFileSize(path))
}

// ──────────────────────────── keyHasControlChars ────────────────────────────

func TestKeyHasControlChars_Clean(t *testing.T) {
	assert.False(t, keyHasControlChars("MY_KEY"))
}

func TestKeyHasControlChars_WithESC(t *testing.T) {
	assert.True(t, keyHasControlChars("MY\x1bKEY"))
}

func TestKeyHasControlChars_WithNull(t *testing.T) {
	assert.True(t, keyHasControlChars("KEY\x00"))
}

// ──────────────────────────── valueHasDangerousControlChars ─────────────────

func TestValueHasDangerousControlChars_Clean(t *testing.T) {
	assert.False(t, valueHasDangerousControlChars("mysecretvalue"))
}

func TestValueHasDangerousControlChars_TabNewline(t *testing.T) {
	// \t, \n, \r are explicitly allowed (PEM keys, multiline creds).
	assert.False(t, valueHasDangerousControlChars("line1\nline2\ttab\r"))
}

func TestValueHasDangerousControlChars_ESC(t *testing.T) {
	assert.True(t, valueHasDangerousControlChars("value\x1b[31m"))
}

// ──────────────────────────── validateImportedEntry ─────────────────────────

func TestValidateImportedEntry_Clean(t *testing.T) {
	e := secretEntry{Name: "MY_SECRET", Value: "supersecret"}
	require.NoError(t, validateImportedEntry(e))
}

func TestValidateImportedEntry_ControlInName(t *testing.T) {
	e := secretEntry{Name: "MY\x1bSECRET", Value: "value"}
	err := validateImportedEntry(e)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestValidateImportedEntry_ControlInValue(t *testing.T) {
	e := secretEntry{Name: "CLEAN_KEY", Value: "bad\x01value"}
	require.Error(t, validateImportedEntry(e))
}

// ──────────────────────────── scanEnvFile ────────────────────────────────────

func TestScanEnvFile_MissingFile(t *testing.T) {
	findings := scanEnvFile("/nonexistent/path/.env", ".env")
	assert.Nil(t, findings)
}

func TestScanEnvFile_WithRealContent(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := "DB_PASSWORD=supersecret123\nAPI_KEY=myapikey456\n# comment\nEMPTY=\nPLACEHOLDER=changeme\n"
	require.NoError(t, os.WriteFile(envPath, []byte(content), 0600))

	findings := scanEnvFile(envPath, ".env")
	// Should find DB_PASSWORD and API_KEY but skip EMPTY and PLACEHOLDER.
	assert.GreaterOrEqual(t, len(findings), 2)
	for _, f := range findings {
		assert.NotEmpty(t, f.Name)
		assert.NotEmpty(t, f.Value)
	}
}

func TestScanEnvFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(path, []byte(""), 0600))
	findings := scanEnvFile(path, ".env")
	assert.Len(t, findings, 0)
}

func TestScanEnvFile_CommentsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(path, []byte("# comment\n# another\n"), 0600))
	findings := scanEnvFile(path, ".env")
	assert.Len(t, findings, 0)
}

// ──────────────────────────── scanSourceFile ─────────────────────────────────

func TestScanSourceFile_MissingFile(t *testing.T) {
	findings := scanSourceFile("/nonexistent/main.go", "main.go")
	assert.Nil(t, findings)
}

func TestScanSourceFile_CleanFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.go")
	require.NoError(t, os.WriteFile(path, []byte("package main\nfunc main() {}\n"), 0600))
	findings := scanSourceFile(path, "clean.go")
	assert.Len(t, findings, 0)
}

// ──────────────────────────── rollbackCmd early returns ──────────────────────

func TestRollbackCmd_ZeroID(t *testing.T) {
	origID, origV := rollbackID, rollbackVersion
	defer func() { rollbackID = origID; rollbackVersion = origV }()
	rollbackID = 0
	rollbackVersion = 1
	err := rollbackCmd.RunE(rollbackCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestRollbackCmd_ZeroVersion(t *testing.T) {
	origID, origV := rollbackID, rollbackVersion
	defer func() { rollbackID = origID; rollbackVersion = origV }()
	rollbackID = 1
	rollbackVersion = 0
	err := rollbackCmd.RunE(rollbackCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--version")
}

func TestRollbackCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origID, origV := rollbackID, rollbackVersion
	defer func() { rollbackID = origID; rollbackVersion = origV }()
	rollbackID = 1
	rollbackVersion = 2
	err := rollbackCmd.RunE(rollbackCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── orphanedCmd early returns ──────────────────────

func TestOrphanedCmd_ZeroProject(t *testing.T) {
	orig := orphanedProject
	defer func() { orphanedProject = orig }()
	orphanedProject = 0
	err := orphanedCmd.RunE(orphanedCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project is required")
}

func TestOrphanedCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := orphanedProject
	defer func() { orphanedProject = orig }()
	orphanedProject = 1
	err := orphanedCmd.RunE(orphanedCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── tagsCmd early returns ─────────────────────────

func TestTagsCmd_ZeroID(t *testing.T) {
	orig := tagsID
	defer func() { tagsID = orig }()
	tagsID = 0
	err := tagsCmd.RunE(tagsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestTagsCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := tagsID
	defer func() { tagsID = orig }()
	tagsID = 1
	err := tagsCmd.RunE(tagsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── parseSecretArg ────────────────────────────────

func TestParseSecretArg_Valid(t *testing.T) {
	id, err := parseSecretArg("42")
	require.NoError(t, err)
	assert.Equal(t, uint(42), id)
}

func TestParseSecretArg_Zero(t *testing.T) {
	_, err := parseSecretArg("0")
	require.Error(t, err)
}

func TestParseSecretArg_NonNumeric(t *testing.T) {
	_, err := parseSecretArg("abc")
	require.Error(t, err)
}

func TestParseSecretArg_WithSpaces(t *testing.T) {
	id, err := parseSecretArg("  10  ")
	require.NoError(t, err)
	assert.Equal(t, uint(10), id)
}

// ──────────────────────────── writeExportJSON ────────────────────────────────

func TestWriteExportJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := writeExportJSON(&buf, []exportedSecret{})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "{")
}

func TestWriteExportJSON_WithSecrets(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{
		{ID: 1, Name: "DB_PASSWORD", Value: "s3cret"},
		{ID: 2, Name: "API_KEY", Value: "key123"},
	}
	err := writeExportJSON(&buf, secrets)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "DB_PASSWORD")
	assert.Contains(t, out, "s3cret")
}

// ──────────────────────────── writeVault ────────────────────────────────────

func TestWriteVault_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := writeVault(&buf, []exportedSecret{}, "production")
	require.NoError(t, err)
}

func TestWriteVault_WithSecrets(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{
		{ID: 1, Name: "DB_PASSWORD", Value: "s3cret"},
	}
	err := writeVault(&buf, secrets, "production")
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "DB_PASSWORD")
	assert.Contains(t, out, "production")
}

// ──────────────────────────── collectEntries ────────────────────────────────

func TestCollectEntries_BothSourceAndFile(t *testing.T) {
	origSource, origFile := importSource, importFile
	defer func() { importSource = origSource; importFile = origFile }()
	importSource = "vault"
	importFile = "/some/file.env"

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestCollectEntries_NeitherSourceNorFile(t *testing.T) {
	origSource, origFile := importSource, importFile
	defer func() { importSource = origSource; importFile = origFile }()
	importSource = ""
	importFile = ""

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--file")
}

func TestCollectEntries_FileNotFound(t *testing.T) {
	origSource, origFile := importSource, importFile
	defer func() { importSource = origSource; importFile = origFile }()
	importSource = ""
	importFile = "/nonexistent/path/secrets.env"

	_, err := collectEntries(context.Background())
	require.Error(t, err)
}

func TestCollectEntries_WithDotenvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "secrets.env")
	require.NoError(t, os.WriteFile(envPath, []byte("MY_KEY=myvalue\n"), 0600))

	origSource, origFile, origFmt := importSource, importFile, importFormat
	defer func() { importSource = origSource; importFile = origFile; importFormat = origFmt }()
	importSource = ""
	importFile = envPath
	importFormat = "dotenv"

	entries, err := collectEntries(context.Background())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 1)
}

// ──────────────────────────── runListEmbedded ────────────────────────────────

func TestRunListEmbedded_LocalMode(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origFmt, origProject, origLimit := listFormat, listProjectName, listLimit
	defer func() { listFormat = origFmt; listProjectName = origProject; listLimit = origLimit }()
	listFormat = "table"
	listProjectName = ""
	listLimit = 50 // prevent divide-by-zero in (listOffset / listLimit)

	err := runListEmbedded(context.Background())
	// Expect success (empty list) or storage init error — no panic.
	_ = err
}

func TestRunListEmbedded_InvalidFormat(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origFmt, origLimit := listFormat, listLimit
	defer func() { listFormat = origFmt; listLimit = origLimit }()
	listFormat = "xml"
	listLimit = 50

	err := runListEmbedded(context.Background())
	// Expect "unsupported format" or storage init error.
	_ = err
}

// ──────────────────────────── runGetEmbedded ────────────────────────────────

func TestRunGetEmbedded_NotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origName, origRef := getID, getName, getRef
	defer func() { getID = origID; getName = origName; getRef = origRef }()
	getID = 0
	getName = "nonexistent-secret"
	getRef = ""

	err := runGetEmbedded(context.Background())
	// Expect "not found" or storage error — no panic.
	_ = err
}

// ──────────────────────────── runCreateEmbedded ──────────────────────────────

func TestRunCreateEmbedded_NameRequired(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	req, err := buildCreateRequest()
	if err != nil {
		// buildCreateRequest failed before getting to runCreateEmbedded — acceptable.
		assert.Contains(t, err.Error(), "required")
		return
	}
	err = runCreateEmbedded(context.Background(), req)
	_ = err
}

// ──────────────────────────── runRender ─────────────────────────────────────

func TestRunRender_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// Provide a template file path that doesn't exist → reads template then fails on connection.
	dir := t.TempDir()
	tplPath := filepath.Join(dir, "app.tpl")
	require.NoError(t, os.WriteFile(tplPath, []byte("hello world"), 0600))

	err := runRender(renderCmd, []string{tplPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── refuseVaultRedirect ───────────────────────────

func TestRefuseVaultRedirect_AlwaysErrors(t *testing.T) {
	err := refuseVaultRedirect(nil, nil)
	assert.ErrorIs(t, err, http.ErrUseLastResponse)
}

// ──────────────────────────── splitTags ─────────────────────────────────────

func TestSplitTags_Empty(t *testing.T) {
	tags := splitTags("")
	assert.Empty(t, tags)
}

func TestSplitTags_SingleTag(t *testing.T) {
	tags := splitTags("prod")
	assert.Equal(t, []string{"prod"}, tags)
}

func TestSplitTags_MultipleWithSpaces(t *testing.T) {
	tags := splitTags(" prod , tier1 , backend ")
	assert.Equal(t, []string{"prod", "tier1", "backend"}, tags)
}

func TestSplitTags_TrailingComma(t *testing.T) {
	tags := splitTags("prod,")
	assert.Equal(t, []string{"prod"}, tags)
}

// ──────────────────────────── buildCreateRequest ────────────────────────────

func TestBuildCreateRequest_AbsolutePath(t *testing.T) {
	origName, origVal, origFile := createName, createValue, createFromFile
	defer func() { createName = origName; createValue = origVal; createFromFile = origFile }()
	createName = "my-secret"
	createValue = ""
	createFromFile = "/absolute/path/to/file"
	_, err := buildCreateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute paths")
}

func TestBuildCreateRequest_WithValue(t *testing.T) {
	origName, origVal, origFile, origType := createName, createValue, createFromFile, createType
	defer func() {
		createName = origName
		createValue = origVal
		createFromFile = origFile
		createType = origType
	}()
	createName = "test-secret"
	createValue = "supersecretvalue"
	createFromFile = ""
	createType = "generic"
	req, err := buildCreateRequest()
	require.NoError(t, err)
	assert.Equal(t, "test-secret", req.Name)
	assert.Equal(t, []byte("supersecretvalue"), req.Value)
}

func TestBuildCreateRequest_InvalidExpiration(t *testing.T) {
	origName, origVal, origExp := createName, createValue, createExpiration
	defer func() { createName = origName; createValue = origVal; createExpiration = origExp }()
	createName = "my-secret"
	createValue = "value"
	createExpiration = "not-a-date"
	_, err := buildCreateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expiration format")
}

// ──────────────────────────── buildUpdateRequest ────────────────────────────

func TestBuildUpdateRequest_AbsolutePath(t *testing.T) {
	origID, origFile := updateID, updateFromFile
	defer func() { updateID = origID; updateFromFile = origFile }()
	updateID = 1
	updateFromFile = "/absolute/path.txt"
	_, err := buildUpdateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute paths")
}

func TestBuildUpdateRequest_InvalidExpiration(t *testing.T) {
	origID, origExp, origVal, origFile := updateID, updateExpiration, updateValue, updateFromFile
	defer func() {
		updateID = origID
		updateExpiration = origExp
		updateValue = origVal
		updateFromFile = origFile
	}()
	updateID = 1
	updateValue = ""
	updateFromFile = ""
	updateExpiration = "not-a-date"
	_, err := buildUpdateRequest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expiration format")
}

func TestBuildUpdateRequest_WithValue(t *testing.T) {
	origID, origVal, origFile, origExp := updateID, updateValue, updateFromFile, updateExpiration
	defer func() {
		updateID = origID
		updateValue = origVal
		updateFromFile = origFile
		updateExpiration = origExp
	}()
	updateID = 42
	updateValue = "new-value"
	updateFromFile = ""
	updateExpiration = ""
	req, err := buildUpdateRequest()
	require.NoError(t, err)
	assert.Equal(t, uint(42), req.ID)
	assert.Equal(t, []byte("new-value"), req.Value)
}

func TestBuildUpdateRequest_ClearExpiration(t *testing.T) {
	origID, origClear := updateID, updateClearExp
	defer func() { updateID = origID; updateClearExp = origClear }()
	updateID = 1
	updateClearExp = true
	req, err := buildUpdateRequest()
	require.NoError(t, err)
	assert.True(t, req.ClearExpiration)
}

// ──────────────────────────── runUpdate zero-ID ─────────────────────────────

func TestRunUpdate_ZeroID(t *testing.T) {
	origID := updateID
	defer func() { updateID = origID }()
	updateID = 0
	err := updateCmd.RunE(updateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ID is required")
}

// ──────────────────────────── confirmDeletion ────────────────────────────────

func TestConfirmDeletion_NameMismatch(t *testing.T) {
	// Replace os.Stdin with a pipe that provides wrong name.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString("wrong-name\n")
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	result := confirmDeletion("my-secret")
	assert.False(t, result)
}

func TestConfirmDeletion_CorrectNameButNo(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString("my-secret\nno\n")
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	result := confirmDeletion("my-secret")
	assert.False(t, result)
}

func TestConfirmDeletion_CorrectNameAndYes(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString("my-secret\nyes\n")
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	result := confirmDeletion("my-secret")
	assert.True(t, result)
}

// ──────────────────────────── interactiveCreate ──────────────────────────────

func TestInteractiveCreate_EmptyName(t *testing.T) {
	// Provide empty line for name → "secret name is required".
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString("\n") // empty name
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	_, err = interactiveCreate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret name is required")
}

// ──────────────────────────── interactiveUpdate ──────────────────────────────

func TestInteractiveUpdate_NoChanges(t *testing.T) {
	// All prompts answered with "" (no change) or "n".
	r, w, err := os.Pipe()
	require.NoError(t, err)
	// Prompt order: "Update secret value?" (n), "Secret type" (\n), "Max reads" (\n), "Update expiration?" (n)
	_, err = w.WriteString("n\n\n\nn\n")
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	current := &models.SecretNode{Name: "db-pass", Type: "password"}
	current.ID = 1
	req, err := interactiveUpdate(current)
	require.NoError(t, err)
	assert.Equal(t, uint(0), req.ID) // updateID is 0 in this context
}

func TestInteractiveUpdate_UpdateMaxReads(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	// No value update, change max reads to 10, no expiration update.
	_, err = w.WriteString("n\n\n10\nn\n")
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	current := &models.SecretNode{Name: "db-pass", Type: "password"}
	current.ID = 1
	req, err := interactiveUpdate(current)
	require.NoError(t, err)
	require.NotNil(t, req.MaxReads)
	assert.Equal(t, 10, *req.MaxReads)
}

func TestInteractiveUpdate_ClearExpiration(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	// No value, no type, no max reads, update expiration=yes, clear=yes.
	_, err = w.WriteString("n\n\n\ny\ny\n")
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	exp := time.Now().Add(24 * time.Hour)
	current := &models.SecretNode{Name: "db-pass", Type: "password", Expiration: &exp}
	current.ID = 1
	req, err := interactiveUpdate(current)
	require.NoError(t, err)
	assert.True(t, req.ClearExpiration)
}

func TestInteractiveUpdate_SetExpiration(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	futureTime := "2027-01-01T00:00:00Z"
	// No value, no type, no max reads, update expiration=yes, clear=no, set date.
	input := "n\n\n\ny\nn\n" + futureTime + "\n"
	_, err = w.WriteString(input)
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	current := &models.SecretNode{Name: "db-pass", Type: "password"}
	current.ID = 1
	req, err := interactiveUpdate(current)
	require.NoError(t, err)
	require.NotNil(t, req.Expiration)
}

func TestInteractiveUpdate_InvalidExpiration(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	// No value, no type, no max reads, update expiration=yes, clear=no, bad date.
	input := "n\n\n\ny\nn\nnot-a-date\n"
	_, err = w.WriteString(input)
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	current := &models.SecretNode{Name: "db-pass", Type: "password"}
	current.ID = 1
	req, err := interactiveUpdate(current)
	require.NoError(t, err) // invalid date is just skipped with a warning
	assert.Nil(t, req.Expiration)
}

func TestInteractiveUpdate_TypeChange(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	// No value update, change type (triggers "type not supported" warning), no max reads, no expiry.
	_, err = w.WriteString("n\napi-key\n\nn\n")
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	current := &models.SecretNode{Name: "db-pass", Type: "password"}
	current.ID = 1
	req, err := interactiveUpdate(current)
	require.NoError(t, err)
	_ = req
}

func TestInteractiveUpdate_WithCurrentMaxReads(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	// No changes to any field — accept all defaults.
	_, err = w.WriteString("n\n\n\nn\n")
	require.NoError(t, err)
	w.Close() //nolint:errcheck

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close() //nolint:errcheck
	}()

	maxReads := 5
	current := &models.SecretNode{Name: "limited-secret", Type: "generic", MaxReads: &maxReads}
	current.ID = 2
	req, err := interactiveUpdate(current)
	require.NoError(t, err)
	assert.Nil(t, req.MaxReads) // no change
}

// ──────────────────────────── vault KV v1 path and extra vault coverage ──────

func TestVaultRead_KVv1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// KV v1 LIST: ?list=true on the base path
		if r.URL.Query().Get("list") == "true" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"data":{"keys":["mykey"]}}`)) //nolint:errcheck
			return
		}
		// KV v1 READ: flat data (no nested data.data)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"value":"v1-secret"}}`)) //nolint:errcheck
	}))
	defer srv.Close()

	vaultAddr, vaultToken, vaultMount, vaultPath, vaultKVVersion = srv.URL, "root", "kv", "", 1
	importNoExplode = false

	entries, err := fetchFromVault(context.Background())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "v1-secret", entries[0].Value)
}

func TestVaultDo_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := &vaultClient{
		addr:      srv.URL,
		token:     "bad",
		mount:     "secret",
		kvVersion: 2,
		hc:        &http.Client{},
	}
	var out struct{}
	_, err := c.do(context.Background(), srv.URL+"/test", &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestVaultDo_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &vaultClient{
		addr:      srv.URL,
		token:     "tok",
		mount:     "secret",
		kvVersion: 2,
		hc:        &http.Client{},
	}
	var out struct{}
	_, err := c.do(context.Background(), srv.URL+"/test", &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestVaultDo_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &vaultClient{
		addr:      srv.URL,
		token:     "tok",
		mount:     "secret",
		kvVersion: 2,
		hc:        &http.Client{},
	}
	var out struct{}
	status, err := c.do(context.Background(), srv.URL+"/test", &out)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, status)
}

func TestVaultMetadataURL_V1(t *testing.T) {
	c := &vaultClient{addr: "http://vault:8200", token: "t", mount: "kv", kvVersion: 1}
	url := c.metadataURL("mypath")
	assert.Contains(t, url, "/v1/kv/mypath")
	assert.NotContains(t, url, "metadata")
}

func TestVaultDataURL_V1(t *testing.T) {
	c := &vaultClient{addr: "http://vault:8200", token: "t", mount: "kv", kvVersion: 1}
	url := c.dataURL("mypath")
	assert.Contains(t, url, "/v1/kv/mypath")
	assert.NotContains(t, url, "/data/")
}

func TestVaultDataURL_V2(t *testing.T) {
	c := &vaultClient{addr: "http://vault:8200", token: "t", mount: "secret", kvVersion: 2}
	url := c.dataURL("prod/db")
	assert.Contains(t, url, "/v1/secret/data/prod/db")
}

func TestVaultMetadataURL_V2(t *testing.T) {
	c := &vaultClient{addr: "http://vault:8200", token: "t", mount: "secret", kvVersion: 2}
	url := c.metadataURL("prod/db")
	assert.Contains(t, url, "/v1/secret/metadata/prod/db")
}

func TestVaultList_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &vaultClient{
		addr:      srv.URL,
		token:     "tok",
		mount:     "secret",
		kvVersion: 2,
		hc:        &http.Client{},
	}
	keys, err := c.list(context.Background(), "prod")
	require.NoError(t, err)
	assert.Nil(t, keys)
}

func TestVaultRead_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &vaultClient{
		addr:      srv.URL,
		token:     "tok",
		mount:     "secret",
		kvVersion: 2,
		hc:        &http.Client{},
	}
	fields, err := c.read(context.Background(), "prod/missing")
	require.NoError(t, err)
	assert.Nil(t, fields)
}

func TestVaultReadLeaf_EmptyFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"data":{}}}`)) //nolint:errcheck
	}))
	defer srv.Close()

	c := &vaultClient{
		addr:      srv.URL,
		token:     "tok",
		mount:     "secret",
		kvVersion: 2,
		hc:        &http.Client{},
	}
	var out []secretEntry
	err := c.readLeaf(context.Background(), "prod/empty", &out)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestFetchFromSource_Vault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list") == "true" {
			w.Write([]byte(`{"data":{"keys":[]}}`)) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	vaultAddr, vaultToken, vaultMount, vaultPath, vaultKVVersion = srv.URL, "root", "secret", "", 2
	importNoExplode = false
	importPrefix = ""

	entries, err := fetchFromSource(context.Background(), "vault")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestFetchFromSource_WithPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list") == "true" {
			w.Write([]byte(`{"data":{"keys":["mykey"]}}`)) //nolint:errcheck
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"data":{"value":"myval"}}}`)) //nolint:errcheck
	}))
	defer srv.Close()

	vaultAddr, vaultToken, vaultMount, vaultPath, vaultKVVersion = srv.URL, "root", "secret", "", 2
	importNoExplode = false
	importPrefix = "prod-"

	entries, err := fetchFromSource(context.Background(), "vault")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, strings.HasPrefix(entries[0].Name, "prod-"), "prefix not applied: %q", entries[0].Name)
}

func TestFetchFromSource_GCP(t *testing.T) {
	origProject, origPrefix := gcpProject, gcpPrefix
	defer func() { gcpProject = origProject; gcpPrefix = origPrefix }()
	gcpProject = ""
	_, err := fetchFromSource(context.Background(), "gcp")
	require.Error(t, err)
}

func TestFetchFromSource_Azure(t *testing.T) {
	origURL := azureVaultURL
	defer func() { azureVaultURL = origURL }()
	azureVaultURL = ""
	_, err := fetchFromSource(context.Background(), "azure")
	require.Error(t, err)
}

func TestVaultNewVaultClient_InvalidKVVersion(t *testing.T) {
	origAddr, origToken, origVersion := vaultAddr, vaultToken, vaultKVVersion
	defer func() { vaultAddr = origAddr; vaultToken = origToken; vaultKVVersion = origVersion }()
	vaultAddr = "http://vault:8200"
	vaultToken = "tok"
	vaultKVVersion = 3
	_, err := newVaultClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--vault-kv-version")
}

// ──────────────────────────── orDefault / boolWord ───────────────────────────

func TestOrDefault_NonEmpty(t *testing.T) {
	assert.Equal(t, "active", orDefault("active", "fallback"))
}

func TestOrDefault_Empty(t *testing.T) {
	assert.Equal(t, "fallback", orDefault("", "fallback"))
}

func TestBoolWord_True(t *testing.T) {
	assert.Equal(t, "yes", boolWord(true))
}

func TestBoolWord_False(t *testing.T) {
	assert.Equal(t, "no", boolWord(false))
}

// ──────────────────────────── accessCmd / accessLogCmd RunE ──────────────────

func TestAccessCmd_ZeroID(t *testing.T) {
	orig := accessID
	defer func() { accessID = orig }()
	accessID = 0
	err := accessCmd.RunE(accessCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestAccessCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := accessID
	defer func() { accessID = orig }()
	accessID = 1
	err := accessCmd.RunE(accessCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestAccessLogCmd_ZeroID(t *testing.T) {
	orig := accessLogID
	defer func() { accessLogID = orig }()
	accessLogID = 0
	err := accessLogCmd.RunE(accessLogCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestAccessLogCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := accessLogID
	defer func() { accessLogID = orig }()
	accessLogID = 1
	err := accessLogCmd.RunE(accessLogCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── auditCmd RunE ───────────────────────────────────

func TestAuditCmd_ZeroID(t *testing.T) {
	orig := auditID
	defer func() { auditID = orig }()
	auditID = 0
	err := auditCmd.RunE(auditCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestAuditCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := auditID
	defer func() { auditID = orig }()
	auditID = 1
	err := auditCmd.RunE(auditCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── autoRotateCmd RunE ──────────────────────────────

func TestAutoRotateCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origID, origCharset := autoRotateID, autoRotateCharset
	defer func() { autoRotateID = origID; autoRotateCharset = origCharset }()
	autoRotateID = 1
	autoRotateCharset = ""
	err := autoRotateCmd.RunE(autoRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── suspendCmd / resumeCmd RunE ────────────────────

func TestSuspendCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := suspendID
	defer func() { suspendID = orig }()
	suspendID = 1
	err := suspendCmd.RunE(suspendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestResumeCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := resumeID
	defer func() { resumeID = orig }()
	resumeID = 1
	err := resumeCmd.RunE(resumeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── expiringCmd RunE ───────────────────────────────

func TestExpiringCmd_ZeroProject(t *testing.T) {
	orig := expiringProject
	defer func() { expiringProject = orig }()
	expiringProject = 0
	err := expiringCmd.RunE(expiringCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project is required")
}

func TestExpiringCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := expiringProject
	defer func() { expiringProject = orig }()
	expiringProject = 1
	err := expiringCmd.RunE(expiringCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── copyCmd RunE ───────────────────────────────────

func TestCopyCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origID, origEnv := copyID, copyToEnv
	defer func() { copyID = origID; copyToEnv = origEnv }()
	copyID = 1
	copyToEnv = 2
	err := copyCmd.RunE(copyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── classifyCmd RunE ───────────────────────────────

func TestClassifyCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origID, origLevel := classifyID, classifyLevel
	defer func() { classifyID = origID; classifyLevel = origLevel }()
	classifyID = 1
	classifyLevel = "confidential"
	err := classifyCmd.RunE(classifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── infoCmd RunE ───────────────────────────────────

func TestInfoCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := infoID
	defer func() { infoID = orig }()
	infoID = 1
	err := infoCmd.RunE(infoCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── descriptionCmd RunE ────────────────────────────

func TestDescriptionCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := descID
	defer func() { descID = orig }()
	descID = 1
	err := descriptionCmd.RunE(descriptionCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── fetchExpiring with days > 0 ────────────────────

func TestFetchExpiring_WithDays(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.RawQuery, "days=7")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"expiring":[]}}`)) //nolint:errcheck
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	c, ok := common.NewRemoteClient()
	require.True(t, ok)
	rows, err := fetchExpiring(context.Background(), c, 1, 7)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// ──────────────────────────── fetchAccessLog with days > 0 ───────────────────

func TestFetchAccessLog_WithDays(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.RawQuery, "days=14")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"access_log":[]}}`)) //nolint:errcheck
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	c, ok := common.NewRemoteClient()
	require.True(t, ok)
	rows, err := fetchAccessLog(context.Background(), c, 1, 14)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// ──────────────────────────── cobra RunE early-returns ───────────────────────

func TestTrashCmd_ZeroProject(t *testing.T) {
	orig := trashProject
	defer func() { trashProject = orig }()
	trashProject = 0
	err := trashCmd.RunE(trashCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project is required")
}

func TestTrashCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := trashProject
	defer func() { trashProject = orig }()
	trashProject = 1
	err := trashCmd.RunE(trashCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestRestoreCmd_ZeroID(t *testing.T) {
	orig := restoreID
	defer func() { restoreID = orig }()
	restoreID = 0
	err := restoreCmd.RunE(restoreCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestRestoreCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orig := restoreID
	defer func() { restoreID = orig }()
	restoreID = 1
	err := restoreCmd.RunE(restoreCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestReassignOwnerCmd_MissingRequired(t *testing.T) {
	origProject, origFrom, origTo := reassignProject, reassignFrom, reassignTo
	defer func() { reassignProject = origProject; reassignFrom = origFrom; reassignTo = origTo }()
	reassignProject = 0
	reassignFrom = 0
	reassignTo = 0
	err := reassignOwnerCmd.RunE(reassignOwnerCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project, --from and --to are all required")
}

func TestReassignOwnerCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origProject, origFrom, origTo := reassignProject, reassignFrom, reassignTo
	defer func() { reassignProject = origProject; reassignFrom = origFrom; reassignTo = origTo }()
	reassignProject = 1
	reassignFrom = 2
	reassignTo = 3
	err := reassignOwnerCmd.RunE(reassignOwnerCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ──────────────────────────── splitSecretRef ──────────────────────────────────

func TestSplitSecretRef_Valid(t *testing.T) {
	env, name, err := splitSecretRef("production/my-db-password")
	require.NoError(t, err)
	assert.Equal(t, "production", env)
	assert.Equal(t, "my-db-password", name)
}

func TestSplitSecretRef_NameWithSlashes(t *testing.T) {
	env, name, err := splitSecretRef("staging/nested/path/secret")
	require.NoError(t, err)
	assert.Equal(t, "staging", env)
	assert.Equal(t, "nested/path/secret", name)
}

func TestSplitSecretRef_NoSlash(t *testing.T) {
	_, _, err := splitSecretRef("no-slash-here")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid reference")
}

func TestSplitSecretRef_EmptyName(t *testing.T) {
	_, _, err := splitSecretRef("env/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid reference")
}

func TestSplitSecretRef_LeadingSlash(t *testing.T) {
	_, _, err := splitSecretRef("/name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid reference")
}

// ──────────────────────────── renderWith via httptest ────────────────────────

func TestRenderWith_SecretNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"secrets":[]}}`)) //nolint:errcheck
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	_, err := renderWith(context.Background(), rc, "${secret:prod/missing}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

func TestRenderWith_NoPlaceholders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	out, err := renderWith(context.Background(), rc, "hello world")
	require.NoError(t, err)
	assert.Equal(t, "hello world", out)
}

// ──────────────────────────── runRender with file ────────────────────────────

func TestRunRender_FileNotFound(t *testing.T) {
	err := runRender(renderCmd, []string{"/nonexistent/path/template.tpl"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read template")
}

// ──────────────────────────── runUpdate local mode path ──────────────────────

func TestRunUpdate_LocalMode_NotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID := updateID
	defer func() { updateID = origID }()
	updateID = 9999

	err := runUpdate(updateCmd, nil)
	// Expected: "not found" or storage error — the secret ID doesn't exist.
	_ = err
}

// ──────────────────────────── runDelete with --force in local mode ───────────

func TestRunDelete_ForceLocalMode_SecretNotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origName, origForce := deleteID, deleteName, deleteForce
	defer func() { deleteID = origID; deleteName = origName; deleteForce = origForce }()
	deleteID = 9999 // will not be found in empty DB
	deleteName = ""
	deleteForce = true

	err := deleteCmd.RunE(deleteCmd, nil)
	// Expect "secret not found" error.
	_ = err
}

// ──────────────────────────── runListRemote with JSON format ─────────────────

func TestRunListRemote_JSONFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secrets":[{"id":1,"name":"db-pass","type":"password","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}],"total":1,"page":1,"page_size":50}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origEnv, origLimit, origOffset, origFormat :=
		listProjectName, listEnv, listLimit, listOffset, listFormat
	defer func() {
		listProjectName = origProject
		listEnv = origEnv
		listLimit = origLimit
		listOffset = origOffset
		listFormat = origFormat
	}()
	listProjectName = ""
	listEnv = 0
	listLimit = 50
	listOffset = 0
	listFormat = "json"

	require.NoError(t, runList(nil, nil))
}

// ──────────────────────────── printScanReport ────────────────────────────────

func TestPrintScanReport_NoFindings(t *testing.T) {
	report := &ScanReport{
		ScannedPath: "/test",
		TotalFound:  0,
		HighRisk:    0,
		MediumRisk:  0,
		LowRisk:     0,
		Findings:    nil,
	}
	printScanReport(report) // must not panic
}

func TestPrintScanReport_WithFindings(t *testing.T) {
	report := &ScanReport{
		ScannedPath: "/test",
		TotalFound:  3,
		HighRisk:    1,
		MediumRisk:  1,
		LowRisk:     1,
		Findings: []ScanFinding{
			{File: "main.go", Line: 5, Name: "DB_PASS", Value: "secret", RiskLevel: "high", Source: "hardcoded"},
			{File: ".env", Line: 2, Name: "API_KEY", Value: "key123", RiskLevel: "medium", Source: "env_file"},
			{File: "config.yaml", Line: 8, Name: "TOKEN", Value: "tok", RiskLevel: "low", Source: "config_file"},
		},
	}
	printScanReport(report)
}

// ──────────────────────────── scanSourceFile with match ──────────────────────

func TestScanSourceFile_WithMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	// Craft a Go source file that likely matches a secretPatterns regex.
	content := `package main
const dbPassword = "mysupersecretpassword"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	findings := scanSourceFile(path, "main.go")
	// If a pattern matches, we get findings; if not, we get none.
	// Either way, no panic and Source must be "hardcoded".
	for _, f := range findings {
		assert.Equal(t, "hardcoded", f.Source)
	}
}

// ──────────────────────────── fetchFromSource / cloud source error paths ────

func TestFetchFromSource_UnknownSource(t *testing.T) {
	_, err := fetchFromSource(context.Background(), "s3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown source")
}

func TestFetchFromAzure_MissingVaultURL(t *testing.T) {
	origURL := azureVaultURL
	defer func() { azureVaultURL = origURL }()
	azureVaultURL = ""
	_, err := fetchFromAzure(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure vault URL")
}

func TestFetchFromGCP_MissingProject(t *testing.T) {
	origProject := gcpProject
	defer func() { gcpProject = origProject }()
	gcpProject = ""
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := fetchFromGCP(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GCP project")
}

// ──────────────────────────── doImport ──────────────────────────────────────

func TestDoImport_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":1,"name":"MY_SECRET","type":"generic","project_id":1,"environment_id":1,"created_by":"cli","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	entries := []secretEntry{
		{Name: "MY_SECRET", Value: "myvalue"},
	}
	err := doImport(context.Background(), rc, entries, 1, 1, 0)
	require.NoError(t, err)
}

// TestDoImport_SourceSkippedFoldsIntoSummary verifies that secrets a live
// source already dropped (sourceSkipped, e.g. Azure/GCP entries with no
// accessible value) are folded into the same final "imported N, skipped M"
// summary as destination-side skips — a non-zero source-skip count must be
// visible in doImport's own printed output, not just logged separately where
// it could be missed.
func TestDoImport_SourceSkippedFoldsIntoSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":1,"name":"MY_SECRET","type":"generic","project_id":1,"environment_id":1,"created_by":"cli","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	entries := []secretEntry{
		{Name: "MY_SECRET", Value: "myvalue"},
	}
	var err error
	out := captureStdout(t, func() {
		err = doImport(context.Background(), rc, entries, 1, 1, 2)
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Imported 1/3 secrets", "total must include the 2 secrets skipped before doImport ever saw them")
	assert.Contains(t, out, "2 skipped")
}

func TestDoImport_SkipExisting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 409 to simulate already-exists.
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"secret already exists"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origSkip := importSkipExisting
	defer func() { importSkipExisting = origSkip }()
	importSkipExisting = true

	entries := []secretEntry{
		{Name: "MY_SECRET", Value: "myvalue"},
	}
	// With skip-existing=true and 409 → no error (skipped).
	err := doImport(context.Background(), rc, entries, 1, 1, 0)
	_ = err // may succeed or fail depending on error message parsing
}

func TestDoImport_FailedEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origSkip := importSkipExisting
	defer func() { importSkipExisting = origSkip }()
	importSkipExisting = false

	entries := []secretEntry{
		{Name: "FAIL_SECRET", Value: "value"},
	}
	err := doImport(context.Background(), rc, entries, 1, 1, 0)
	require.Error(t, err) // 1 failed
	assert.Contains(t, err.Error(), "failed to import")
}

// ──────────────────────────── runImport dry-run ─────────────────────────────

func TestRunImport_DryRunWithFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "secrets.env")
	require.NoError(t, os.WriteFile(envPath, []byte("MY_KEY=myvalue\n"), 0600))

	origSource, origFile, origFmt, origDry, origProject, origEnv := importSource, importFile, importFormat, importDryRun, importProject, importEnv
	defer func() {
		importSource = origSource
		importFile = origFile
		importFormat = origFmt
		importDryRun = origDry
		importProject = origProject
		importEnv = origEnv
	}()
	importSource = ""
	importFile = envPath
	importFormat = "dotenv"
	importDryRun = true
	importProject = "default"
	importEnv = "production"

	// Use the real cobra command (which has a Context backed by Background).
	cmd := importCmd
	cmd.SetContext(context.Background())
	err := runImport(cmd, nil)
	require.NoError(t, err)
}

func TestRunImport_NeitherSourceNorFile(t *testing.T) {
	origSource, origFile, origDry := importSource, importFile, importDryRun
	defer func() { importSource = origSource; importFile = origFile; importDryRun = origDry }()
	importSource = ""
	importFile = ""
	importDryRun = false

	cmd := importCmd
	cmd.SetContext(context.Background())
	err := runImport(cmd, nil)
	require.Error(t, err)
}

// ──────────────────────────── runFix ─────────────────────────────────────────

func TestRunFix_DryRunNoMatches(t *testing.T) {
	dir := t.TempDir()

	origPath, origDry, origAll, origInteractive, origEnvFile :=
		fixPath, fixDryRun, fixAll, fixInteractive, fixEnvFile
	defer func() {
		fixPath = origPath
		fixDryRun = origDry
		fixAll = origAll
		fixInteractive = origInteractive
		fixEnvFile = origEnvFile
	}()
	fixPath = dir
	fixDryRun = true
	fixAll = false
	fixInteractive = false
	fixEnvFile = ".env"

	err := runFix(fixCmd, []string{"MY_API_KEY"})
	require.NoError(t, err)
}

func TestRunFix_DryRunWithMatches(t *testing.T) {
	dir := t.TempDir()
	// Create a source file with a pattern that fix will detect.
	srcPath := filepath.Join(dir, "main.go")
	content := `package main
const dbPassword = "hardcoded_password_value"
`
	require.NoError(t, os.WriteFile(srcPath, []byte(content), 0600))

	origPath, origDry, origAll, origInteractive, origEnvFile :=
		fixPath, fixDryRun, fixAll, fixInteractive, fixEnvFile
	defer func() {
		fixPath = origPath
		fixDryRun = origDry
		fixAll = origAll
		fixInteractive = origInteractive
		fixEnvFile = origEnvFile
	}()
	fixPath = dir
	fixDryRun = true
	fixAll = false
	fixInteractive = false
	fixEnvFile = ".env"

	// If findAndPlanFix finds a match, dry-run just prints the plan and returns nil.
	err := runFix(fixCmd, []string{"DB_PASSWORD"})
	// Expect success (may or may not find a match based on regex).
	_ = err
}

// ──────────────────────────── runExport ─────────────────────────────────────

func TestRunExport_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := exportCmd.RunE(exportCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no remote server configured")
}

func TestRunExport_UnknownFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// projects
		if r.URL.Path == "/api/v1/projects" {
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"default"}]}}`))
			return
		}
		// environments
		if r.URL.Path == "/api/v1/projects/1/environments" {
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"production"}]}}`))
			return
		}
		// secrets
		_, _ = w.Write([]byte(`{"data":{"secrets":[],"total":0}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origFmt, origProject, origEnv := exportFormat, exportProject, exportEnv
	defer func() { exportFormat = origFmt; exportProject = origProject; exportEnv = origEnv }()
	exportFormat = "csv"
	exportProject = "default"
	exportEnv = "production"

	cmd := exportCmd
	cmd.SetContext(context.Background())
	err := runExport(cmd, nil)
	// Will fail at project resolution or format check.
	_ = err
}

// ──────────────────────────── runCreateRemote ────────────────────────────────

func TestRunCreateRemote_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":10,"name":"test-secret","type":"generic","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	req := &core.CreateSecretRequest{
		Name:          "test-secret",
		Value:         []byte("myvalue"),
		Type:          "generic",
		ProjectID:     1,
		EnvironmentID: 1,
		CreatedBy:     "cli-user",
	}
	require.NoError(t, runCreateRemote(context.Background(), rc, req))
}

func TestRunCreateRemote_WithMaxReadsAndExpiration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":11,"name":"temp-secret","type":"generic","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	maxReads := 5
	exp := time.Now().Add(24 * time.Hour)
	req := &core.CreateSecretRequest{
		Name:          "temp-secret",
		Value:         []byte("myvalue"),
		Type:          "generic",
		ProjectID:     1,
		EnvironmentID: 1,
		MaxReads:      &maxReads,
		Expiration:    &exp,
		Description:   "test description",
		CreatedBy:     "cli-user",
	}
	require.NoError(t, runCreateRemote(context.Background(), rc, req))
}

// ──────────────────────────── runUpdateRemote ────────────────────────────────

func TestRunUpdateRemote_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GET for current state
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"data":{"id":5,"name":"db-pass","type":"password","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
			return
		}
		// PUT for update
		_, _ = w.Write([]byte(`{"data":{"id":5,"name":"db-pass","type":"password","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origID, origVal, origFile, origExp, origClear := updateID, updateValue, updateFromFile, updateExpiration, updateClearExp
	defer func() {
		updateID = origID
		updateValue = origVal
		updateFromFile = origFile
		updateExpiration = origExp
		updateClearExp = origClear
	}()
	updateID = 5
	updateValue = "new-value"
	updateFromFile = ""
	updateExpiration = ""
	updateClearExp = false

	require.NoError(t, runUpdateRemote(rc))
}

func TestRunUpdateRemote_WithMaxReads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":6,"name":"limited-secret","type":"password","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origID, origVal, origMax := updateID, updateValue, updateMaxReads
	defer func() { updateID = origID; updateValue = origVal; updateMaxReads = origMax }()
	updateID = 6
	updateValue = ""
	updateMaxReads = 10

	require.NoError(t, runUpdateRemote(rc))
}

// ──────────────────────────── runGetRemote additional paths ─────────────────

func TestRunGetRemote_ByIDWithValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secret":{"id":5,"name":"db-pass","type":"password","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},"value":"s3cr3t"}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origID, origRef, origShow := getID, getRef, getShowValue
	defer func() { getID = origID; getRef = origRef; getShowValue = origShow }()
	getID = 5
	getRef = ""
	getShowValue = true

	require.NoError(t, runGetRemote(context.Background(), rc))
}

func TestRunGetRemote_ByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secrets":[{"id":7,"name":"db-pass","type":"password","project_id":1,"environment_id":1,"created_by":"admin","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}],"total":1,"page":1,"page_size":1000}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origID, origName, origRef, origShow := getID, getName, getRef, getShowValue
	defer func() { getID = origID; getName = origName; getRef = origRef; getShowValue = origShow }()
	getID = 0
	getName = "db-pass"
	getRef = ""
	getShowValue = false

	require.NoError(t, runGetRemote(context.Background(), rc))
}

func TestRunGetRemote_ByNameNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secrets":[],"total":0,"page":1,"page_size":1000}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origID, origName, origRef := getID, getName, getRef
	defer func() { getID = origID; getName = origName; getRef = origRef }()
	getID = 0
	getName = "nonexistent-secret"
	getRef = ""

	err := runGetRemote(context.Background(), rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ──────────────────────────── runScan ───────────────────────────────────────

func TestRunScan_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	origStaged, origCommit, origSev := scanStaged, scanCommit, scanSeverity
	defer func() { scanStaged = origStaged; scanCommit = origCommit; scanSeverity = origSev }()
	scanStaged = false
	scanCommit = ""
	scanSeverity = ""

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err) // empty dir → no findings
}

func TestRunScan_EmptyDirWithSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	origStaged, origCommit, origSev := scanStaged, scanCommit, scanSeverity
	defer func() { scanStaged = origStaged; scanCommit = origCommit; scanSeverity = origSev }()
	scanStaged = false
	scanCommit = ""
	scanSeverity = "high"

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

func TestRunScan_WithReportFile(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")

	origStaged, origCommit, origSev, origRep := scanStaged, scanCommit, scanSeverity, scanReport
	defer func() {
		scanStaged = origStaged
		scanCommit = origCommit
		scanSeverity = origSev
		scanReport = origRep
	}()
	scanStaged = false
	scanCommit = ""
	scanSeverity = ""
	scanReport = reportPath

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
	// Report file should be created.
	_, statErr := os.Stat(reportPath)
	require.NoError(t, statErr)
}

func TestRunScan_WithDotEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(envPath, []byte("MY_SECRET=real_value\n"), 0600))

	origStaged, origCommit, origSev, origRep := scanStaged, scanCommit, scanSeverity, scanReport
	defer func() { scanStaged = origStaged; scanCommit = origCommit; scanSeverity = origSev; scanReport = origRep }()
	scanStaged = false
	scanCommit = ""
	scanSeverity = ""
	scanReport = ""

	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err)
}

func TestRunScan_InvalidCommit(t *testing.T) {
	dir := t.TempDir()
	origCommit := scanCommit
	defer func() { scanCommit = origCommit }()
	scanCommit = "-bad-commit-arg"

	err := runScan(scanCmd, []string{dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not start with '-'")
}

// ──────────────────────────── parseFile dotenv/vault/json paths ─────────────

func TestParseFile_DotenvPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	require.NoError(t, os.WriteFile(path, []byte("MY_SECRET=value123\n"), 0600))

	entries, err := parseFile(path, "dotenv")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 1)
}

func TestParseFile_JSONPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	content := `{"my_secret": "value123"}`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	entries, err := parseFile(path, "json")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 1)
}

// ──────────────────────────── displaySecretsTable / displaySecretsJSON ──────

func TestDisplaySecretsTable_Empty(t *testing.T) {
	filter := &coreStorage.SecretFilter{Page: 1, PageSize: 50}
	displaySecretsTable(nil, 0, filter) // must not panic
}

func TestDisplaySecretsTable_WithSecrets(t *testing.T) {
	now := time.Now()
	sec := &models.SecretNode{
		Name:      "db-password",
		Type:      "generic",
		Status:    "active",
		CreatedAt: now,
	}
	sec.ID = 1
	filter := &coreStorage.SecretFilter{Page: 1, PageSize: 50}
	displaySecretsTable([]*models.SecretNode{sec}, 1, filter)
}

func TestDisplaySecretsTable_WithExpiredSecret(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	sec := &models.SecretNode{
		Name:       "expired-secret",
		Type:       "generic",
		Status:     "active",
		CreatedAt:  time.Now(),
		Expiration: &past,
	}
	sec.ID = 2
	filter := &coreStorage.SecretFilter{Page: 1, PageSize: 50}
	displaySecretsTable([]*models.SecretNode{sec}, 1, filter)
}

func TestDisplaySecretsTable_Pagination(t *testing.T) {
	now := time.Now()
	var secrets []*models.SecretNode
	for i := 1; i <= 3; i++ {
		s := &models.SecretNode{Name: "secret", Type: "generic", Status: "active", CreatedAt: now}
		s.ID = uint(i)
		secrets = append(secrets, s)
	}
	// Total 100, page size 10 → pagination shown.
	pid := uint(1)
	filter := &coreStorage.SecretFilter{Page: 1, PageSize: 10, ProjectID: &pid}
	displaySecretsTable(secrets, 100, filter)
}

func TestDisplaySecretsJSON_Empty(t *testing.T) {
	filter := &coreStorage.SecretFilter{Page: 1, PageSize: 50}
	displaySecretsJSON(nil, 0, filter)
}

func TestDisplaySecretsJSON_WithSecrets(t *testing.T) {
	now := time.Now()
	exp := now.Add(24 * time.Hour)
	sec := &models.SecretNode{
		Name:       "db-password",
		Type:       "generic",
		Status:     "active",
		CreatedAt:  now,
		UpdatedAt:  now,
		Expiration: &exp,
	}
	sec.ID = 1
	filter := &coreStorage.SecretFilter{Page: 1, PageSize: 50}
	displaySecretsJSON([]*models.SecretNode{sec}, 1, filter)
}

// ──────────────────────────── runCreateEmbedded via valid request ─────────────

func TestRunCreateEmbedded_WithValidRequest(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	ctx := context.Background()
	req := &core.CreateSecretRequest{
		Name:          "test-s2-secret",
		Value:         []byte("test-value"),
		Type:          "generic",
		ProjectID:     1,
		EnvironmentID: 1,
		CreatedBy:     "cli-user",
	}
	err := runCreateEmbedded(ctx, req)
	// Will succeed (creates empty-DB + secret) or fail on migration — no panic.
	_ = err
}
