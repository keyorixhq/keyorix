package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout redirects os.Stdout for the duration of fn and returns the
// captured output.  It restores os.Stdout before returning even if fn panics.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w
	defer func() {
		os.Stdout = orig
	}()

	fn()

	_ = w.Close()
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// writeJSONFile marshals v into JSON and writes it to dir/name.
func writeJSONFile(t *testing.T, dir, name string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

// setupTranslationsTest creates a temp locales directory for validateTranslations
// tests. loadTranslationFile scopes its secure read to whatever localesDir is
// passed to validateTranslations, so a single directory suffices: write JSON
// files into it and pass it straight to validateTranslations.
//
// Usage:
//
//	dir := setupTranslationsTest(t)
//	writeJSONFile(t, dir, "en.json", tf)
//	summary, err := validateTranslations(dir)
func setupTranslationsTest(t *testing.T) (dir string) {
	t.Helper()
	return t.TempDir()
}

// ---------------------------------------------------------------------------
// validateLanguage
// ---------------------------------------------------------------------------

func TestValidateLanguage_S23_AllMessagesPresent(t *testing.T) {
	tf := TranslationFile{
		"hello": {One: "Hello", Other: "Hello"},
		"bye":   {One: "Bye", Other: "Goodbye"},
	}
	ids := []string{"bye", "hello"}
	result := validateLanguage("en", "/fake/en.json", tf, ids)

	assert.True(t, result.Valid)
	assert.Equal(t, "en", result.Language)
	assert.Equal(t, "/fake/en.json", result.FilePath)
	assert.Equal(t, 2, result.MessageCount)
	assert.Empty(t, result.MissingMessages)
	assert.Empty(t, result.EmptyMessages)
}

func TestValidateLanguage_S23_MissingMessage(t *testing.T) {
	tf := TranslationFile{
		"hello": {One: "Hola", Other: "Hola"},
	}
	ids := []string{"bye", "hello"}
	result := validateLanguage("es", "/fake/es.json", tf, ids)

	assert.False(t, result.Valid)
	require.Len(t, result.MissingMessages, 1)
	assert.Equal(t, "bye", result.MissingMessages[0])
	assert.Empty(t, result.EmptyMessages)
}

func TestValidateLanguage_S23_EmptyBothFields(t *testing.T) {
	tf := TranslationFile{
		"hello": {One: "", Other: ""},
	}
	ids := []string{"hello"}
	result := validateLanguage("fr", "/fake/fr.json", tf, ids)

	assert.False(t, result.Valid)
	assert.Empty(t, result.MissingMessages)
	require.Len(t, result.EmptyMessages, 1)
	assert.Equal(t, "hello", result.EmptyMessages[0])
}

func TestValidateLanguage_S23_OneFieldEmptyOtherPresent(t *testing.T) {
	// A message where One="" but Other is set should be valid (not empty).
	tf := TranslationFile{
		"count": {One: "", Other: "items"},
	}
	ids := []string{"count"}
	result := validateLanguage("de", "/fake/de.json", tf, ids)

	assert.True(t, result.Valid)
	assert.Empty(t, result.EmptyMessages)
}

func TestValidateLanguage_S23_OtherFieldEmptyOnePresent(t *testing.T) {
	// A message where Other="" but One is set should be valid (not empty).
	tf := TranslationFile{
		"item": {One: "one item", Other: ""},
	}
	ids := []string{"item"}
	result := validateLanguage("de", "/fake/de.json", tf, ids)

	assert.True(t, result.Valid)
	assert.Empty(t, result.EmptyMessages)
}

func TestValidateLanguage_S23_MultipleMissingAndEmpty(t *testing.T) {
	tf := TranslationFile{
		"a": {One: "", Other: ""},
		"b": {One: "B", Other: "Bs"},
	}
	ids := []string{"a", "b", "c", "d"}
	result := validateLanguage("ru", "/fake/ru.json", tf, ids)

	assert.False(t, result.Valid)
	assert.ElementsMatch(t, []string{"c", "d"}, result.MissingMessages)
	assert.ElementsMatch(t, []string{"a"}, result.EmptyMessages)
}

func TestValidateLanguage_S23_EmptyTranslationFile(t *testing.T) {
	tf := TranslationFile{}
	ids := []string{"hello", "bye"}
	result := validateLanguage("ja", "/fake/ja.json", tf, ids)

	assert.False(t, result.Valid)
	assert.Equal(t, 2, len(result.MissingMessages))
	assert.Empty(t, result.EmptyMessages)
	assert.Equal(t, 0, result.MessageCount)
}

func TestValidateLanguage_S23_NoExpectedIDs(t *testing.T) {
	tf := TranslationFile{
		"extra": {One: "extra", Other: "extras"},
	}
	// When allMessageIDs is empty nothing is missing; but "extra" should not
	// appear as empty because it has content.
	ids := []string{}
	result := validateLanguage("en", "/fake/en.json", tf, ids)

	// The function iterates only over allMessageIDs for missing check, and
	// over translations for empty check.
	assert.True(t, result.Valid)
	assert.Empty(t, result.MissingMessages)
	assert.Empty(t, result.EmptyMessages)
}

// ---------------------------------------------------------------------------
// findInconsistentKeys
// ---------------------------------------------------------------------------

func TestFindInconsistentKeys_S23_AllConsistent(t *testing.T) {
	translations := map[string]TranslationFile{
		"en": {"hello": {One: "Hello", Other: "Hellos"}},
		"es": {"hello": {One: "Hola", Other: "Holas"}},
	}
	ids := []string{"hello"}
	result := findInconsistentKeys(translations, ids)
	assert.Empty(t, result)
}

func TestFindInconsistentKeys_S23_OneKeyMissingFromOneLanguage(t *testing.T) {
	translations := map[string]TranslationFile{
		"en": {
			"hello": {One: "Hello", Other: "Hellos"},
			"bye":   {One: "Bye", Other: "Goodbyes"},
		},
		"es": {
			"hello": {One: "Hola", Other: "Holas"},
			// "bye" missing from es
		},
	}
	ids := []string{"bye", "hello"}
	result := findInconsistentKeys(translations, ids)

	require.Len(t, result, 1)
	assert.Equal(t, "bye", result[0])
}

func TestFindInconsistentKeys_S23_MultipleInconsistentKeys(t *testing.T) {
	translations := map[string]TranslationFile{
		"en": {
			"a": {One: "A", Other: "As"},
			"b": {One: "B", Other: "Bs"},
			"c": {One: "C", Other: "Cs"},
		},
		"es": {
			"a": {One: "Ae", Other: "Aes"},
			// b and c missing
		},
		"fr": {
			"a": {One: "Af", Other: "Afs"},
			"b": {One: "Bf", Other: "Bfs"},
			// c missing
		},
	}
	ids := []string{"a", "b", "c"}
	result := findInconsistentKeys(translations, ids)

	sort.Strings(result)
	assert.Equal(t, []string{"b", "c"}, result)
}

func TestFindInconsistentKeys_S23_EmptyAllMessageIDs(t *testing.T) {
	translations := map[string]TranslationFile{
		"en": {"hello": {One: "Hello", Other: "Hellos"}},
	}
	result := findInconsistentKeys(translations, []string{})
	assert.Empty(t, result)
}

func TestFindInconsistentKeys_S23_SingleLanguageAlwaysConsistent(t *testing.T) {
	translations := map[string]TranslationFile{
		"en": {"hello": {One: "Hello", Other: "Hellos"}},
	}
	ids := []string{"hello"}
	result := findInconsistentKeys(translations, ids)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// printUsage
// ---------------------------------------------------------------------------

func TestPrintUsage_S23_ContainsExpectedSections(t *testing.T) {
	out := captureStdout(t, func() {
		printUsage()
	})

	assert.Contains(t, out, "Translation Validation Utility")
	assert.Contains(t, out, "Usage:")
	assert.Contains(t, out, "Arguments:")
	assert.Contains(t, out, "Examples:")
	assert.Contains(t, out, "locales-directory")
	assert.Contains(t, out, "internal/i18n/locales")
}

// ---------------------------------------------------------------------------
// printValidationSummary
// ---------------------------------------------------------------------------

func TestPrintValidationSummary_S23_AllValid(t *testing.T) {
	summary := &ValidationSummary{
		TotalLanguages:   2,
		ValidLanguages:   2,
		InvalidLanguages: 0,
		AllMessageIDs:    []string{"hello", "bye"},
		InconsistentKeys: nil,
		Results: []ValidationResult{
			{Language: "en", MessageCount: 2, Valid: true},
			{Language: "es", MessageCount: 2, Valid: true},
		},
	}

	out := captureStdout(t, func() {
		printValidationSummary(summary)
	})

	assert.Contains(t, out, "All translations are valid")
	assert.Contains(t, out, "Consistency: 100%")
	assert.Contains(t, out, "en")
	assert.Contains(t, out, "es")
}

func TestPrintValidationSummary_S23_InvalidLanguage(t *testing.T) {
	summary := &ValidationSummary{
		TotalLanguages:   2,
		ValidLanguages:   1,
		InvalidLanguages: 1,
		AllMessageIDs:    []string{"bye", "hello"},
		InconsistentKeys: nil,
		Results: []ValidationResult{
			{Language: "en", MessageCount: 2, Valid: true},
			{
				Language:        "es",
				MessageCount:    1,
				Valid:           false,
				MissingMessages: []string{"bye"},
			},
		},
	}

	out := captureStdout(t, func() {
		printValidationSummary(summary)
	})

	assert.Contains(t, out, "1 language(s) have validation issues")
	assert.Contains(t, out, "Missing messages")
	assert.Contains(t, out, "bye")
}

func TestPrintValidationSummary_S23_EmptyMessages(t *testing.T) {
	summary := &ValidationSummary{
		TotalLanguages:   1,
		ValidLanguages:   0,
		InvalidLanguages: 1,
		AllMessageIDs:    []string{"hello"},
		InconsistentKeys: nil,
		Results: []ValidationResult{
			{
				Language:      "en",
				MessageCount:  1,
				Valid:         false,
				EmptyMessages: []string{"hello"},
			},
		},
	}

	out := captureStdout(t, func() {
		printValidationSummary(summary)
	})

	assert.Contains(t, out, "Empty messages")
	assert.Contains(t, out, "hello")
}

func TestPrintValidationSummary_S23_InconsistentKeys(t *testing.T) {
	// When there are inconsistent keys the summary prints them with
	// "Present in" / "Missing in" breakdown loaded via loadTranslationFile.
	// Since file paths in Results are fake ("/fake/en.json"), loadTranslationFile
	// will fail gracefully (translations == nil), so the present/missing lists
	// stay empty — but the inconsistency block itself must still appear.
	summary := &ValidationSummary{
		TotalLanguages:   2,
		ValidLanguages:   2,
		InvalidLanguages: 0,
		AllMessageIDs:    []string{"bye", "hello"},
		InconsistentKeys: []string{"bye"},
		Results: []ValidationResult{
			{Language: "en", FilePath: "/nonexistent/en.json", MessageCount: 2, Valid: true},
			{Language: "es", FilePath: "/nonexistent/es.json", MessageCount: 1, Valid: true},
		},
	}

	out := captureStdout(t, func() {
		printValidationSummary(summary)
	})

	assert.Contains(t, out, "Inconsistent Keys")
	assert.Contains(t, out, "bye")
	// Consistency stat should be printed, not the "100%" variant.
	assert.NotContains(t, out, "Consistency: 100%")
}

func TestPrintValidationSummary_S23_StatsCoverage(t *testing.T) {
	summary := &ValidationSummary{
		TotalLanguages:   4,
		ValidLanguages:   3,
		InvalidLanguages: 1,
		AllMessageIDs:    []string{"a", "b", "c"},
		InconsistentKeys: nil,
		Results: []ValidationResult{
			{Language: "en", MessageCount: 3, Valid: true},
			{Language: "es", MessageCount: 3, Valid: true},
			{Language: "fr", MessageCount: 3, Valid: true},
			{Language: "de", MessageCount: 2, Valid: false, MissingMessages: []string{"c"}},
		},
	}

	out := captureStdout(t, func() {
		printValidationSummary(summary)
	})

	assert.Contains(t, out, "75.0%") // 3/4 languages valid
	assert.Contains(t, out, "3/4 languages valid")
}

// ---------------------------------------------------------------------------
// validateTranslations — error branches
// ---------------------------------------------------------------------------

// TestValidateTranslations_S23_RealLocalesDirDefaultInvocation is a regression
// test for a bug where loadTranslationFile joined its hardcoded baseDir onto a
// path that validateTranslations had already joined onto localesDir, doubling
// it (e.g. internal/i18n/locales/internal/i18n/locales/de.json) and making
// every invocation fail with "no such file or directory" — including the
// tool's documented default invocation with no arguments. This test exercises
// that exact shape: a relative "internal/i18n/locales" argument run from the
// repo root, against the real locale files, rather than a synthetic temp dir.
func TestValidateTranslations_S23_RealLocalesDirDefaultInvocation(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	t.Chdir(repoRoot)

	summary, err := validateTranslations("internal/i18n/locales")
	require.NoError(t, err, "validateTranslations must succeed against the real locales directory using the documented default relative path")

	assert.NotZero(t, summary.TotalLanguages)
	assert.Equal(t, summary.TotalLanguages, len(summary.Results))

	var enResult *ValidationResult
	for i := range summary.Results {
		if summary.Results[i].Language == "en" {
			enResult = &summary.Results[i]
		}
	}
	require.NotNil(t, enResult, "expected an en.json result among the real locale files")
	assert.NotZero(t, enResult.MessageCount)
}

// TestLoadTranslationFile_S23_ScopedToPassedBaseDir is a regression test for
// the same doubled-path bug at the loadTranslationFile call site directly:
// loadTranslationFile must read filename relative to whatever baseDir it is
// given, not a hardcoded "internal/i18n/locales" that ignores the baseDir
// argument entirely.
func TestLoadTranslationFile_S23_ScopedToPassedBaseDir(t *testing.T) {
	dir := t.TempDir()
	tf := TranslationFile{"hello": {One: "Hello", Other: "Hellos"}}
	writeJSONFile(t, dir, "en.json", tf)

	got, err := loadTranslationFile(dir, "en.json")
	require.NoError(t, err)
	assert.Equal(t, tf, got)
}

func TestValidateTranslations_S23_DirNotFound(t *testing.T) {
	_, err := validateTranslations("/nonexistent/path/to/locales")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestValidateTranslations_S23_NoJSONFiles(t *testing.T) {
	dir := t.TempDir()
	// Write a non-JSON file to make the directory non-empty but with no JSON.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0600))

	_, err := validateTranslations(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no translation files found")
}

func TestValidateTranslations_S23_InvalidJSON(t *testing.T) {
	dir := setupTranslationsTest(t)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.json"), []byte("not-json{{{"), 0600))

	_, err := validateTranslations(dir)
	require.Error(t, err)
	assert.NotEmpty(t, err.Error())
}

func TestValidateTranslations_S23_SingleValidLanguage(t *testing.T) {
	dir := setupTranslationsTest(t)

	tf := TranslationFile{
		"hello": {Description: "greeting", One: "Hello", Other: "Hellos"},
		"bye":   {Description: "farewell", One: "Bye", Other: "Goodbyes"},
	}
	writeJSONFile(t, dir, "en.json", tf)

	summary, err := validateTranslations(dir)
	require.NoError(t, err)

	assert.Equal(t, 1, summary.TotalLanguages)
	assert.Equal(t, 1, summary.ValidLanguages)
	assert.Equal(t, 0, summary.InvalidLanguages)
	assert.ElementsMatch(t, []string{"bye", "hello"}, summary.AllMessageIDs)
	assert.Empty(t, summary.InconsistentKeys)
}

func TestValidateTranslations_S23_MultipleLanguagesAllValid(t *testing.T) {
	dir := setupTranslationsTest(t)

	enTF := TranslationFile{"greet": {One: "Hi", Other: "His"}}
	esTF := TranslationFile{"greet": {One: "Hola", Other: "Holas"}}

	writeJSONFile(t, dir, "en.json", enTF)
	writeJSONFile(t, dir, "es.json", esTF)

	summary, err := validateTranslations(dir)
	require.NoError(t, err)

	assert.Equal(t, 2, summary.TotalLanguages)
	assert.Equal(t, 2, summary.ValidLanguages)
	assert.Equal(t, 0, summary.InvalidLanguages)
	assert.Empty(t, summary.InconsistentKeys)
}

func TestValidateTranslations_S23_MissingKeyInOneLanguage(t *testing.T) {
	dir := setupTranslationsTest(t)

	enTF := TranslationFile{
		"a": {One: "A", Other: "As"},
		"b": {One: "B", Other: "Bs"},
	}
	esTF := TranslationFile{
		"a": {One: "Ae", Other: "Aes"},
		// "b" intentionally missing
	}
	writeJSONFile(t, dir, "en.json", enTF)
	writeJSONFile(t, dir, "es.json", esTF)

	summary, err := validateTranslations(dir)
	require.NoError(t, err)

	assert.Equal(t, 2, summary.TotalLanguages)
	assert.Equal(t, 1, summary.ValidLanguages)
	assert.Equal(t, 1, summary.InvalidLanguages)
	assert.Contains(t, summary.InconsistentKeys, "b")

	var esResult *ValidationResult
	for i := range summary.Results {
		if summary.Results[i].Language == "es" {
			esResult = &summary.Results[i]
		}
	}
	require.NotNil(t, esResult)
	assert.Contains(t, esResult.MissingMessages, "b")
}

func TestValidateTranslations_S23_EmptyMessageInLanguage(t *testing.T) {
	dir := setupTranslationsTest(t)

	tf := TranslationFile{"welcome": {One: "", Other: ""}}
	writeJSONFile(t, dir, "en.json", tf)

	summary, err := validateTranslations(dir)
	require.NoError(t, err)

	assert.Equal(t, 1, summary.InvalidLanguages)
	require.Len(t, summary.Results, 1)
	assert.Contains(t, summary.Results[0].EmptyMessages, "welcome")
}

func TestValidateTranslations_S23_NonJSONFilesIgnored(t *testing.T) {
	dir := setupTranslationsTest(t)

	tf := TranslationFile{"hi": {One: "Hi", Other: "His"}}
	writeJSONFile(t, dir, "en.json", tf)
	// These should be ignored by the JSON file filter.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("docs"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte("mac"), 0600))

	summary, err := validateTranslations(dir)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalLanguages)
}

func TestValidateTranslations_S23_SummaryMessageIDsSorted(t *testing.T) {
	dir := setupTranslationsTest(t)

	tf := TranslationFile{
		"zebra": {One: "Zebra", Other: "Zebras"},
		"apple": {One: "Apple", Other: "Apples"},
		"mango": {One: "Mango", Other: "Mangos"},
	}
	writeJSONFile(t, dir, "en.json", tf)

	summary, err := validateTranslations(dir)
	require.NoError(t, err)

	sorted := make([]string, len(summary.AllMessageIDs))
	copy(sorted, summary.AllMessageIDs)
	sort.Strings(sorted)
	assert.Equal(t, sorted, summary.AllMessageIDs, "AllMessageIDs should be sorted")
}

// ---------------------------------------------------------------------------
// printValidationSummary — inconsistent-keys stat line with >0 inconsistencies
// ---------------------------------------------------------------------------

func TestPrintValidationSummary_S23_InconsistentKeyStatLine(t *testing.T) {
	// Three keys, one inconsistent → consistency = 2/3 ≈ 66.7%
	summary := &ValidationSummary{
		TotalLanguages:   2,
		ValidLanguages:   2,
		InvalidLanguages: 0,
		AllMessageIDs:    []string{"a", "b", "c"},
		InconsistentKeys: []string{"c"},
		Results: []ValidationResult{
			{Language: "en", FilePath: "/nonexistent/en.json", MessageCount: 3, Valid: true},
			{Language: "es", FilePath: "/nonexistent/es.json", MessageCount: 2, Valid: true},
		},
	}

	out := captureStdout(t, func() {
		printValidationSummary(summary)
	})

	assert.Contains(t, out, "Inconsistent Keys")
	assert.Contains(t, out, "c")
	// Consistency stat should show partial percentage, not "100%".
	assert.True(t,
		strings.Contains(out, "66.7%") || strings.Contains(out, "2/3 keys consistent"),
		"expected partial consistency stat in output",
	)
}

// TestPrintValidationSummary_S23_InconsistentKeyDetail verifies that
// printValidationSummary emits "Present in:" / "Missing in:" lines for an
// inconsistent key when loadTranslationFile can actually read the files.
func TestPrintValidationSummary_S23_InconsistentKeyDetail(t *testing.T) {
	dir := setupTranslationsTest(t)

	enTF := TranslationFile{
		"hello": {One: "Hello", Other: "Hellos"},
		"bye":   {One: "Bye", Other: "Goodbyes"},
	}
	esTF := TranslationFile{
		"hello": {One: "Hola", Other: "Holas"},
		// "bye" absent → inconsistent
	}
	writeJSONFile(t, dir, "en.json", enTF)
	writeJSONFile(t, dir, "es.json", esTF)

	summary, err := validateTranslations(dir)
	require.NoError(t, err)
	require.NotEmpty(t, summary.InconsistentKeys)

	out := captureStdout(t, func() {
		printValidationSummary(summary)
	})

	assert.Contains(t, out, "Inconsistent Keys")
	assert.Contains(t, out, "bye")
	assert.True(t,
		strings.Contains(out, "Present in:") || strings.Contains(out, "Missing in:"),
		"expected language breakdown in inconsistent keys section",
	)
}

// TestValidateTranslations_S23_ReadDirFailsOnRegularFile is a regression test
// for the os.ReadDir error branch: os.Stat succeeds for a path that exists
// but isn't a directory (so the "does not exist" check doesn't fire), and
// os.ReadDir then fails with ENOTDIR. validateTranslations must surface that
// as a wrapped "failed to read locales directory" error rather than panicking
// or silently continuing.
func TestValidateTranslations_S23_ReadDirFailsOnRegularFile(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-directory")
	require.NoError(t, os.WriteFile(notADir, []byte("hi"), 0600))

	_, err := validateTranslations(notADir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read locales directory")
}

// ---------------------------------------------------------------------------
// main — exercised via a re-exec'd subprocess.
//
// main() calls os.Exit(1) on several error/invalid paths, which would kill
// the entire `go test` process if invoked in-process. Following the standard
// Go idiom for testing os.Exit-calling code (see e.g. os/exec_test.go's
// TestHelperProcess pattern), we re-exec the test binary itself, restricted
// via -test.run to a single helper test that actually calls main(), and
// assert on the subprocess's exit code and captured output.
// ---------------------------------------------------------------------------

// TestHelperProcess_S23_Main is not a real test: it is invoked only by
// runMainSubprocess as a subprocess entry point. When run directly by `go
// test` (without the GO_WANT_HELPER_PROCESS_S23 env var set) it is a no-op.
func TestHelperProcess_S23_Main(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_S23") != "1" {
		return
	}

	// os.Args at this point is the full test-binary invocation, e.g.
	// [testbinary -test.run=TestHelperProcess_S23_Main -- arg1 arg2]. Find
	// the "--" separator and treat everything after it as main()'s argv.
	var mainArgs []string
	for i, a := range os.Args {
		if a == "--" {
			mainArgs = os.Args[i+1:]
			break
		}
	}
	os.Args = append([]string{"validate-translations"}, mainArgs...)

	main()
}

// runMainSubprocess re-execs the current test binary so that main() runs in
// a genuine child process, then returns its combined stdout+stderr and exit
// code. dir, if non-empty, sets the child's working directory.
func runMainSubprocess(t *testing.T, args []string, dir string) (output string, exitCode int) {
	t.Helper()

	cmdArgs := []string{"-test.run=TestHelperProcess_S23_Main", "--"}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(os.Args[0], cmdArgs...) // #nosec G204 -- re-execs the trusted test binary itself for os.Exit isolation
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_S23=1")
	if dir != "" {
		cmd.Dir = dir
	}

	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok, "expected subprocess to fail via exit code, got: %v (output: %s)", err, out)
	return string(out), exitErr.ExitCode()
}

func TestMain_S23_HelpShortFlag(t *testing.T) {
	out, exitCode := runMainSubprocess(t, []string{"-h"}, "")
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, out, "Usage:")
	assert.Contains(t, out, "Translation Validation Utility")
	// Help output must not attempt any validation.
	assert.NotContains(t, out, "Validating translations in")
}

func TestMain_S23_HelpLongFlag(t *testing.T) {
	out, exitCode := runMainSubprocess(t, []string{"--help"}, "")
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, out, "Usage:")
}

func TestMain_S23_DirNotFoundExitsNonZero(t *testing.T) {
	out, exitCode := runMainSubprocess(t, []string{"/nonexistent/path/for/validate-translations-test"}, "")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, out, "❌ Error:")
	assert.Contains(t, out, "does not exist")
}

func TestMain_S23_AllValidExitsZero(t *testing.T) {
	dir := t.TempDir()
	tf := TranslationFile{"hello": {One: "Hello", Other: "Hellos"}}
	writeJSONFile(t, dir, "en.json", tf)

	out, exitCode := runMainSubprocess(t, []string{dir}, "")
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, out, "All translations are valid")
	assert.Contains(t, out, "Validating translations in: "+dir)
}

func TestMain_S23_InvalidLanguagesExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	enTF := TranslationFile{
		"a": {One: "A", Other: "As"},
		"b": {One: "B", Other: "Bs"},
	}
	esTF := TranslationFile{
		"a": {One: "Ae", Other: "Aes"},
		// "b" intentionally missing, forcing an invalid language.
	}
	writeJSONFile(t, dir, "en.json", enTF)
	writeJSONFile(t, dir, "es.json", esTF)

	out, exitCode := runMainSubprocess(t, []string{dir}, "")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, out, "language(s) have validation issues")
}

// TestMain_S23_DefaultLocalesDir exercises the no-argument path, where main()
// falls back to the hardcoded default "internal/i18n/locales" relative
// directory. The subprocess's working directory is set to the repo root so
// that default path resolves against the real locale files, mirroring how
// the tool is documented to be invoked.
func TestMain_S23_DefaultLocalesDir(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)

	out, exitCode := runMainSubprocess(t, nil, repoRoot)
	assert.Contains(t, out, "Validating translations in: internal/i18n/locales")
	// Real locale files may or may not all be fully consistent; either
	// outcome is a legitimate exit code for this branch, but the process
	// must not crash or exit with anything else.
	assert.Contains(t, []int{0, 1}, exitCode)
}
