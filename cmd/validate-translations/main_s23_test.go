package main

import (
	"encoding/json"
	"io"
	"os"
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

	w.Close()
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

// setupTranslationsTest sets up a temp environment for validateTranslations tests.
//
// Because loadTranslationFile hardcodes baseDir="internal/i18n/locales" and
// SecureReadFile joins that with the filePath argument, the only way to avoid a
// double-nested path is to:
//   - call validateTranslations("."), so filePath becomes bare "en.json"
//   - provide the JSON files both at the CWD root (for scanning) and under
//     internal/i18n/locales/ (for the secure read that loadTranslationFile uses)
//
// This function creates both directories, switches CWD to root, and returns root
// so callers can write JSON files to both locations via writeToScan and writeToRead.
//
// Usage:
//
//	root, scan, secure := setupTranslationsTest(t)
//	writeJSONFile(t, scan,   "en.json", tf)   // scanned by validateTranslations(".")
//	writeJSONFile(t, secure, "en.json", tf)   // read by loadTranslationFile("en.json")
//	summary, err := validateTranslations(".")
func setupTranslationsTest(t *testing.T) (root, scanDir, secureDir string) {
	t.Helper()
	root = t.TempDir()
	// secureDir is where loadTranslationFile actually reads from.
	secureDir = filepath.Join(root, "internal", "i18n", "locales")
	require.NoError(t, os.MkdirAll(secureDir, 0700))
	// scanDir is the directory passed to validateTranslations; using "." means
	// filePath in loadTranslationFile will be the bare filename only.
	scanDir = root
	t.Chdir(root)
	return root, scanDir, secureDir
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

	assert.Contains(t, out, "75.0%")  // 3/4 languages valid
	assert.Contains(t, out, "3/4 languages valid")
}

// ---------------------------------------------------------------------------
// validateTranslations — error branches
// ---------------------------------------------------------------------------

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
	// We need loadTranslationFile to actually reach the file.
	// Use "." as localesDir and place JSON in both root and internal/i18n/locales/.
	_, scanDir, _ := setupTranslationsTest(t)

	// Write invalid JSON only to the scan dir; loadTranslationFile will fail
	// before even reading the secure copy.
	require.NoError(t, os.WriteFile(filepath.Join(scanDir, "bad.json"), []byte("not-json{{{"), 0600))

	_, err := validateTranslations(".")
	require.Error(t, err)
	assert.NotEmpty(t, err.Error())
}

func TestValidateTranslations_S23_SingleValidLanguage(t *testing.T) {
	_, scanDir, secureDir := setupTranslationsTest(t)

	tf := TranslationFile{
		"hello": {Description: "greeting", One: "Hello", Other: "Hellos"},
		"bye":   {Description: "farewell", One: "Bye", Other: "Goodbyes"},
	}
	writeJSONFile(t, scanDir, "en.json", tf)
	writeJSONFile(t, secureDir, "en.json", tf)

	summary, err := validateTranslations(".")
	require.NoError(t, err)

	assert.Equal(t, 1, summary.TotalLanguages)
	assert.Equal(t, 1, summary.ValidLanguages)
	assert.Equal(t, 0, summary.InvalidLanguages)
	assert.ElementsMatch(t, []string{"bye", "hello"}, summary.AllMessageIDs)
	assert.Empty(t, summary.InconsistentKeys)
}

func TestValidateTranslations_S23_MultipleLanguagesAllValid(t *testing.T) {
	_, scanDir, secureDir := setupTranslationsTest(t)

	enTF := TranslationFile{"greet": {One: "Hi", Other: "His"}}
	esTF := TranslationFile{"greet": {One: "Hola", Other: "Holas"}}

	writeJSONFile(t, scanDir, "en.json", enTF)
	writeJSONFile(t, scanDir, "es.json", esTF)
	writeJSONFile(t, secureDir, "en.json", enTF)
	writeJSONFile(t, secureDir, "es.json", esTF)

	summary, err := validateTranslations(".")
	require.NoError(t, err)

	assert.Equal(t, 2, summary.TotalLanguages)
	assert.Equal(t, 2, summary.ValidLanguages)
	assert.Equal(t, 0, summary.InvalidLanguages)
	assert.Empty(t, summary.InconsistentKeys)
}

func TestValidateTranslations_S23_MissingKeyInOneLanguage(t *testing.T) {
	_, scanDir, secureDir := setupTranslationsTest(t)

	enTF := TranslationFile{
		"a": {One: "A", Other: "As"},
		"b": {One: "B", Other: "Bs"},
	}
	esTF := TranslationFile{
		"a": {One: "Ae", Other: "Aes"},
		// "b" intentionally missing
	}
	writeJSONFile(t, scanDir, "en.json", enTF)
	writeJSONFile(t, scanDir, "es.json", esTF)
	writeJSONFile(t, secureDir, "en.json", enTF)
	writeJSONFile(t, secureDir, "es.json", esTF)

	summary, err := validateTranslations(".")
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
	_, scanDir, secureDir := setupTranslationsTest(t)

	tf := TranslationFile{"welcome": {One: "", Other: ""}}
	writeJSONFile(t, scanDir, "en.json", tf)
	writeJSONFile(t, secureDir, "en.json", tf)

	summary, err := validateTranslations(".")
	require.NoError(t, err)

	assert.Equal(t, 1, summary.InvalidLanguages)
	require.Len(t, summary.Results, 1)
	assert.Contains(t, summary.Results[0].EmptyMessages, "welcome")
}

func TestValidateTranslations_S23_NonJSONFilesIgnored(t *testing.T) {
	_, scanDir, secureDir := setupTranslationsTest(t)

	tf := TranslationFile{"hi": {One: "Hi", Other: "His"}}
	writeJSONFile(t, scanDir, "en.json", tf)
	writeJSONFile(t, secureDir, "en.json", tf)
	// These should be ignored by the JSON file filter.
	require.NoError(t, os.WriteFile(filepath.Join(scanDir, "README.md"), []byte("docs"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(scanDir, ".DS_Store"), []byte("mac"), 0600))

	summary, err := validateTranslations(".")
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalLanguages)
}

func TestValidateTranslations_S23_SummaryMessageIDsSorted(t *testing.T) {
	_, scanDir, secureDir := setupTranslationsTest(t)

	tf := TranslationFile{
		"zebra": {One: "Zebra", Other: "Zebras"},
		"apple": {One: "Apple", Other: "Apples"},
		"mango": {One: "Mango", Other: "Mangos"},
	}
	writeJSONFile(t, scanDir, "en.json", tf)
	writeJSONFile(t, secureDir, "en.json", tf)

	summary, err := validateTranslations(".")
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
	_, scanDir, secureDir := setupTranslationsTest(t)

	enTF := TranslationFile{
		"hello": {One: "Hello", Other: "Hellos"},
		"bye":   {One: "Bye", Other: "Goodbyes"},
	}
	esTF := TranslationFile{
		"hello": {One: "Hola", Other: "Holas"},
		// "bye" absent → inconsistent
	}
	writeJSONFile(t, scanDir, "en.json", enTF)
	writeJSONFile(t, scanDir, "es.json", esTF)
	writeJSONFile(t, secureDir, "en.json", enTF)
	writeJSONFile(t, secureDir, "es.json", esTF)

	summary, err := validateTranslations(".")
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
