package i18n

import (
	"encoding/json"
	"errors"
	"io/fs"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

// errorOnOpenFS wraps an fs.FS and returns an error when Open is called for a
// specific filename. All other calls are delegated to the underlying FS.
// This lets us trigger the fs.ReadFile error branch in loadTranslationFiles.
type errorOnOpenFS struct {
	inner    fs.FS
	failName string // base name of the file that should fail
}

func (e errorOnOpenFS) Open(name string) (fs.File, error) {
	base := name
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			base = name[i+1:]
			break
		}
	}
	if base == e.failName {
		return nil, errors.New("injected open error for " + name)
	}
	return e.inner.Open(name)
}

// swapLocaleFS replaces the package-level localeFS with customFS for the
// duration of the test, restoring the original on cleanup.
func swapLocaleFS(t *testing.T, customFS fs.FS) {
	t.Helper()
	original := localeFS
	localeFS = customFS
	t.Cleanup(func() { localeFS = original })
}

// TestLoadTranslationFiles_ReadDirError covers the ReadDir error branch in
// loadTranslationFiles by pointing localeFS at an empty MapFS that contains
// no "locales" directory.
func TestLoadTranslationFiles_ReadDirError(t *testing.T) {
	swapLocaleFS(t, fstest.MapFS{})

	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	err := loadTranslationFiles(bundle)
	require.Error(t, err, "expected error when 'locales' dir does not exist")
	assert.Contains(t, err.Error(), "failed to read locales directory")
}

// TestLoadTranslationFiles_IsDir covers the entry.IsDir() branch by including
// a nested directory inside "locales" in the MapFS. fstest.MapFS automatically
// synthesises intermediate directories, so ReadDir("locales") will include a
// DirEntry whose IsDir() returns true, exercising the skip path.
func TestLoadTranslationFiles_IsDir(t *testing.T) {
	enData := `{"Welcome": {"other": "Welcome to Keyorix!"}}`
	mapFS := fstest.MapFS{
		"locales/en.json":            {Data: []byte(enData)},
		"locales/subdir/nested.json": {Data: []byte(enData)},
	}
	swapLocaleFS(t, mapFS)

	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	err := loadTranslationFiles(bundle)
	require.NoError(t, err, "directory entries inside locales should be silently skipped")
}

// TestLoadTranslationFiles_ParseError covers the ParseMessageFileBytes error
// branch by supplying a .json file whose content is not valid JSON.
func TestLoadTranslationFiles_ParseError(t *testing.T) {
	swapLocaleFS(t, fstest.MapFS{
		"locales/bad.json": {Data: []byte(`NOT VALID JSON`)},
	})

	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	err := loadTranslationFiles(bundle)
	require.Error(t, err, "expected error for invalid JSON in translation file")
	assert.Contains(t, err.Error(), "failed to parse translation file")
}

// TestLoadTranslationFiles_NonJsonSkipped covers the
// !strings.HasSuffix(entry.Name(), ".json") branch by including non-.json
// files in the locales directory alongside a valid .json file.
func TestLoadTranslationFiles_NonJsonSkipped(t *testing.T) {
	enData := `{"Welcome": {"other": "Welcome!"}}`
	swapLocaleFS(t, fstest.MapFS{
		"locales/en.json":  {Data: []byte(enData)},
		"locales/notes.md": {Data: []byte("# notes")},
		"locales/.hidden":  {Data: []byte("hidden")},
	})

	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	err := loadTranslationFiles(bundle)
	require.NoError(t, err, "non-.json files should be silently skipped")
}

// TestLoadTranslationFiles_ReadFileError covers the fs.ReadFile error branch
// by using errorOnOpenFS: ReadDir succeeds (via the inner MapFS), but Open
// fails for the specific .json file, causing fs.ReadFile to return an error.
func TestLoadTranslationFiles_ReadFileError(t *testing.T) {
	enData := `{"Welcome": {"other": "Welcome!"}}`
	inner := fstest.MapFS{
		"locales/en.json": {Data: []byte(enData)},
	}
	// Wrap with errorOnOpenFS so that opening "en.json" fails.
	errFS := errorOnOpenFS{inner: inner, failName: "en.json"}
	swapLocaleFS(t, errFS)

	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	err := loadTranslationFiles(bundle)
	require.Error(t, err, "expected error when ReadFile fails for a translation file")
	assert.Contains(t, err.Error(), "failed to read translation file")
}

// TestInitialize_LoadTranslationFilesError covers the initErr assignment in
// Initialize (line 72) that is reached when loadTranslationFiles returns an
// error. We achieve this by pointing localeFS at an empty MapFS so that
// fs.ReadDir("locales") fails.
func TestInitialize_LoadTranslationFilesError(t *testing.T) {
	// Save and restore global state.
	origFS := localeFS
	origGlobal := globalLocalizer
	t.Cleanup(func() {
		localeFS = origFS
		once = sync.Once{} // reset so real Initialize can re-run
		globalLocalizer = origGlobal
	})

	// Reset so once.Do fires.
	globalLocalizer = nil
	once = sync.Once{}
	localeFS = fstest.MapFS{} // empty — ReadDir("locales") will fail

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := Initialize(cfg)
	require.Error(t, err, "Initialize should return error when loadTranslationFiles fails")
	assert.Contains(t, err.Error(), "error loading translation files")
}
