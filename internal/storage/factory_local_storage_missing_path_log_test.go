// factory_local_storage_missing_path_log_test.go — INV-STORAGE-22 (#2504).
//
// ADR-095 Task 3 recommends createLocalStorage refuse to boot against a
// missing SQLite path instead of silently creating a fresh, empty database.
// That refusal is NOT built (it is a fresh-install compatibility change
// awaiting sign-off -- see #2504). Until it is, the only operator-visible
// signal that a mistyped path or unmounted volume produced a brand-new empty
// store is #1636's boot log line. These tests guard that signal.
//
// They exist because the signal was silently inverted: #1652 put
// prepareLocalStorageFile's O_CREATE pre-create ahead of the os.Stat that
// decides which line to log, so every missing path was reported as
// "opening existing SQLite database" and the "NEW, EMPTY database" warning
// could never fire.
//
// What this does NOT cover: whether boot should refuse (it currently
// succeeds -- asserted below so a future refusal change updates this test
// deliberately), and in-memory DSNs (no file to stat).
package storage

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	newEmptyDatabaseLog = "a NEW, EMPTY database will be created here"
	openingExistingLog  = "storage: opening existing SQLite database at"
)

// bootLocalStorageCapturingLog runs CreateStorage against path and returns
// every log line that mentions path.
func bootLocalStorageCapturingLog(t *testing.T, path string) []string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = path
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "boot against a missing path currently succeeds (refusal is #2504, not built)")
	require.NotNil(t, st)

	var lines []string
	for _, l := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if bytes.Contains(l, []byte(path)) {
			lines = append(lines, string(l))
		}
	}
	return lines
}

func TestCreateLocalStorage_MissingPath_LogsNewEmptyDatabase(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// A missing file in a missing directory: the mistyped-path /
	// unmounted-volume shape ADR-095 Task 3 is about.
	path := filepath.Join(t.TempDir(), "typo", "secrets.db")
	_, statErr := os.Stat(path)
	require.True(t, os.IsNotExist(statErr), "precondition: path must not exist before boot")

	got := strings.Join(bootLocalStorageCapturingLog(t, path), "\n")
	assert.Contains(t, got, newEmptyDatabaseLog,
		"booting against a missing SQLite path must warn that a new, empty database is being created")
	assert.NotContains(t, got, openingExistingLog,
		"a missing SQLite path must never be reported as an existing database")
}

func TestCreateLocalStorage_ExistingPath_LogsOpeningExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	path := filepath.Join(t.TempDir(), "secrets.db")
	_ = bootLocalStorageCapturingLog(t, path) // first boot creates it

	got := strings.Join(bootLocalStorageCapturingLog(t, path), "\n")
	assert.Contains(t, got, openingExistingLog,
		"a second boot against the same file must report it as existing")
	assert.NotContains(t, got, newEmptyDatabaseLog,
		"an existing database must never be reported as new and empty")
}
