package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── #295: file-size cap ─────────────────────────────────────────────────────

func TestParseVault_RejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.yaml")
	require.NoError(t, os.WriteFile(path, []byte("secret/x:\n  value: y\n"), 0o600))

	// Writing a real >100MiB file would be wasteful in CI; the size check runs
	// via os.Stat before any read, so a sparse (truncated) file that merely
	// reports a size over the cap is enough to exercise the rejection path.
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600) // #nosec G304 -- test fixture
	require.NoError(t, err)
	require.NoError(t, f.Truncate(maxImportFileBytes+1))
	require.NoError(t, f.Close())

	_, err = parseVault(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestParseJSON_RejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"a":"b"}`), 0o600))

	f, err := os.OpenFile(path, os.O_WRONLY, 0o600) // #nosec G304 -- test fixture
	require.NoError(t, err)
	require.NoError(t, f.Truncate(maxImportFileBytes+1))
	require.NoError(t, f.Close())

	_, err = parseJSON(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestParseVault_AllowsFileUnderCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.yaml")
	require.NoError(t, os.WriteFile(path, []byte("secret/production/database-password:\n  value: supersecret123\n"), 0o600))

	entries, err := parseVault(path)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "database-password", entries[0].Name)
	assert.Equal(t, "supersecret123", entries[0].Value)
}

func TestParseJSON_AllowsFileUnderCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"DB_PASSWORD":"supersecret123"}`), 0o600))

	entries, err := parseJSON(path)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "DB_PASSWORD", entries[0].Name)
	assert.Equal(t, "supersecret123", entries[0].Value)
}

func TestCheckImportFileSize_MissingFile(t *testing.T) {
	err := checkImportFileSize(filepath.Join(t.TempDir(), "does-not-exist.json"))
	require.Error(t, err)
}

// ── #295: terminal-escape sanitization ──────────────────────────────────────

func TestSanitizeForTerminal_StripsControlAndANSI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello", "hello"},
		{"ansi_escape", "\x1b[2Khidden\x1b[0m", "[2Khidden[0m"},
		{"cr_lf", "line1\r\nline2", "line1line2"},
		{"nul", "a\x00b", "ab"},
		{"tab_normalized", "a\tb", "a b"},
		{"bell", "a\x07b", "ab"},
		{"c1_control", "a\u009bb", "ab"}, // C1 CSI (escape avoids an unprintable byte in the source file)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeForTerminal(tc.in))
		})
	}
}

func TestSanitizeForTerminal_NeutralizesCursorHidingSequence(t *testing.T) {
	// A crafted value trying to move the cursor up and overwrite the CLI's own
	// status line: ESC[1A ESC[2K <fake status>. Stripping the ESC byte breaks
	// the escape sequence into inert printable text.
	malicious := "\x1b[1A\x1b[2K  + Imported everything (id=999)\n"
	out := sanitizeForTerminal(malicious)
	assert.NotContains(t, out, "\x1b")
	assert.False(t, strings.ContainsRune(out, 0x1b))
}
