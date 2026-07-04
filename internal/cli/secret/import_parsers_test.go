package secret

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// esc is the ANSI/terminal escape-introducer byte (0x1B), built from a hex
// rune literal rather than a string escape so test fixtures below can embed
// it in generated file content without hand-writing raw escape sequences.
const esc = rune(0x1B)

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
		{"ansi_escape", string(esc) + "[2Khidden" + string(esc) + "[0m", "[2Khidden[0m"},
		{"cr_lf", "line1\r\nline2", "line1line2"},
		{"nul", "a\x00b", "ab"},
		{"tab_normalized", "a\tb", "a b"},
		{"bell", "a\x07b", "ab"},
		{"c1_control", "a" + string(rune(0x9b)) + "b", "ab"}, // C1 CSI, built from a hex rune literal to avoid an unprintable byte in the source file
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
	malicious := string(esc) + "[1A" + string(esc) + "[2K  + Imported everything (id=999)\n"
	out := sanitizeForTerminal(malicious)
	assert.NotContains(t, out, string(esc))
	assert.False(t, strings.ContainsRune(out, esc))
}

// ── #295: reject (not silently strip) control chars/ANSI in parsed keys/values ──

func TestParseDotenv_RejectsANSIEscapeInKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "DB_" + string(esc) + "[2KPASSWORD=hunter2\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := parseDotenv(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret name")
}

func TestParseDotenv_RejectsANSIEscapeInValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "API_KEY=sk_live_" + string(esc) + "[1A" + string(esc) + "[2Kabc123\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := parseDotenv(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API_KEY")
}

func TestParseDotenv_AllowsOrdinaryUTF8(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "GREETING=héllo wörld 你好\nDB_PASSWORD=supersecret123\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	entries, err := parseDotenv(path)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestParseDotenv_AllowsMultilineValueWithNewlinesAndTabs(t *testing.T) {
	// Multi-line credential material (e.g. a PEM private key exported as a
	// single quoted dotenv value) legitimately contains \n and \t; these must
	// not be rejected as "dangerous" the way an ESC-introduced ANSI sequence
	// would be.
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "TLS_KEY=\"-----BEGIN KEY-----\nline\twith\ttabs\n-----END KEY-----\"\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := parseDotenv(path)
	require.NoError(t, err)
}

func TestParseJSON_RejectsANSIEscapeInKey(t *testing.T) {
	// Raw, unescaped control bytes are already invalid JSON per encoding/json's
	// own grammar (confirmed by TestParseJSON_RawControlByteIsInvalidJSON
	// below); a crafted real-world import instead carries the standard JSON
	// numeric escape for the byte, which decodes to a real ESC rune during
	// json.Unmarshal -- that's what our post-decode check has to catch. Using
	// json.Marshal to produce the fixture (rather than hand-writing the escape
	// in source) guarantees we're testing exactly that decoded form.
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	data, err := json.Marshal(map[string]string{
		"DB_" + string(esc) + "[2KPASSWORD": "hunter2",
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	_, err = parseJSON(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret name")
}

func TestParseJSON_RejectsANSIEscapeInValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	data, err := json.Marshal(map[string]string{
		"API_KEY": "sk_live_" + string(esc) + "[1A" + string(esc) + "[2Kabc123",
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	_, err = parseJSON(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API_KEY")
}

func TestParseJSON_RawControlByteIsInvalidJSON(t *testing.T) {
	// Documents why the two tests above must go through json.Marshal instead
	// of embedding a literal control byte in a hand-written JSON fixture: the
	// standard library itself already refuses raw unescaped control bytes in
	// a JSON string, independent of anything this package adds.
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	raw := []byte(`{"API_KEY":"sk_live_`)
	raw = append(raw, byte(esc))
	raw = append(raw, []byte(`abc123"}`)...)
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	_, err := parseJSON(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestParseJSON_AllowsOrdinaryUTF8(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"GREETING":"héllo wörld 你好","DB_PASSWORD":"supersecret123"}`), 0o600))

	entries, err := parseJSON(path)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestParseVault_RejectsANSIEscapeInKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.yaml")
	data, err := yaml.Marshal(map[string]map[string]string{
		"secret/production/database": {
			"pass" + string(esc) + "[2Kword": "REPLACE_ME",
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	_, err = parseVault(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret name")
}

func TestParseVault_RejectsANSIEscapeInValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.yaml")
	data, err := yaml.Marshal(map[string]map[string]string{
		"secret/production/database-password": {
			"value": "hunter2" + string(esc) + "[2Kfake",
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	_, err = parseVault(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database-password")
}

func TestParseVault_AllowsOrdinaryUTF8(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.yaml")
	content := "secret/production/database-password:\n  value: supersecret123\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	entries, err := parseVault(path)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestKeyHasControlChars(t *testing.T) {
	assert.True(t, keyHasControlChars("db"+string(esc)+"[2Kpassword"))
	assert.True(t, keyHasControlChars("a\nb"))
	assert.False(t, keyHasControlChars("DB_PASSWORD"))
	assert.False(t, keyHasControlChars("héllo"))
}

func TestValueHasDangerousControlChars(t *testing.T) {
	assert.True(t, valueHasDangerousControlChars("hunter2"+string(esc)+"[2K"))
	assert.True(t, valueHasDangerousControlChars("a\x00b"))
	assert.True(t, valueHasDangerousControlChars("a\x07b")) // bell
	assert.False(t, valueHasDangerousControlChars("line1\nline2\r\nwith\ttab"))
	assert.False(t, valueHasDangerousControlChars("-----BEGIN KEY-----\nabc\n-----END KEY-----"))
}
