package crypto

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SECRETENV-TAILS-2 F11: --passphrase-file is bounded by the X_FILE secret cap
// (secretenv.MaxSecretFileSize, 1 MiB) instead of an unbounded io.ReadAll.
// The cap is spelled as a literal here on purpose: the test pins the documented
// limit, not whatever the constant happens to hold.
func TestReadPassphraseFile_SizeCap(t *testing.T) {
	const capBytes = 1 << 20
	dir := t.TempDir()

	big := filepath.Join(dir, "big")
	require.NoError(t, os.WriteFile(big, []byte(strings.Repeat("a", 2<<20)), 0o600))
	_, err := readPassphraseFile(big)
	require.Error(t, err, "a 2 MiB --passphrase-file must be refused")
	assert.Contains(t, err.Error(), "too large")
	assert.Contains(t, err.Error(), "limit "+strconv.Itoa(capBytes))
	assert.Contains(t, err.Error(), "--passphrase-file")
	assert.NotContains(t, err.Error(), "aaaa", "the error must not carry the contents")

	normal := filepath.Join(dir, "normal")
	require.NoError(t, os.WriteFile(normal, []byte("correct horse battery staple\n"), 0o600))
	got, err := readPassphraseFile(normal)
	require.NoError(t, err)
	assert.Equal(t, "correct horse battery staple", string(got), "a normal file is read and trimmed as before")

	atCap := filepath.Join(dir, "atcap")
	require.NoError(t, os.WriteFile(atCap, []byte(strings.Repeat("b", capBytes)), 0o600))
	got, err = readPassphraseFile(atCap)
	require.NoError(t, err, "the cap is inclusive, like X_FILE's")
	assert.Len(t, got, capBytes)
}
