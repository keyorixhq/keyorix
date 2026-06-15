package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKEK returns a deterministic 32-byte key for the exec tests.
func testKEK() []byte {
	raw := make([]byte, KEKSize)
	for i := range raw {
		raw[i] = byte(i * 7)
	}
	return raw
}

func TestExecKeyProvider_AcceptsRawHexBase64(t *testing.T) {
	dir := t.TempDir()
	raw := testKEK()

	cases := map[string][]byte{
		"raw":       raw,
		"hex":       []byte(hex.EncodeToString(raw)),
		"hex+nl":    []byte(hex.EncodeToString(raw) + "\n"),
		"base64":    []byte(base64.StdEncoding.EncodeToString(raw)),
		"base64+nl": []byte(base64.StdEncoding.EncodeToString(raw) + "\n"),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".key")
			require.NoError(t, os.WriteFile(path, content, 0600))
			// `cat <file>` stands in for a real resolver command (op/sops/vault/…).
			kek, err := NewExecKeyProvider([]string{"cat", path}).KEK()
			require.NoError(t, err)
			assert.Equal(t, raw, kek)
		})
	}
}

func TestExecKeyProvider_Name(t *testing.T) {
	assert.Equal(t, "exec", NewExecKeyProvider([]string{"cat"}).Name())
}

func TestExecKeyProvider_Errors(t *testing.T) {
	dir := t.TempDir()

	t.Run("empty command rejected", func(t *testing.T) {
		_, err := NewExecKeyProvider(nil).KEK()
		require.Error(t, err)
		_, err = NewExecKeyProvider([]string{""}).KEK()
		require.Error(t, err)
	})

	t.Run("command not found", func(t *testing.T) {
		_, err := NewExecKeyProvider([]string{filepath.Join(dir, "keyorix-kek-helper-does-not-exist")}).KEK()
		require.Error(t, err)
	})

	t.Run("nonzero exit", func(t *testing.T) {
		// `false` exits 1 with no output — a resolver that failed to fetch the key.
		_, err := NewExecKeyProvider([]string{"false"}).KEK()
		require.Error(t, err)
	})

	t.Run("no output rejected", func(t *testing.T) {
		// `true` succeeds but prints nothing.
		_, err := NewExecKeyProvider([]string{"true"}).KEK()
		require.ErrorContains(t, err, "no output")
	})

	t.Run("garbage output rejected", func(t *testing.T) {
		path := filepath.Join(dir, "garbage.key")
		require.NoError(t, os.WriteFile(path, []byte("not-a-valid-key"), 0600))
		_, err := NewExecKeyProvider([]string{"cat", path}).KEK()
		require.Error(t, err, "output that does not decode to 32 bytes must be rejected")
	})
}

func TestStderrHint(t *testing.T) {
	assert.Equal(t, "", stderrHint(nil))
	assert.Equal(t, "", stderrHint([]byte("   \n")))
	assert.Equal(t, " (stderr: boom)", stderrHint([]byte("  boom\n")))

	long := make([]byte, 500)
	for i := range long {
		long[i] = 'x'
	}
	hint := stderrHint(long)
	assert.Less(t, len(hint), 500, "a flood of stderr must be bounded")
	assert.Contains(t, hint, "…")
}
