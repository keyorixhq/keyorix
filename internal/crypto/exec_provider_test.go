package crypto

import (
	"bytes"
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

	// ── #288: stdout is bounded ─────────────────────────────────────────────
	t.Run("oversized stdout rejected", func(t *testing.T) {
		path := filepath.Join(dir, "toolarge.key")
		data := bytes.Repeat([]byte("A"), execMaxStdoutBytes+1024)
		require.NoError(t, os.WriteFile(path, data, 0600))
		_, err := NewExecKeyProvider([]string{"cat", path}).KEK()
		require.ErrorContains(t, err, "limit exceeded")
	})
}

// ── #288: the resolver only sees a minimal, explicit environment ───────────

func TestExecEnv_MinimalAllowlist(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("HOME", "/home/tester")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "should-not-leak")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "should-not-leak-either")

	env := execEnv()

	assert.Contains(t, env, "PATH=/usr/bin:/bin")
	assert.Contains(t, env, "HOME=/home/tester")
	assert.Len(t, env, 2, "only PATH and HOME should pass through")
	for _, kv := range env {
		assert.NotContains(t, kv, "should-not-leak")
	}
}

func TestExecEnv_OmitsUnsetAllowedVar(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	require.NoError(t, os.Unsetenv("HOME"))

	env := execEnv()

	assert.Equal(t, []string{"PATH=/usr/bin"}, env)
}

func TestExecKeyProvider_ChildDoesNotInheritFullEnvironment(t *testing.T) {
	t.Setenv("KEYORIX_KEK_TEST_LEAK", "must-not-leak-into-resolver")

	// printenv exits 1 (and prints nothing) when the named variable is unset in
	// its own environment — regardless of whether it's set in the test process.
	_, err := NewExecKeyProvider([]string{"printenv", "KEYORIX_KEK_TEST_LEAK"}).KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed", "printenv should exit non-zero because the var is not in the child's restricted env")
}

func TestExecKeyProvider_ChildStillSeesPath(t *testing.T) {
	// printenv succeeds (exit 0) for PATH, proving the allowlisted var does reach
	// the child even though the environment as a whole is minimal. The printed
	// PATH value isn't valid key material, so KEK() still errors, but on the
	// decode path rather than "command failed".
	_, err := NewExecKeyProvider([]string{"printenv", "PATH"}).KEK()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "failed", "PATH must be visible to the child, so printenv should exit 0")
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
