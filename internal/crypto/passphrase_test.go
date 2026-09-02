package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePassphrase_EnvVarFallback(t *testing.T) {
	t.Setenv("TEST_PASSPHRASE_ENV", "  hunter2  ")
	got, err := ResolvePassphrase(PassphraseSource{}, "TEST_PASSPHRASE_ENV")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", string(got), "env var fallback must trim surrounding whitespace, matching pre-existing os.Getenv+TrimSpace behavior")
}

func TestResolvePassphrase_EnvVarUnsetIsAnError(t *testing.T) {
	t.Setenv("TEST_PASSPHRASE_ENV", "")
	_, err := ResolvePassphrase(PassphraseSource{}, "TEST_PASSPHRASE_ENV")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TEST_PASSPHRASE_ENV")
}

func TestResolvePassphrase_FD(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	go func() {
		_, _ = w.Write([]byte("passphrase-from-fd\n"))
		_ = w.Close()
	}()

	got, err := ResolvePassphrase(PassphraseSource{FD: int(r.Fd())}, "UNUSED")
	require.NoError(t, err)
	assert.Equal(t, "passphrase-from-fd", string(got), "trailing newline must be trimmed")
}

func TestResolvePassphrase_FDPrecedenceOverFileAndStdin(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	go func() {
		_, _ = w.Write([]byte("from-fd"))
		_ = w.Close()
	}()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(filePath, []byte("from-file"), 0o600))

	got, err := ResolvePassphrase(PassphraseSource{FD: int(r.Fd()), FilePath: filePath, Stdin: true}, "UNUSED")
	require.NoError(t, err)
	assert.Equal(t, "from-fd", string(got), "FD must win when more than one source is set")
}

func TestResolvePassphrase_File(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(filePath, []byte("file-passphrase\n"), 0o600))

	got, err := ResolvePassphrase(PassphraseSource{FilePath: filePath}, "UNUSED")
	require.NoError(t, err)
	assert.Equal(t, "file-passphrase", string(got))
}

func TestResolvePassphrase_FilePrecedenceOverStdin(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(filePath, []byte("from-file"), 0o600))

	got, err := ResolvePassphrase(PassphraseSource{FilePath: filePath, Stdin: true}, "UNUSED")
	require.NoError(t, err)
	assert.Equal(t, "from-file", string(got))
}

func TestResolvePassphrase_FileRefusesGroupReadable(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(filePath, []byte("secret"), 0o640))

	_, err := ResolvePassphrase(PassphraseSource{FilePath: filePath}, "UNUSED")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group- or world-readable")
}

func TestResolvePassphrase_FileRefusesWorldReadable(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(filePath, []byte("secret"), 0o604))

	_, err := ResolvePassphrase(PassphraseSource{FilePath: filePath}, "UNUSED")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group- or world-readable")
}

func TestResolvePassphrase_FileAcceptsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(filePath, []byte("secret"), 0o600))

	_, err := ResolvePassphrase(PassphraseSource{FilePath: filePath}, "UNUSED")
	require.NoError(t, err)
}

func TestResolvePassphrase_FileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-pass")
	require.NoError(t, os.WriteFile(real, []byte("secret"), 0o600))
	link := filepath.Join(dir, "link-pass")
	require.NoError(t, os.Symlink(real, link))

	_, err := ResolvePassphrase(PassphraseSource{FilePath: link}, "UNUSED")
	require.Error(t, err, "a symlink must be refused, not followed to an arbitrary target")
}

func TestResolvePassphrase_FileMissingIsAnError(t *testing.T) {
	_, err := ResolvePassphrase(PassphraseSource{FilePath: filepath.Join(t.TempDir(), "does-not-exist")}, "UNUSED")
	require.Error(t, err)
}

func TestResolvePassphrase_StdinPiped(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin; _ = r.Close() })

	go func() {
		_, _ = w.Write([]byte("stdin-passphrase\n"))
		_ = w.Close()
	}()

	got, err := ResolvePassphrase(PassphraseSource{Stdin: true}, "UNUSED")
	require.NoError(t, err)
	assert.Equal(t, "stdin-passphrase", string(got))
}

func TestWipeBytes(t *testing.T) {
	b := []byte("hunter2")
	WipeBytes(b)
	for i, c := range b {
		assert.Equal(t, byte(0), c, "byte %d must be zeroed", i)
	}
}
