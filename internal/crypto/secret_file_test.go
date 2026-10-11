package crypto

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func secretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestResolvePassphrase_EnvFileVariant(t *testing.T) {
	t.Setenv("KX_PASS_FILE", secretFile(t, "s3cret pass\n"))
	got, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
	require.NoError(t, err)
	assert.Equal(t, "s3cret pass", string(got))
}

func TestResolvePassphrase_BothEnvAndFileRefuses(t *testing.T) {
	t.Setenv("KX_PASS", "from-env")
	t.Setenv("KX_PASS_FILE", secretFile(t, "from-file\n"))
	got, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "KX_PASS_FILE")
	assert.NotContains(t, err.Error(), "from-env")
	assert.NotContains(t, err.Error(), "from-file")
}

func TestResolvePassphrase_EnvFileUnreadableRefuses(t *testing.T) {
	t.Setenv("KX_PASS_FILE", filepath.Join(t.TempDir(), "missing"))
	_, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
	require.Error(t, err)
}

func TestEnvKeyProvider_FileVariant(t *testing.T) {
	kek := testKEK()
	t.Setenv("KX_KEK_FILE", secretFile(t, hex.EncodeToString(kek)+"\n"))
	got, err := NewEnvKeyProvider("KX_KEK").KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

func TestEnvKeyProvider_BothSetRefuses(t *testing.T) {
	kek := testKEK()
	t.Setenv("KX_KEK", hex.EncodeToString(kek))
	t.Setenv("KX_KEK_FILE", secretFile(t, hex.EncodeToString(kek)))
	_, err := NewEnvKeyProvider("KX_KEK").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KX_KEK_FILE")
}

func TestShamirKeyProvider_EnvShareFileVariant(t *testing.T) {
	kek := testKEK()
	shares, err := SplitKEK(kek, 5, 3)
	require.NoError(t, err)
	f1 := secretFile(t, hex.EncodeToString(shares[0]))
	f2 := secretFile(t, hex.EncodeToString(shares[1]))
	t.Setenv("KX_SH_FILE_SHARE3_FILE", secretFile(t, hex.EncodeToString(shares[2])+"\n"))
	commitment := hex.EncodeToString(CommitKEK(kek))
	got, err := NewShamirKeyProvider([]string{f1, f2}, []string{"KX_SH_FILE_SHARE3"}, commitment).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}
