package crypto

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SECRETENV-TAILS-2 F10: a shamir_share_files file is judged with the secretenv
// owner + mode rule on the descriptor that is read. The verdict is a warning
// naming the file (the startup permission check keeps the refuse/warn/grace
// decision; ask secretenv-shamir-share-file-read-policy), so a too-open or
// foreign-owned share no longer goes unexamined at the read that uses it.
func TestShamirKeyProvider_ShareFileJudgedAtRead(t *testing.T) {
	kek := testKEK()
	shares, err := SplitKEK(kek, 2, 2)
	require.NoError(t, err)
	commitmentHex := hex.EncodeToString(CommitKEK(kek))

	writeShares := func(t *testing.T, mode1 os.FileMode) (string, string) {
		dir := t.TempDir()
		f1, f2 := filepath.Join(dir, "s1"), filepath.Join(dir, "s2")
		require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0o600))
		require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0o600))
		require.NoError(t, os.Chmod(f1, mode1))
		return f1, f2
	}
	captureLog := func(t *testing.T) *bytes.Buffer {
		var buf bytes.Buffer
		prevW, prevF := log.Writer(), log.Flags()
		log.SetOutput(&buf)
		log.SetFlags(0)
		t.Cleanup(func() { log.SetOutput(prevW); log.SetFlags(prevF) })
		return &buf
	}
	run := func(t *testing.T, f1, f2 string) string {
		buf := captureLog(t)
		got, err := NewShamirKeyProvider([]string{f1, f2}, nil, commitmentHex).KEK()
		require.NoError(t, err, "the read-time judgment warns; it must not change whether the KEK is reconstructed")
		assert.Equal(t, kek, got)
		return buf.String()
	}

	t.Run("0600 own file: no warning", func(t *testing.T) {
		f1, f2 := writeShares(t, 0o600)
		assert.NotContains(t, run(t, f1, f2), "share file")
	})

	t.Run("0644 share file is named", func(t *testing.T) {
		f1, f2 := writeShares(t, 0o644)
		out := run(t, f1, f2)
		assert.Contains(t, out, "WARNING: shamir key provider: share file "+f1)
		assert.Contains(t, out, "mode 0644 is too open")
		assert.NotContains(t, out, "share file "+f2)
		assert.NotContains(t, out, hex.EncodeToString(shares[0]), "never the share itself")
	})

	t.Run("foreign-owned 0600 share file is named", func(t *testing.T) {
		f1, f2 := writeShares(t, 0o600)
		defer secretenv.OverrideOwnershipForTest(4242, os.Geteuid())()
		out := run(t, f1, f2)
		assert.Contains(t, out, "share file "+f1)
		assert.Contains(t, out, "owned by uid 4242")
		assert.NotContains(t, out, hex.EncodeToString(shares[0]))
	})
}
