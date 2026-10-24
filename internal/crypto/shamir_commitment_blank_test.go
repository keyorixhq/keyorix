package crypto

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// REVIEW-ENCRYPTIONOPS-1 F6: a shamir_commitment of only whitespace decoded to
// zero bytes, so KEK() skipped the commitment check AND the #429 warning that an
// unset commitment logs: the forgeable magic-byte check was the only one left,
// silently. Blank now counts as unset (warned), and a commitment of the wrong
// length is refused with an error that says so.
func TestShamirKeyProvider_BlankCommitmentWarnsLikeUnset(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 3, 2)
	require.NoError(t, err)
	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))

	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	got, err := NewShamirKeyProvider([]string{f1, f2}, nil, " \n\t").KEK()
	require.NoError(t, err)
	require.Equal(t, kek, got)
	require.Contains(t, buf.String(), "no shamir_commitment configured",
		"a blank shamir_commitment disabled the commitment check without the #429 warning")
}

func TestShamirKeyProvider_WrongLengthCommitmentRefusedAsSuch(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 3, 2)
	require.NoError(t, err)
	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))

	truncated := hex.EncodeToString(CommitKEK(kek))[:32]
	_, err = NewShamirKeyProvider([]string{f1, f2}, nil, truncated).KEK()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "64 hex"), "got: %v", err)
}
