package crypto

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SECRETENV-TAILS-2 F10, ask secretenv-shamir-share-file-read-policy (answer a):
// a shamir_share_files file that fails the secretenv owner + mode rule is refused
// at read, unconditionally, like shamir_share_env + _FILE and the file KEK
// provider. The provider has no notion of the boot check's warn or grace modes,
// so these cases hold in every one of them.
func TestShamirKeyProvider_ShareFileRefusedAtRead(t *testing.T) {
	kek := testKEK()
	shares, err := SplitKEK(kek, 3, 2)
	require.NoError(t, err)
	commitmentHex := hex.EncodeToString(CommitKEK(kek))

	// writeShares writes all three shares at 0600, then applies mode to the first.
	writeShares := func(t *testing.T, mode os.FileMode) []string {
		dir := t.TempDir()
		paths := make([]string, len(shares))
		for i, s := range shares {
			paths[i] = filepath.Join(dir, "s"+string(rune('1'+i)))
			require.NoError(t, os.WriteFile(paths[i], []byte(hex.EncodeToString(s)), 0o600))
		}
		require.NoError(t, os.Chmod(paths[0], mode))
		return paths
	}
	assertRefused := func(t *testing.T, files []string, wantProblem string) {
		t.Helper()
		got, err := NewShamirKeyProvider(files, nil, commitmentHex).KEK()
		require.Error(t, err, "a share file that fails the rule must refuse the unseal")
		assert.Nil(t, got, "no KEK may come back from a refused read")
		assert.Contains(t, err.Error(), "read share "+files[0], "the error names the file to fix")
		assert.Contains(t, err.Error(), wantProblem)
		assert.Contains(t, err.Error(), "refusing to trust it")
		for _, s := range shares {
			assert.NotContains(t, err.Error(), hex.EncodeToString(s), "never the share itself")
		}
	}

	for _, mode := range []os.FileMode{0o600, 0o400} {
		t.Run("own file at "+mode.String()+" unseals", func(t *testing.T) {
			got, err := NewShamirKeyProvider(writeShares(t, mode)[:2], nil, commitmentHex).KEK()
			require.NoError(t, err)
			assert.Equal(t, kek, got)
		})
	}

	// Loose mode: other-accessible, and group access on a file the server owns.
	for mode, problem := range map[os.FileMode]string{
		0o644: "mode 0644 is too open (accessible to other users)",
		0o604: "mode 0604 is too open (accessible to other users)",
		0o620: "mode 0620 is too open (writable by its group)",
		0o640: "mode 0640 is too open (group-readable but owned by the running user)",
	} {
		t.Run("loose mode "+mode.String()+" is refused", func(t *testing.T) {
			assertRefused(t, writeShares(t, mode)[:2], problem)
		})
	}

	t.Run("wrong owner is refused whatever the mode", func(t *testing.T) {
		files := writeShares(t, 0o600)[:2]
		defer secretenv.OverrideOwnershipForTest(4242, os.Geteuid())()
		assertRefused(t, files, "owned by uid 4242")
	})

	// Enough good shares must not excuse a bad one: dropping it and unsealing from
	// the rest would leave the loose file in place and unreported.
	t.Run("a loose share is refused even when the others reach the threshold", func(t *testing.T) {
		assertRefused(t, writeShares(t, 0o644), "mode 0644 is too open")
	})

	// The rule's one exception, the same as for the env share: an orchestrator
	// mount, root-owned and readable through a group the process holds.
	t.Run("root-owned 0440 mount in a held group unseals", func(t *testing.T) {
		files := writeShares(t, 0o600)
		for _, f := range files[:2] {
			require.NoError(t, os.Chown(f, -1, os.Getegid()))
			require.NoError(t, os.Chmod(f, 0o440))
		}
		defer secretenv.OverrideOwnershipForTest(0, os.Geteuid())()
		got, err := NewShamirKeyProvider(files[:2], nil, commitmentHex).KEK()
		require.NoError(t, err)
		assert.Equal(t, kek, got)
	})
}
