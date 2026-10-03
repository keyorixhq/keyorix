package backupfmt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
)

// allowedTarMember is the complete set of member-name shapes writeBackupModels
// produces: the manifest, caller-supplied key files (server/admin names them
// keyfiles/<i>), and one NDJSON file per table.
var allowedTarMember = regexp.MustCompile(`^(MANIFEST\.json|keyfiles/[0-9]+|tables/[a-z0-9_]+\.ndjson)$`)

// TestBackupArchive_NeverContainsAuditHighWaterWitness guards the archive half
// of INV-AUDITVERIFY-11: the audit high-water witness must never be a backup
// tar member. `admin restore` compares the archive's recorded high-water mark
// against the host-local witness; if the witness travelled inside the archive,
// a restore would compare the archive against its own old mark and prove
// nothing.
//
// The key files are built exactly as server/admin's readKeyFilesForBackup
// does (keyfiles.Registry, then read each path), from a directory that holds
// the database, the witness, and the key files side by side. The archive's
// member set is then checked closed-world: every member must be one of the
// shapes writeBackupModels is known to emit, none may carry the witness's
// name, and none may carry the witness's bytes.
//
// What this does not cover: server/admin's readKeyFilesForBackup itself (it
// is mirrored here, not called), and a config that names the witness file
// directly as a key path.
func TestBackupArchive_NeverContainsAuditHighWaterWitness(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"kek.salt", "dek.key", "kek.tpm", "keyorix.db"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("key-material-"+name), 0600))
	}
	witnessCP := &auditverify.Checkpoint{ChainedEvents: 99, HeadID: 99, HeadHash: "witnesshead", KeyVersion: "v1"}
	witnessValue := auditverify.EncodeHighWater(witnessCP, "witnesssig")
	witnessPath := auditverify.WitnessPath(filepath.Join(dir, "keyorix.db"))
	wrote, err := auditverify.WriteWitnessIfHigher(witnessPath, witnessValue)
	require.NoError(t, err)
	require.True(t, wrote)
	witnessBytes, err := os.ReadFile(witnessPath)
	require.NoError(t, err)

	enc := &config.EncryptionConfig{
		SaltPath:    "kek.salt",
		DEKPath:     "dek.key",
		KeyProvider: config.KeyProviderConfig{Type: "tpm", WrappedKeyPath: "kek.tpm"},
	}
	specs, err := keyfiles.Registry(enc, dir)
	require.NoError(t, err)

	keyEntries := make([]KeyFileEntry, len(specs))
	keyBlobs := make([][]byte, len(specs))
	for i, spec := range specs {
		data, rerr := os.ReadFile(spec.Path)
		require.NoError(t, rerr)
		sum := sha256.Sum256(data)
		keyEntries[i] = KeyFileEntry{
			OriginalPath: spec.Path,
			TarName:      fmt.Sprintf("keyfiles/%d", i),
			Mode:         uint32(spec.Mode),
			SHA256:       hex.EncodeToString(sum[:]),
			Size:         int64(len(data)),
		}
		keyBlobs[i] = data
		require.NotEqual(t, filepath.Clean(witnessPath), filepath.Clean(spec.Path), "the witness must never be a key-file entry")
	}
	require.Len(t, specs, 3, "test bug: expected salt, DEK and wrapped KEK")

	// The archive's own high-water mark (from the DB) is lower than the
	// witness, as it would be for an old backup.
	archiveHW := auditverify.EncodeHighWater(&auditverify.Checkpoint{ChainedEvents: 5, HeadID: 5, HeadHash: "archivehead", KeyVersion: "v1"}, "archivesig")

	db := openTestDB(t)
	var archive bytes.Buffer
	_, err = writeBackupModels(db, testSeedModels(), 1, archiveHW, testManifestKey(), keyEntries, keyBlobs, &archive)
	require.NoError(t, err)

	gz, err := gzip.NewReader(&archive)
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	members := 0
	for {
		hdr, nerr := tr.Next()
		if nerr == io.EOF {
			break
		}
		require.NoError(t, nerr)
		members++
		body, rerr := io.ReadAll(tr)
		require.NoError(t, rerr)

		require.Regexp(t, allowedTarMember, hdr.Name, "unexpected archive member %q: the writer's member set must stay closed", hdr.Name)
		require.NotEqual(t, auditverify.AuditHighWaterWitnessFileName, filepath.Base(hdr.Name), "the witness must never be an archive member")
		require.False(t, strings.Contains(hdr.Name, "highwater-witness"), "member %q looks like the witness", hdr.Name)
		require.False(t, bytes.Contains(body, witnessBytes), "member %q carries the witness file's bytes", hdr.Name)
		require.False(t, bytes.Contains(body, []byte("witnesshead")), "member %q carries the witness's recorded head", hdr.Name)
	}
	require.Equal(t, 1+len(keyEntries)+len(testSeedModels()), members, "test bug: expected manifest + key files + one entry per table")
}
