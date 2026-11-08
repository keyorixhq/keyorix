package backupfmt

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/verifierflip"
)

// TestArchiveBitFlip drives the whole backup-integrity path (ExtractArchive's
// per-entry sha256 pins + VerifyManifestSignature) through the verifierflip
// mutation set: every single bit of a real gzip+tar backup archive, plus
// truncation, extension, reordering and byte insert/delete. An accepted
// mutation must leave the manifest (which pins every staged file by sha256)
// semantically identical, otherwise it is a silent accept. See
// internal/verifierflip/PREREG.md.
func TestArchiveBitFlip(t *testing.T) {
	src := openTestDB(t)
	require.NoError(t, src.Create(&models.Project{Name: "proj-1"}).Error)
	require.NoError(t, src.Create(&models.User{Username: "alice", Email: "a@example.com", PasswordHash: "alice-hash"}).Error)
	key := testManifestKey()
	var archive bytes.Buffer
	_, err := writeBackupModels(src, []any{&models.Project{}, &models.User{}}, 5, "", key,
		[]KeyFileEntry{{OriginalPath: "dek.key", TarName: "keyfiles/0", Mode: 0600, SHA256: "b5d54c39e66671c9731b9f471e585d8262cd4f54963f0c93082d8dcf334d4c78", Size: 4}},
		[][]byte{[]byte("fake")}, &archive)
	require.NoError(t, err)

	verify := func(b []byte) (Manifest, bool) {
		dir, err := os.MkdirTemp("", "vflip-backup-*")
		if err != nil {
			return Manifest{}, false
		}
		defer func() { _ = os.RemoveAll(dir) }()
		m, err := ExtractArchive(bytes.NewReader(b), dir, 0, 0)
		if err != nil || !VerifyManifestSignature(m, key) {
			return Manifest{}, false
		}
		return m, true
	}
	tg := verifierflip.Target{
		Name: "backup-archive-extract-and-verify", Artifact: archive.Bytes(),
		Verify: func(b []byte) bool { _, ok := verify(b); return ok },
		Canon: func(b []byte) string {
			m, _ := verify(b)
			o, _ := json.Marshal(m)
			return string(o)
		},
		Region: verifierflip.GzipRegion(archive.Len()),
	}
	o := verifierflip.DefaultOptions(1)
	o.SkipTiming = true // I/O bound (temp dir per call); timing is covered by the pure-MAC targets
	rep, err := verifierflip.Run(tg, o)
	require.NoError(t, err)
	t.Logf("%s mutations=%d reject=%d equiv=%d DIFFERENT=%d PANIC=%d", rep.Target, rep.Mutations, rep.Rejects, rep.Equivalent, rep.Different, rep.Panics)
	for k, n := range rep.ByRegion {
		t.Logf("    %s x%d", k, n)
	}
	// Reviewed equivalents (PREREG "Verdicts"): gzip framing that is not
	// content or is never read, because extraction stops at the tar
	// end-of-archive. Canon is the signed manifest, which pins every entry.
	reviewed := []string{"gzip-header|bitflip", "deflate|*", "gzip-trailer|*", "|dup8", "|truncate", "|extend+*"}
	for _, c := range rep.UnexpectedEquivalents(reviewed) {
		t.Errorf("unreviewed ACCEPT-EQUIVALENT class %s", c)
	}
	for _, c := range rep.Candidates {
		if c.Kind == verifierflip.AcceptEquivalent {
			t.Logf("    equivalent example: %s", c.Mutation)
		}
		if c.Kind == verifierflip.Panic || c.Kind == verifierflip.AcceptDifferent {
			t.Errorf("%s %s %s hex=%.120s", c.Kind, c.Mutation, c.Detail, c.Hex)
		}
	}
}
