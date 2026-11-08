package backupfmt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// mutation must leave the manifest semantically identical and every other tar
// entry byte-identical, otherwise it is a silent accept. See
// internal/verifierflip/PREREG.md.
func TestArchiveBitFlip(t *testing.T) {
	o := verifierflip.DefaultOptions(1)
	o.SkipTiming = true // I/O bound (temp dir per call); timing is covered by the pure-MAC targets
	rep, err := verifierflip.Run(archiveBitFlipTarget(t, ExtractArchive), o)
	require.NoError(t, err)
	t.Logf("%s mutations=%d reject=%d equiv=%d DIFFERENT=%d PANIC=%d", rep.Target, rep.Mutations, rep.Rejects, rep.Equivalent, rep.Different, rep.Panics)
	for k, n := range rep.ByRegion {
		t.Logf("    %s x%d", k, n)
	}
	// Reviewed equivalents (PREREG "Verdicts"): gzip framing that is not
	// content or is never read, because extraction stops at the tar
	// end-of-archive. Canon is the signed manifest plus a digest of every other
	// tar entry, so these classes cannot hide a changed entry.
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

// archiveBitFlipTarget builds the archive target around extract, so planted
// defects run through the same Canon as the real ExtractArchive.
func archiveBitFlipTarget(t *testing.T, extract func(io.Reader, string, int64, int64) (Manifest, error)) verifierflip.Target {
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
		m, err := extract(bytes.NewReader(b), dir, 0, 0)
		if err != nil || !VerifyManifestSignature(m, key) {
			return Manifest{}, false
		}
		return m, true
	}
	return verifierflip.Target{
		Name: "backup-archive-extract-and-verify", Artifact: archive.Bytes(),
		Verify: func(b []byte) bool { _, ok := verify(b); return ok },
		Canon: func(b []byte) string {
			m, _ := verify(b)
			o, _ := json.Marshal(m)
			// MANIFEST.json is left out: m already carries its meaning, and JSON
			// whitespace in it is free.
			return string(o) + "|" + verifierflip.GzipTarDigest(b, "MANIFEST.json")
		},
		Region: verifierflip.GzipRegion(archive.Len()),
	}
}

// TestArchiveBitFlip_IgnoringEntryDigestIsDifferent: an extractor that still
// enforces the entry set and sizes but no longer compares entry digests returns
// the same manifest for changed entries, so a Canon of the manifest alone
// reports those accepts as equivalent.
func TestArchiveBitFlip_IgnoringEntryDigestIsDifferent(t *testing.T) {
	o := verifierflip.DefaultOptions(1)
	o.SkipTiming = true
	rep, err := verifierflip.Run(archiveBitFlipTarget(t, extractWithoutDigestCheck), o)
	require.NoError(t, err)
	if rep.Different == 0 || rep.Panics != 0 {
		t.Fatalf("planted defect not reported as ACCEPT-DIFFERENT: different=%d equiv=%d panics=%d", rep.Different, rep.Equivalent, rep.Panics)
	}
}

// extractWithoutDigestCheck is ExtractArchive with the per-entry sha256 compare
// removed: manifest position, entry set and sizes are still checked.
func extractWithoutDigestCheck(r io.Reader, _ string, _, _ int64) (Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return Manifest{}, err
	}
	tr := tar.NewReader(gz)
	h, err := tr.Next()
	if err != nil {
		return Manifest{}, err
	}
	if h.Name != "MANIFEST.json" {
		return Manifest{}, fmt.Errorf("first entry %q", h.Name)
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, err
	}
	sizes := make(map[string]int64, len(m.KeyFiles)+len(m.Tables))
	for _, kf := range m.KeyFiles {
		sizes[kf.TarName] = kf.Size
	}
	for _, te := range m.Tables {
		sizes[te.TarName] = te.UncompressedSize
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, err
		}
		if want, ok := sizes[h.Name]; !ok || h.Size != want {
			return Manifest{}, fmt.Errorf("unlisted, duplicate or resized entry %q", h.Name)
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return Manifest{}, err
		}
		delete(sizes, h.Name)
	}
	if len(sizes) != 0 {
		return Manifest{}, fmt.Errorf("%d entries missing", len(sizes))
	}
	return m, nil
}
