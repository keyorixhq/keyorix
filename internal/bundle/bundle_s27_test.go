// bundle_s27_test.go — additional coverage uplift targeting branches still uncovered after
// s18/s24/s25/s26/extra/coverage/main test files (baseline 91.3% statements per the coverage
// campaign; see bundle_s26_test.go's header for the branches it already closed).
//
// Gaps targeted here:
//   - Sign / WriteBundle: MarshalCanonical error path (a manifest whose ReleasedAt year is
//     outside time.Time's JSON-encodable range [0,9999] makes json.MarshalIndent fail)
//   - process: writeInstalledVersion error AFTER a genuinely clean staging pass (a
//     zero-component manifest, so the failure is isolated to the final marker write and
//     not masked by an earlier component-staging failure on the same read-only dest)
//   - streamBundleComponents: the blanket entries>maxComponentEntries cap, exercised via
//     non-regular (directory) entries that never reach the duplicate-name check
//   - streamComponent: n != comp.Size with NO copy error (a source that ends cleanly, via
//     io.EOF, before satisfying the pinned size — distinct from the copyErr branch already
//     covered by TestStreamComponent_S26_CopyError)
//   - readNamedEntry: tr.Read() failing mid-entry for the manifest itself (declared size
//     under the cap, but the archive's body bytes are absent)
//   - hashFile: io.Copy error when the opened path is a directory (open succeeds, read
//     fails) — distinct from the already-covered os.Open permission-denied branch
//   - streamBundleComponents: tr.Next() returning a genuine non-EOF error (a corrupt,
//     full-length-but-invalid tar header block after the manifest+sig entries — as opposed
//     to a clean/EOF-terminated stream or a short trailing fragment, both of which the tar
//     reader treats as ordinary EOF, not an error)
//
// Branches deliberately NOT targeted (documented here rather than left silently unexplained):
//   - BuildManifest's filepath.Rel error and WriteBundle's f.Close() error: both require an
//     OS-level failure mode (a differing filesystem "volume", a Close() syscall failure) with
//     no portable way to force it from a normal Go test.
//   - mkdirAllNoSymlink's / safeJoin's filepath.Abs error branches: only reachable if
//     os.Getwd() fails, which requires a deleted cwd — confirmed NOT to error on macOS
//     (getcwd is cached/resolved via fcntl(F_GETPATH) even after the directory is removed),
//     so a test relying on it would be silently no-op on this platform and is not worth the
//     portability risk.
//   - mkdirAllNoSymlink's `part == ""` branch and safeJoin's escape-check branch: both sit
//     downstream of cleanComponentPath, which already rejects the inputs (".", "..", leading
//     "/") that would be needed to produce an empty path segment or an escaping join — see
//     bundle_s26_test.go's TestSafeJoin_S26_ValidNestedPath comment, which reached the same
//     conclusion for the safeJoin branch.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Sign / WriteBundle — MarshalCanonical error path
// ---------------------------------------------------------------------------

// TestSign_S27_MarshalCanonicalError verifies Sign propagates a MarshalCanonical failure
// instead of signing whatever partial bytes json.MarshalIndent managed to produce. A
// ReleasedAt year outside [0,9999] is the one field on Manifest whose JSON encoding can
// fail (time.Time.MarshalJSON explicitly rejects it), so this is a real, reachable failure
// mode rather than a contrived one.
func TestSign_S27_MarshalCanonicalError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	m := &Manifest{
		Version:    "v1.0.0",
		KeyID:      "s27-badyear",
		ReleasedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	_, err = Sign(m, priv)
	assert.Error(t, err, "Sign must propagate a MarshalCanonical failure instead of signing garbage")
}

// TestWriteBundle_S27_MarshalCanonicalError verifies WriteBundle fails before writing any
// tar entry when the manifest itself can't be canonically marshaled.
func TestWriteBundle_S27_MarshalCanonicalError(t *testing.T) {
	m := &Manifest{
		Version:    "v1.0.0",
		KeyID:      "s27-badyear2",
		ReleasedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	var buf bytes.Buffer
	err := WriteBundle(&buf, t.TempDir(), m, []byte("sig"))
	assert.Error(t, err, "WriteBundle must propagate a MarshalCanonical failure before writing anything")
	assert.Zero(t, buf.Len(), "nothing should be written to w once MarshalCanonical fails")
}

// ---------------------------------------------------------------------------
// process — writeInstalledVersion error isolated from earlier staging failures
// ---------------------------------------------------------------------------

// TestExtract_S27_MarkerWriteFailsZeroComponents targets the writeInstalledVersion error
// branch specifically — as opposed to the existing read-only-dest tests (e.g.
// TestExtract_S25_MarkerWriteFailure, TestExtract_S26_MarkerWriteFailsAfterStaging), which
// use a manifest with at least one component and so actually fail earlier, at component
// staging (CreateTemp into the read-only dir), never reaching the marker write at all. A
// zero-component manifest is a legitimate (if degenerate) bundle: it still needs a
// signature and a key-id, and process() still runs staging + the final marker write, but
// staging itself never touches the filesystem, so a read-only dest is guaranteed to fail
// exactly at, and only at, the marker write.
func TestExtract_S27_MarkerWriteFailsZeroComponents(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks; skip")
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	m := &Manifest{Version: "v1.0.0", KeyID: "s27-marker", ReleasedAt: time.Unix(1_700_000_000, 0)}
	sig, err := Sign(m, priv)
	require.NoError(t, err)

	var buf bytes.Buffer
	// srcDir is irrelevant: m.Components is empty, so WriteBundle's component loop never
	// runs and never touches srcDir.
	require.NoError(t, WriteBundle(&buf, t.TempDir(), m, sig))

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, "s27-marker", pub))

	dest := t.TempDir()
	require.NoError(t, os.Chmod(dest, 0o555)) // read+execute only: no write
	t.Cleanup(func() { _ = os.Chmod(dest, 0o755) })

	_, err = Extract(bytes.NewReader(buf.Bytes()), reg, dest, "")
	require.Error(t, err, "writing the installed-version marker into a read-only, otherwise-untouched destination must fail")
	assert.Contains(t, err.Error(), "installed-version marker", "error should identify the marker write as the failure point")
}

// ---------------------------------------------------------------------------
// streamBundleComponents — the blanket entries>maxComponentEntries cap
// ---------------------------------------------------------------------------

// TestVerify_S27_TooManyNonRegularEntries verifies the general entries++ cap fires on its
// own, independent of the (cheaper, more specific) duplicate-name check. The existing
// TestVerify_RejectsThousandsOfRepeatedValidEntries repeats one regular-file component name,
// which trips ErrDuplicateComponent on its second iteration — long before entries could ever
// reach maxComponentEntries. Directory-type entries are never regular files, so they skip
// the name/duplicate checks entirely (via the `continue` below the Typeflag check) and so
// are the only way to actually drive the entries counter past the cap.
func TestVerify_S27_TooManyNonRegularEntries(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	m := &Manifest{Version: "v1.0.0", KeyID: "s27-many", ReleasedAt: time.Unix(1_700_000_000, 0)}
	sig, err := Sign(m, priv)
	require.NoError(t, err)
	manifestBytes, err := m.MarshalCanonical()
	require.NoError(t, err)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	putReg := func(name string, b []byte) {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}))
		_, werr := tw.Write(b)
		require.NoError(t, werr)
	}
	putReg(manifestName, manifestBytes)
	putReg(sigName, sig)
	for i := range maxComponentEntries + 1 {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     fmt.Sprintf("dir-%d/", i),
			Mode:     0o755,
			Typeflag: tar.TypeDir,
		}))
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, "s27-many", pub))

	_, err = Verify(bytes.NewReader(buf.Bytes()), reg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyEntries)
}

// ---------------------------------------------------------------------------
// streamComponent — size mismatch with a clean EOF (no copy error)
// ---------------------------------------------------------------------------

// TestStreamComponent_S27_ShortReadCleanEOF covers the n != comp.Size branch when the
// underlying reader simply runs out of bytes (io.Copy treats that as a normal end, not an
// error) — distinct from TestStreamComponent_S26_CopyError, which forces an actual I/O
// error. A source that legitimately ends early without erroring (e.g. a well-behaved
// io.Reader wrapping fewer bytes than the pinned size) must still be rejected as a digest
// mismatch, not silently accepted as a short write.
func TestStreamComponent_S27_ShortReadCleanEOF(t *testing.T) {
	comp := Component{Path: "x.bin", SHA256: strings.Repeat("0", 64), Size: 1000}
	err := streamComponent(strings.NewReader("short content, well under the pinned size"), comp, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDigestMismatch, "a source that ends cleanly before the pinned size must still be rejected")
}

// ---------------------------------------------------------------------------
// readNamedEntry — tr.Read() failing mid-entry for the manifest itself
// ---------------------------------------------------------------------------

// TestVerify_S27_TruncatedManifestBody verifies readNamedEntry propagates a read failure
// when a tar entry declares a size UNDER the size cap (so the early declared-size check
// doesn't fire) but the archive's actual body bytes are absent — the archive ends before
// satisfying the header's own declared size. writeRawBundleOversizedEntry writes exactly
// this shape (a header with no following body, gz.Close() called directly); it is normally
// used with a declaredSize ABOVE the cap to test the size-cap rejection, but reusing it with
// a modest size below the cap instead exercises the read-error branch this test targets.
func TestVerify_S27_TruncatedManifestBody(t *testing.T) {
	raw := writeRawBundleOversizedEntry(t, nil, nil, manifestName, 1000)
	reg := trust.NewRegistry()
	_, err := Verify(bytes.NewReader(raw), reg)
	require.Error(t, err, "a manifest entry shorter than its own declared header size must fail while reading, not silently truncate")
}

// ---------------------------------------------------------------------------
// hashFile — io.Copy error (open succeeds, read fails)
// ---------------------------------------------------------------------------

// TestHashFile_S27_DirectoryReadError covers hashFile's io.Copy error return, distinct from
// TestBuildManifest_Cov_HashFileUnreadable / TestHashFile_S25_FileNotFound which both fail at
// os.Open. Opening a directory succeeds (os.Open works on directories), but reading its
// contents as a byte stream fails at the first Read — this is the only portable, no-mocking
// way to separate the "open failed" and "read failed" branches of hashFile.
func TestHashFile_S27_DirectoryReadError(t *testing.T) {
	dir := t.TempDir()
	_, _, err := hashFile(dir)
	assert.Error(t, err, "hashFile must fail when the read (not the open) of the target path fails")
}

// ---------------------------------------------------------------------------
// streamBundleComponents — tr.Next() returning a genuine non-EOF error
// ---------------------------------------------------------------------------

// TestVerify_S27_CorruptTarHeaderAfterSig verifies streamBundleComponents propagates a
// tr.Next() failure that is a real parse error, not end-of-archive. A full 512-byte block of
// non-zero garbage right after a valid manifest+sig fails tar's header checksum validation —
// unlike simply truncating the stream (which the tar reader treats as ordinary EOF, already
// exercised by TestVerify_S26_CorruptTarAfterSig and friends), a complete-but-invalid block
// is what actually drives tr.Next() down the err != nil (and NOT io.EOF) branch.
func TestVerify_S27_CorruptTarHeaderAfterSig(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	m := &Manifest{Version: "v1.0.0", KeyID: "s27-corrupt", ReleasedAt: time.Unix(1_700_000_000, 0)}
	sig, err := Sign(m, priv)
	require.NoError(t, err)
	manifestBytes, err := m.MarshalCanonical()
	require.NoError(t, err)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	putReg := func(name string, b []byte) {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}))
		_, werr := tw.Write(b)
		require.NoError(t, werr)
	}
	putReg(manifestName, manifestBytes)
	putReg(sigName, sig)
	// Deliberately skip tw.Close() (which would append the proper end-of-archive zero
	// blocks) and instead write one full, non-zero, non-header-shaped block directly to the
	// underlying gzip stream — a complete block the tar reader will attempt to parse as a
	// header and reject on checksum, rather than a short/absent tail it would treat as EOF.
	_, werr := gz.Write(bytes.Repeat([]byte{0x41}, 512))
	require.NoError(t, werr)
	require.NoError(t, gz.Close())

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, "s27-corrupt", pub))

	_, err = Verify(bytes.NewReader(buf.Bytes()), reg)
	require.Error(t, err, "a corrupt (not merely truncated) tar header after the manifest+sig must fail Verify")
	assert.Contains(t, err.Error(), "read archive", "error should identify the archive-read failure, not a signature or digest mismatch")
}
