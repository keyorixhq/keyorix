// bundle_coverage_test.go — targeted coverage uplift for the remaining uncovered
// branches after s18/s24/s25/s26/extra/main test files.
//
// Gaps targeted:
//   - WriteBundle: writeTarBytes(sigName) error path
//   - WriteBundle: tw.WriteHeader component error + f.Close() side effect
//   - WriteBundle: io.Copy(tw, f) error + f.Close() side effect
//   - WriteBundle: tw.Close() error
//   - streamBundleComponents: cleanComponentPath error for a bad-path tar entry
//   - streamComponent: n != comp.Size in extract mode (tar header size < manifest size)
//   - mkdirAllNoSymlink: os.Mkdir error (parent is read-only)
//   - safeJoin: valid path — additional branch confirmation
//   - readNamedEntry: io.ReadAll on LimitReader via large-enough body
//   - Sign: happy path with components that exercise MarshalCanonical sorting
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// countingErrorWriter — returns a hard error on write call number failOnCall.
// All prior writes succeed (returning len(p), nil). This reliably surfaces
// write errors through gzip/tar buffering by failing at a specific call.
// ---------------------------------------------------------------------------

type countingErrorWriter struct {
	callNum    int // current call counter (1-based)
	failOnCall int // fail starting from this call number
	buf        bytes.Buffer
}

func (w *countingErrorWriter) Write(p []byte) (int, error) {
	w.callNum++
	if w.callNum >= w.failOnCall {
		return 0, errors.New("countingErrorWriter: injected write error")
	}
	return w.buf.Write(p)
}

// ---------------------------------------------------------------------------
// WriteBundle — error injection at various write-call points
//
// gzip.NewWriter buffers internally. For small inputs, ALL data is buffered
// in-memory until gz.Close() which issues the actual Write calls to the
// underlying writer. We use large component data (≥32KB) to force gzip
// block-level flushes during the in-progress writes, making the error paths
// inside the for loop reachable.
// ---------------------------------------------------------------------------

// TestWriteBundle_Cov_WriteErrors exercises multiple error branches in
// WriteBundle by scanning through write-call failure points. With a large
// enough component the gzip layer must flush mid-stream, making all the
// error branches (sigName write, WriteHeader, io.Copy, tw.Close) reachable.
func TestWriteBundle_Cov_WriteErrors(t *testing.T) {
	// Use a 64KB component to force gzip to flush multiple blocks during the
	// WriteBundle call rather than deferring everything to gz.Close().
	largeContent := strings.Repeat("K", 64*1024)
	dir := srcDirWith(t, map[string]string{"big.bin": largeContent})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	m, err := BuildManifest(dir, "v1.0.0", "k-large", "", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)
	sig, err := Sign(m, priv)
	require.NoError(t, err)

	// Measure total write calls for a successful bundle write.
	counter := &countingErrorWriter{failOnCall: 10000} // very high; won't fail
	require.NoError(t, WriteBundle(counter, dir, m, sig))
	totalCalls := counter.callNum

	// Probe every possible failure point. At least one must return an error.
	// We track which calls produced errors to verify coverage hits differ.
	var errCount int
	for n := 1; n <= totalCalls; n++ {
		w := &countingErrorWriter{failOnCall: n}
		if err := WriteBundle(w, dir, m, sig); err != nil {
			errCount++
		}
	}
	assert.Greater(t, errCount, 0,
		"at least one write-call injection must cause WriteBundle to fail")
}

// ---------------------------------------------------------------------------
// streamBundleComponents — cleanComponentPath error for bad-path tar entry
// ---------------------------------------------------------------------------

// TestVerify_Cov_BadPathInTarEntry exercises the cleanComponentPath error
// branch inside streamBundleComponents. We craft a bundle that contains a
// valid manifest + sig but then a tar component entry whose name is an
// absolute path (e.g. "/etc/passwd") — cleanComponentPath rejects it.
func TestVerify_Cov_BadPathInTarEntry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dir := srcDirWith(t, map[string]string{"legit.bin": "data"})
	m, err := BuildManifest(dir, "v1.0.0", "k-bad-path", "", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)
	sig, err := Sign(m, priv)
	require.NoError(t, err)
	manifestBytes, err := m.MarshalCanonical()
	require.NoError(t, err)

	// Build a bundle manually: manifest + sig are real, but the component
	// entry has an absolute path name — this passes through readNamedEntry
	// (which only reads manifest.json and manifest.sig) and into the component
	// loop where cleanComponentPath will reject the absolute path.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	writeRegEntry := func(name string, body []byte) {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		require.NoError(t, tw.WriteHeader(hdr))
		_, _ = tw.Write(body)
	}
	writeRegEntry(manifestName, manifestBytes)
	writeRegEntry(sigName, sig)
	// Component with an absolute path — cleanComponentPath must reject this.
	writeRegEntry("/etc/passwd", []byte("data"))
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, "k-bad-path", pub))

	_, err = Verify(bytes.NewReader(buf.Bytes()), reg)
	assert.Error(t, err, "Verify must reject a bundle containing a component with an absolute path")
}

// ---------------------------------------------------------------------------
// streamComponent — n != comp.Size in extract mode
// ---------------------------------------------------------------------------

// TestExtract_Cov_SizeMismatchExtractMode exercises the n != comp.Size branch
// inside streamComponent when running in extract mode (destDir is set).
// We craft a bundle where the manifest records Size=10 for a component, but
// the tar entry's header also claims Size=10 while only providing 4 actual
// bytes — so LimitReader(tr, 11) reads 4 bytes, n=4 != comp.Size=10.
//
// To achieve "tar header says 4 but we need manifest to say 10": we build the
// manifest separately with a fake size, then craft the tar entry to match the
// tar-level expectation. The trick: manifest.Components[0].Size = 10, but the
// tar entry has Size = 4 in its own header, so tar delivers only 4 bytes before
// EOF for that entry. LimitReader reads 4 bytes, n=4 != manifest_comp.Size=10.
func TestExtract_Cov_SizeMismatchExtractMode(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Build a real manifest for a file with 10 bytes.
	dir := srcDirWith(t, map[string]string{"cov.bin": strings.Repeat("X", 10)})
	m, err := BuildManifest(dir, "v1.0.0", "k-sizemm", "", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)

	// m.Components[0].Size == 10. Sign the real manifest.
	sig, err := Sign(m, priv)
	require.NoError(t, err)
	manifestBytes, err := m.MarshalCanonical()
	require.NoError(t, err)

	// Now build a tar where the component's tar-level Size = 4 (only 4 bytes
	// of content). streamComponent will LimitReader(tr, 10+1) but tar only
	// delivers 4 bytes before advancing to the next entry. n=4 != comp.Size=10.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	writeRegEntry := func(name string, body []byte) {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		require.NoError(t, tw.WriteHeader(hdr))
		_, _ = tw.Write(body)
	}
	writeRegEntry(manifestName, manifestBytes)
	writeRegEntry(sigName, sig)
	// Tar-level size = 4, but manifest says Size = 10.
	writeRegEntry("cov.bin", []byte("abcd")) // only 4 bytes
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, "k-sizemm", pub))

	dest := t.TempDir()
	_, err = Extract(bytes.NewReader(buf.Bytes()), reg, dest, "")
	// The size mismatch (n=4 != comp.Size=10) triggers ErrDigestMismatch.
	assert.True(t, errors.Is(err, ErrDigestMismatch),
		"expected ErrDigestMismatch for size mismatch in extract mode, got: %v", err)
}

// ---------------------------------------------------------------------------
// mkdirAllNoSymlink — os.Mkdir error (parent directory is read-only)
// ---------------------------------------------------------------------------

// TestMkdirAllNoSymlink_Cov_MkdirPermissionDenied exercises the os.Mkdir
// error branch: the target sub-directory does not yet exist (IsNotExist for
// Lstat) but its parent is read-only so Mkdir fails with EPERM/EACCES.
func TestMkdirAllNoSymlink_Cov_MkdirPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks; skip")
	}

	root := t.TempDir()
	// Create a subdirectory inside root and make it read-only.
	readonlyParent := filepath.Join(root, "readonly")
	require.NoError(t, os.Mkdir(readonlyParent, 0o755))
	require.NoError(t, os.Chmod(readonlyParent, 0o555))
	t.Cleanup(func() { _ = os.Chmod(readonlyParent, 0o755) })

	// Try to create a child under the read-only parent.
	target := filepath.Join(readonlyParent, "child")
	err := mkdirAllNoSymlink(readonlyParent, target)
	assert.Error(t, err, "mkdirAllNoSymlink must fail when the parent directory is read-only")
}

// ---------------------------------------------------------------------------
// safeJoin — additional coverage: valid nested path with multiple segments
// ---------------------------------------------------------------------------

// TestSafeJoin_Cov_MultiSegmentValidPath verifies that safeJoin accepts a
// deeply nested path and returns the correct joined result.
func TestSafeJoin_Cov_MultiSegmentValidPath(t *testing.T) {
	dir := t.TempDir()
	result, err := safeJoin(dir, "a/b/c/d.tar")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, dir),
		"safeJoin result must be inside destDir: got %q", result)
	assert.True(t, strings.HasSuffix(result, filepath.Join("a", "b", "c", "d.tar")),
		"safeJoin result must end with the expected relative path: got %q", result)
}

// ---------------------------------------------------------------------------
// WriteBundle — complete round-trip verifying output structure
// ---------------------------------------------------------------------------

// TestWriteBundle_Cov_OutputStructure writes a bundle to a temp file and
// verifies the output directory structure after extraction, exercising
// WriteBundle's happy path more thoroughly (more components, nested paths).
func TestWriteBundle_Cov_OutputStructure(t *testing.T) {
	files := map[string]string{
		"charts/keyorix-1.0.0.tgz":     "chart-bytes",
		"images/server.tar":            "image-bytes",
		"crds/secrets.keyorix.io.yaml": "crd-bytes",
		"bin/keyorix":                  "binary-bytes",
	}
	dir := srcDirWith(t, files)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	m, err := BuildManifest(dir, "v1.0.0", "test-key", "", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)

	sig, err := Sign(m, priv)
	require.NoError(t, err)

	// Write to an in-memory buffer.
	var buf bytes.Buffer
	err = WriteBundle(&buf, dir, m, sig)
	require.NoError(t, err)
	assert.Greater(t, buf.Len(), 0, "WriteBundle must produce non-empty output")

	// Verify the bundle and confirm all 4 components are present.
	pub := priv.Public().(ed25519.PublicKey)
	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, "test-key", pub))

	got, err := Verify(bytes.NewReader(buf.Bytes()), reg)
	require.NoError(t, err)
	assert.Equal(t, "v1.0.0", got.Version)
	assert.Len(t, got.Components, 4, "all 4 components must be in the verified manifest")
}

// ---------------------------------------------------------------------------
// Sign — verify signature is valid for the manifest bytes (exercises MarshalCanonical
// sorting branch and sign path)
// ---------------------------------------------------------------------------

// TestSign_Cov_MultipleComponents verifies Sign produces a valid signature
// for a manifest with many components, exercising the MarshalCanonical sort.
func TestSign_Cov_MultipleComponents(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	components := []Component{
		{Path: "z/last.bin", SHA256: strings.Repeat("a", 64), Size: 10},
		{Path: "a/first.bin", SHA256: strings.Repeat("b", 64), Size: 20},
		{Path: "m/mid.bin", SHA256: strings.Repeat("c", 64), Size: 30},
	}
	m := &Manifest{
		Version:    "v2.0.0",
		KeyID:      "sig-key",
		ReleasedAt: time.Unix(1_700_000_000, 0),
		Components: components,
	}

	sig, err := Sign(m, priv)
	require.NoError(t, err)
	assert.Len(t, sig, ed25519.SignatureSize, "signature must be 64 bytes")

	// Verify: MarshalCanonical should produce the same bytes as Sign uses.
	canonical, err := m.MarshalCanonical()
	require.NoError(t, err)
	pub := priv.Public().(ed25519.PublicKey)
	assert.True(t, ed25519.Verify(pub, canonical, sig), "signature must verify against canonical bytes")

	// The original component order must not have been mutated.
	assert.Equal(t, "z/last.bin", m.Components[0].Path, "Sign must not mutate the receiver")
}

// ---------------------------------------------------------------------------
// readNamedEntry — exercises a large manifest entry (approaching maxManifestBytes
// boundary) to confirm the LimitReader path is exercised
// ---------------------------------------------------------------------------

// TestReadNamedEntry_Cov_LargeManifest builds a bundle with an unusually large
// manifest.json (many components) and verifies it round-trips correctly, exercising
// the io.ReadAll path with meaningful data volume.
func TestReadNamedEntry_Cov_LargeManifest(t *testing.T) {
	// Build a srcDir with 50 files to produce a large manifest.
	files := make(map[string]string, 50)
	for i := range 50 {
		files[strings.Repeat(string(rune('a'+i%26)), 3)+"/file.bin"] = strings.Repeat("x", i+1)
	}
	dir := srcDirWith(t, files)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	m, err := BuildManifest(dir, "v1.0.0", "large-key", "", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)
	sig, err := Sign(m, priv)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, WriteBundle(&buf, dir, m, sig))

	pub := priv.Public().(ed25519.PublicKey)
	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, "large-key", pub))

	got, err := Verify(bytes.NewReader(buf.Bytes()), reg)
	require.NoError(t, err)
	// Confirm 50 components were read through the readNamedEntry path.
	assert.Equal(t, len(files), len(got.Components))
}

// ---------------------------------------------------------------------------
// streamComponent — safeJoin error in extract mode via invalid component path
// ---------------------------------------------------------------------------

// TestStreamComponent_Cov_InvalidPath exercises the safeJoin error return
// inside streamComponent (extract mode) by calling it directly with an
// invalid component path (empty string, which cleanComponentPath rejects).
func TestStreamComponent_Cov_InvalidPath(t *testing.T) {
	dest := t.TempDir()
	comp := Component{Path: "", SHA256: strings.Repeat("0", 64), Size: 0}
	// streamComponent will call safeJoin(dest, "") → cleanComponentPath("") → error.
	err := streamComponent(io.LimitReader(strings.NewReader(""), 0), comp, dest)
	assert.Error(t, err, "streamComponent must fail for an empty component path")
}

// ---------------------------------------------------------------------------
// mkdirAllNoSymlink — root == dir (rel == ".") path plus already-existing dir
// ---------------------------------------------------------------------------

// TestMkdirAllNoSymlink_Cov_RootEqualsTarget verifies the case where root and
// dir are the same existing directory — rel is ".", no mkdir needed.
func TestMkdirAllNoSymlink_Cov_RootEqualsTarget(t *testing.T) {
	root := t.TempDir()
	err := mkdirAllNoSymlink(root, root)
	assert.NoError(t, err, "mkdirAllNoSymlink with root==dir must succeed for an existing directory")
}

// ---------------------------------------------------------------------------
// WriteBundle — missing component file in srcDir (covers os.Open error path)
// ---------------------------------------------------------------------------

// TestWriteBundle_Cov_ComponentFileDisappears verifies that WriteBundle returns
// an error when a component listed in the manifest cannot be opened (file was
// removed from srcDir between BuildManifest and WriteBundle).
func TestWriteBundle_Cov_ComponentFileDisappears(t *testing.T) {
	dir := srcDirWith(t, map[string]string{"gone.bin": "data"})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	m, err := BuildManifest(dir, "v1.0.0", "k", "", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)
	sig, err := Sign(m, priv)
	require.NoError(t, err)

	// Remove the file after building the manifest.
	require.NoError(t, os.Remove(filepath.Join(dir, "gone.bin")))

	var buf bytes.Buffer
	err = WriteBundle(&buf, dir, m, sig)
	assert.Error(t, err, "WriteBundle must fail when a component file is missing from srcDir")
}
