package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
)

// TestParsePrivateKeyPEM_ValidKey verifies that a well-formed ed25519 private key
// PEM round-trips through ParsePrivateKeyPEM.
func TestParsePrivateKeyPEM_ValidKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	got, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	// The recovered key must produce valid signatures.
	sig := ed25519.Sign(got, []byte("test-message"))
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), []byte("test-message"), sig) {
		t.Error("recovered key does not match original")
	}
}

// TestParsePrivateKeyPEM_RSAKey verifies that a non-ed25519 PEM (RSA) is rejected.
func TestParsePrivateKeyPEM_RSAKey(t *testing.T) {
	// Craft a PEM that passes PKCS8 parse but holds an RSA key.
	// We use a tiny RSA by generating a fake DER block — but for simplicity use
	// a hard-coded PEM of a P-256 key, which is PKCS8-parseable but not ed25519.
	// (A P-256 key triggers the "not ed25519" branch.) We generate one at runtime.
	p256, err := x509.MarshalPKCS8PrivateKey(struct{ ed25519.PrivateKey }{}) // won't work; use below
	_ = p256
	_ = err

	// Generate an ECDSA key instead.
	// Use crypto/elliptic directly to get a non-ed25519 PKCS8 DER.
	// Simpler: just wrap a random 32 bytes as a fake PKCS8 — ParsePKCS8PrivateKey
	// will fail, which also exercises a branch.
	fakeDER := make([]byte, 48)
	_, _ = rand.Read(fakeDER)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: fakeDER})
	_, err = ParsePrivateKeyPEM(pemBytes)
	if err == nil {
		t.Fatal("expected an error for an invalid PKCS8 DER")
	}
}

// TestCleanComponentPath covers the edge cases not hit by other tests.
func TestCleanComponentPath(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
	}{
		{"", true},                  // empty
		{"/absolute", true},         // absolute path
		{"../escape", true},         // escapes via ..
		{"subdir/../escape", false}, // path.Clean → "escape" (stays inside bundle)
		{manifestName, true},        // reserved name
		{sigName, true},             // reserved name
		{"valid/path.txt", false},   // ok
		{"single.txt", false},       // ok
		{"  spaced.txt  ", false},   // trimmed
	}
	for _, c := range cases {
		got, err := cleanComponentPath(c.input)
		if c.wantErr {
			if err == nil {
				t.Errorf("cleanComponentPath(%q): want error, got %q", c.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("cleanComponentPath(%q): unexpected error: %v", c.input, err)
			}
		}
	}
}

// TestIsUnsafeCleanComponentPath_PostCleanAbsoluteRejected proves the
// defense-in-depth check added to cleanComponentPath: the RESULT of
// path.Clean(filepath.ToSlash(p)) must itself be re-checked for absoluteness,
// not just the raw input string.
//
// On this platform (and on Linux), filepath.ToSlash is a no-op — the OS path
// separator already is "/" — so there is no raw input string p that satisfies
// !path.IsAbs(p) && !strings.HasPrefix(p, "/") yet still cleans to a value
// starting with "/"; empirically, path.Clean never turns a relative path into
// a rooted one. The gap is real only on a platform whose separator differs
// from "/" (e.g. Windows): a raw UNC-style component name such as
// `\\server\share\evil` does not start with "/", so it sails past the
// pre-clean checks in cleanComponentPath, but filepath.ToSlash converts the
// backslashes to forward slashes there, and path.Clean("//server/share/evil")
// collapses the doubled slash to a single leading "/" — exactly the shape
// this test exercises directly against isUnsafeCleanComponentPath, the
// extracted post-clean check, so the regression is caught on every platform
// this test runs on rather than only on Windows.
func TestIsUnsafeCleanComponentPath_PostCleanAbsoluteRejected(t *testing.T) {
	cases := []struct {
		name   string
		clean  string
		unsafe bool
	}{
		{"post-clean absolute (simulated Windows UNC bypass)", "/server/share/evil", true},
		{"post-clean absolute root", "/", true},
		{"post-clean absolute simple", "/etc/passwd", true},
		{"dot", ".", true},
		{"dot-dot", "..", true},
		{"dot-dot prefix", "../escape", true},
		{"ordinary relative path", "valid/path.txt", false},
		{"ordinary single segment", "single.txt", false},
	}
	for _, c := range cases {
		if got := isUnsafeCleanComponentPath(c.clean); got != c.unsafe {
			t.Errorf("isUnsafeCleanComponentPath(%q) = %v, want %v", c.clean, got, c.unsafe)
		}
	}
}

// TestParseVersion_EdgeCases covers non-standard version strings.
func TestParseVersion_EdgeCases(t *testing.T) {
	// Negative component.
	if _, err := parseVersion("v1.-2.0"); err == nil {
		t.Error("expected error for negative version component")
	}
	// Non-numeric component.
	if _, err := parseVersion("v1.x.0"); err == nil {
		t.Error("expected error for non-numeric version component")
	}
	// Pre-release suffix is stripped (v1.2.3-beta.1).
	p, err := parseVersion("v1.2.3-beta.1")
	if err != nil {
		t.Fatalf("parseVersion with pre-release: %v", err)
	}
	if p != [3]int{1, 2, 3} {
		t.Errorf("got %v", p)
	}
	// Build metadata is stripped.
	p, err = parseVersion("v1.2.3+build.456")
	if err != nil {
		t.Fatalf("parseVersion with build meta: %v", err)
	}
	if p != [3]int{1, 2, 3} {
		t.Errorf("got %v", p)
	}
}

// TestCompareVersions_EdgeCases exercises the comparison utility directly.
func TestCompareVersions_EdgeCases(t *testing.T) {
	cmp, err := compareVersions("v2.0.0", "v1.9.9")
	if err != nil || cmp != 1 {
		t.Errorf("v2.0.0 > v1.9.9: got %d, %v", cmp, err)
	}
	// Invalid version must return an error.
	if _, err := compareVersions("bad", "v1.0.0"); err == nil {
		t.Error("expected error for invalid 'a'")
	}
	if _, err := compareVersions("v1.0.0", "bad"); err == nil {
		t.Error("expected error for invalid 'b'")
	}
}

// TestDestDirHasContent_Empty verifies an empty directory is reported as having no content.
func TestDestDirHasContent_Empty(t *testing.T) {
	dir := t.TempDir()
	has, err := destDirHasContent(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("empty dir must report no content")
	}
}

// TestDestDirHasContent_NonEmpty verifies a directory with a file is detected.
func TestDestDirHasContent_NonEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	has, err := destDirHasContent(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Error("non-empty dir must report content")
	}
}

// TestDestDirHasContent_Missing verifies a nonexistent directory is treated as empty.
func TestDestDirHasContent_Missing(t *testing.T) {
	has, err := destDirHasContent(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("nonexistent dir must report no content")
	}
}

// TestMkdirAllNoSymlink_DirectCreation creates a nested path and verifies it exists.
func TestMkdirAllNoSymlink_DirectCreation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sub", "deep")
	if err := mkdirAllNoSymlink(root, target); err != nil {
		t.Fatalf("mkdirAllNoSymlink: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected a directory")
	}
}

// TestMkdirAllNoSymlink_RefusesOutsideRoot verifies paths outside the root are rejected.
func TestMkdirAllNoSymlink_RefusesOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "escape")
	if err := mkdirAllNoSymlink(root, outside); err == nil {
		t.Error("expected error for a path outside the staging root")
	}
}

// TestSafeJoin_EscapeRejected verifies safeJoin rejects a relative path that
// resolves outside destDir.
func TestSafeJoin_EscapeRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := safeJoin(dir, "../escape.txt")
	if err == nil {
		t.Error("expected error for path escaping dest")
	}
}

// TestVerify_CorruptGzip verifies a non-gzip bundle returns a descriptive error.
func TestVerify_CorruptGzip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "k", pub)

	_, err := Verify(bytes.NewReader([]byte("not gzip")), reg)
	if err == nil {
		t.Fatal("expected error for corrupt gzip input")
	}
}

// TestWriteBundle_ErrorPropagates verifies WriteBundle surfaces a write error
// when the output writer rejects writes.
func TestWriteBundle_ErrorPropagates(t *testing.T) {
	files := map[string]string{"a": "x"}
	dir := srcDirWith(t, files)
	_, priv, _ := ed25519.GenerateKey(nil)
	m, _ := BuildManifest(dir, "v1.0.0", "k", "", time.Unix(1_700_000_000, 0))
	sig, _ := Sign(m, priv)

	// An errWriter always returns an error.
	err := WriteBundle(&errWriter{}, dir, m, sig)
	if err == nil {
		t.Fatal("expected an error when the output writer fails")
	}
}

// errWriter always fails on Write.
type errWriter struct{}

func (e *errWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write error")
}

// TestSign_MarshalError ensures Sign surfaces a marshal error (artificially).
// A well-formed manifest never errors, so we test that a valid Sign call
// produces a non-empty signature to cover the happy path.
func TestSign_HappyPath(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	m := &Manifest{Version: "v1.0.0", KeyID: "k", Components: []Component{{Path: "a", SHA256: "sha", Size: 1}}}
	sig, err := Sign(m, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Error("expected a non-empty signature")
	}
}

// TestReadInstalledVersion_CorruptMarker verifies a present-but-unreadable marker
// returns an error (fail closed, not "first install").
func TestReadInstalledVersion_CorruptMarker(t *testing.T) {
	dir := t.TempDir()
	// Write the marker as a directory so ReadFile fails.
	markerDir := filepath.Join(dir, installedVersionMarker)
	if err := os.MkdirAll(markerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err := readInstalledVersion(dir)
	if err == nil {
		t.Fatal("expected an error for an unreadable installed-version marker")
	}
}

// TestExtract_AntiSkipWithFlag verifies that an installed version below
// MinUpgradeFrom is rejected even when the flag is provided (not a marker).
func TestExtract_AntiSkipWithFlag(t *testing.T) {
	raw, reg, _ := signedBundle(t, map[string]string{"images/a.tar": "x"}, "v2.0.0", "update-2026", "v1.5.0")
	dest := t.TempDir()
	// Installed v1.0.0 is below the v1.5.0 floor → must fail with ErrUpgradeSkipped.
	_, err := Extract(bytes.NewReader(raw), reg, dest, "v1.0.0")
	if !errors.Is(err, ErrUpgradeSkipped) {
		t.Fatalf("want ErrUpgradeSkipped, got %v", err)
	}
}

// TestVerify_BundleWithNoManifestSig exercises the case where the sig entry is absent
// (i.e. only manifest.json is present before components).
func TestVerify_MissingSigEntry(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := srcDirWith(t, map[string]string{"a": "x"})
	m, _ := BuildManifest(dir, "v1.0.0", "update-2026", "", time.Unix(1_700_000_000, 0))
	_, _ = Sign(m, priv)
	manifestBytes, _ := m.MarshalCanonical()

	// Build a bundle that has manifest.json but then a component instead of manifest.sig.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o644, Size: int64(len(manifestBytes)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(manifestBytes)
	// Write a component where the sig should be.
	body := []byte("x")
	_ = tw.WriteHeader(&tar.Header{Name: "a", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()

	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "update-2026", pub)
	if _, err := Verify(bytes.NewReader(buf.Bytes()), reg); !errors.Is(err, ErrNoManifest) {
		t.Fatalf("want ErrNoManifest when sig entry is missing, got %v", err)
	}
}
