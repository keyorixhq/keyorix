// bundle_s18_test.go — coverage uplift for WriteBundle (line 183) and
// writeInstalledVersion (line 455).
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeSignedManifestS18 returns a srcDir, Manifest, and signature ready for WriteBundle.
// The component is a single file "component.bin".
func makeSignedManifestS18(t *testing.T) (srcDir string, m *Manifest, sig []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	srcDir = t.TempDir()
	content := "hello bundle s18"
	fpath := filepath.Join(srcDir, "component.bin")
	if err := os.WriteFile(fpath, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	h := sha256.New()
	h.Write([]byte(content))
	digest := hex.EncodeToString(h.Sum(nil))
	m = &Manifest{
		Version:    "0.1.0",
		ReleasedAt: time.Unix(1_700_000_000, 0),
		KeyID:      "test-key",
		Components: []Component{
			{Path: "component.bin", SHA256: digest, Size: int64(len(content))},
		},
	}
	sig, err = Sign(m, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return srcDir, m, sig
}

// TestWriteBundle_S18_HappyPath verifies that WriteBundle produces a non-empty output.
func TestWriteBundle_S18_HappyPath(t *testing.T) {
	srcDir, m, sig := makeSignedManifestS18(t)
	var buf bytes.Buffer
	if err := WriteBundle(&buf, srcDir, m, sig); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("WriteBundle produced empty output")
	}
}

// TestWriteBundle_S18_MissingComponentFile verifies that WriteBundle returns an
// error when a component file listed in the manifest is absent from srcDir.
func TestWriteBundle_S18_MissingComponentFile(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	srcDir := t.TempDir()
	// Manifest references a file that does NOT exist in srcDir.
	m := &Manifest{
		Version:    "0.1.0",
		ReleasedAt: time.Unix(1_700_000_000, 0),
		KeyID:      "test-key",
		Components: []Component{
			{Path: "does-not-exist.bin", SHA256: "aabbcc", Size: 10},
		},
	}
	sig, err := Sign(m, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var buf bytes.Buffer
	err = WriteBundle(&buf, srcDir, m, sig)
	if err == nil {
		t.Fatal("expected error for missing component file, got nil")
	}
}

// TestWriteBundle_S18_MarshalCanonicalSmokeTest verifies MarshalCanonical is
// callable and returns non-empty bytes for a manifest with no components.
func TestWriteBundle_S18_MarshalCanonicalSmokeTest(t *testing.T) {
	m := &Manifest{
		Version:    "1.0.0",
		ReleasedAt: time.Unix(1_700_000_000, 0),
		KeyID:      "k1",
	}
	b, err := m.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("MarshalCanonical returned empty bytes")
	}
}

// ---- writeInstalledVersion tests ----

// TestWriteInstalledVersion_S18_HappyPath verifies that writeInstalledVersion
// creates the marker file with the correct content.
func TestWriteInstalledVersion_S18_HappyPath(t *testing.T) {
	dir := t.TempDir()
	if err := writeInstalledVersion(dir, "0.42.0"); err != nil {
		t.Fatalf("writeInstalledVersion: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, installedVersionMarker))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	want := "0.42.0\n"
	if string(data) != want {
		t.Errorf("marker content = %q, want %q", string(data), want)
	}
}

// TestWriteInstalledVersion_S18_Overwrite verifies that a second call overwrites
// the previous version.
func TestWriteInstalledVersion_S18_Overwrite(t *testing.T) {
	dir := t.TempDir()
	if err := writeInstalledVersion(dir, "0.1.0"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeInstalledVersion(dir, "0.2.0"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, installedVersionMarker))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(data) != "0.2.0\n" {
		t.Errorf("expected second version, got %q", string(data))
	}
}

// TestWriteInstalledVersion_S18_BadDir verifies that writeInstalledVersion returns
// an error when the destination directory does not exist.
func TestWriteInstalledVersion_S18_BadDir(t *testing.T) {
	err := writeInstalledVersion("/nonexistent/path/that/does/not/exist", "1.0.0")
	if err == nil {
		t.Fatal("expected error for non-existent directory, got nil")
	}
}

// TestWriteInstalledVersion_S18_EmptyVersion verifies that an empty version string
// writes a file containing only "\n".
func TestWriteInstalledVersion_S18_EmptyVersion(t *testing.T) {
	dir := t.TempDir()
	if err := writeInstalledVersion(dir, ""); err != nil {
		t.Fatalf("writeInstalledVersion with empty version: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, installedVersionMarker))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(data) != "\n" {
		t.Errorf("expected newline-only file, got %q", string(data))
	}
}
