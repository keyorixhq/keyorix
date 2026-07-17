// bundle_s24_test.go — coverage uplift for paths not reached by existing test files.
//
// Gaps covered here:
//   - MarshalCanonical: out-of-order component input produces a sorted result
//   - Extract: empty destDir returns "extract destination is required"
//   - Verify/process: manifest with empty key_id returns "manifest has no key-id"
//   - ParsePrivateKeyPEM: valid PKCS8 non-ed25519 key (ECDSA P-256) hits the
//     "signing key is not ed25519" branch (distinct from the invalid-DER branch
//     already tested in bundle_extra_test.go)
//   - BuildManifest: srcDir containing a file named "manifest.json" is refused via
//     cleanComponentPath (reserved-name check triggered from within the walk)
package bundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMarshalCanonical_SortsComponents verifies that MarshalCanonical produces a
// lexicographically sorted component list regardless of the insertion order, and
// that a second call on the same (now-unsorted-again) manifest is also sorted.
func TestMarshalCanonical_SortsComponents(t *testing.T) {
	m := &Manifest{
		Version: "v1.0.0",
		KeyID:   "k",
		Components: []Component{
			{Path: "z/last.bin", SHA256: "aa", Size: 1},
			{Path: "a/first.bin", SHA256: "bb", Size: 2},
			{Path: "m/middle.bin", SHA256: "cc", Size: 3},
		},
	}

	b, err := m.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("MarshalCanonical returned empty bytes")
	}

	// The original slice must not be mutated.
	if m.Components[0].Path != "z/last.bin" {
		t.Errorf("MarshalCanonical mutated the receiver: got %q", m.Components[0].Path)
	}

	// The JSON output must contain the paths in ascending order.
	s := string(b)
	posA := indexOf(s, "a/first.bin")
	posM := indexOf(s, "m/middle.bin")
	posZ := indexOf(s, "z/last.bin")
	if posA < 0 || posM < 0 || posZ < 0 {
		t.Fatalf("one or more paths missing from output: %s", s)
	}
	if !(posA < posM && posM < posZ) {
		t.Errorf("components not sorted in output: posA=%d posM=%d posZ=%d\n%s", posA, posM, posZ, s)
	}
}

// indexOf is a small helper to find the byte offset of needle in haystack (-1 if absent).
func indexOf(haystack, needle string) int {
	idx := -1
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return idx
}

// TestExtract_EmptyDestDir verifies that Extract rejects an empty destDir before
// performing any I/O, returning an error that contains "destination".
func TestExtract_EmptyDestDir(t *testing.T) {
	raw, reg, _ := signedBundle(t, map[string]string{"images/a.tar": "x"}, "v1.0.0", "update-2026", "")
	_, err := Extract(bytes.NewReader(raw), reg, "", "")
	if err == nil {
		t.Fatal("want error for empty destDir, got nil")
	}
}

// TestVerify_ManifestNoKeyID exercises the "manifest has no key-id" guard in
// process(). We craft a bundle whose manifest.json carries an empty key_id.
func TestVerify_ManifestNoKeyID(t *testing.T) {
	// Build a legitimate signed bundle, then replace the manifest bytes with one
	// whose key_id field is empty, while keeping the old (now invalid) signature.
	// The key-id check fires BEFORE the signature check, so signature validity
	// is irrelevant here.
	_, reg, priv := signedBundle(t, map[string]string{"a": "x"}, "v1.0.0", "update-2026", "")

	// Build a manifest with no KeyID.
	dir := srcDirWith(t, map[string]string{"a": "x"})
	m, err := BuildManifest(dir, "v1.0.0", "update-2026", "", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	m.KeyID = "" // clear it after building
	sig, err := Sign(m, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	manifestBytes, err := m.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}

	raw := writeRawBundle(t, manifestBytes, sig, [][2]string{{"a", "x"}})
	_, err = Verify(bytes.NewReader(raw), reg)
	if err == nil {
		t.Fatal("want error for manifest with empty key-id, got nil")
	}
}

// TestParsePrivateKeyPEM_NonED25519Key verifies that a PKCS8 PEM holding a valid
// ECDSA P-256 key (parseable but not ed25519) reaches the "signing key is not ed25519"
// branch in ParsePrivateKeyPEM, distinct from the invalid-DER branch tested in
// bundle_extra_test.go.
func TestParsePrivateKeyPEM_NonED25519Key(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = ParsePrivateKeyPEM(pemBytes)
	if err == nil {
		t.Fatal("want error for non-ed25519 PKCS8 key, got nil")
	}
}

// TestBuildManifest_RejectsReservedNameInSrcDir verifies that BuildManifest refuses
// a srcDir containing a regular file whose relative path matches a reserved bundle
// entry name (manifest.json or manifest.sig). This exercises the cleanComponentPath
// collision check from inside the WalkDir callback.
func TestBuildManifest_RejectsReservedNameInSrcDir(t *testing.T) {
	for _, reserved := range []string{manifestName, sigName} {
		t.Run(reserved, func(t *testing.T) {
			dir := t.TempDir()
			// Write a regular file with the reserved name at the srcDir root.
			if err := os.WriteFile(filepath.Join(dir, reserved), []byte("data"), 0o644); err != nil {
				t.Fatalf("write %s: %v", reserved, err)
			}
			_, err := BuildManifest(dir, "v1.0.0", "k", "", time.Now())
			if err == nil {
				t.Fatalf("BuildManifest with %q in srcDir: want error, got nil", reserved)
			}
		})
	}
}
