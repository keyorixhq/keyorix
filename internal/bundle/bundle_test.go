package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
)

// --- helpers ---

// srcDirWith writes files (path → content) into a fresh temp dir and returns it.
func srcDirWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return dir
}

// signedBundle builds + signs a bundle from files and returns its bytes plus a registry
// that trusts the signing key under keyID.
func signedBundle(t *testing.T, files map[string]string, version, keyID, minFrom string) ([]byte, *trust.KeyRegistry, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	dir := srcDirWith(t, files)
	m, err := BuildManifest(dir, version, keyID, minFrom, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	sig, err := Sign(m, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteBundle(&buf, dir, m, sig); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	reg := trust.NewRegistry()
	if err := reg.Add(trust.PurposeUpdate, keyID, pub); err != nil {
		t.Fatalf("reg.Add: %v", err)
	}
	return buf.Bytes(), reg, priv
}

// writeRawBundle assembles a tar.gz from explicit ordered parts, for crafting adversarial
// bundles the normal build path would never produce.
func writeRawBundle(t *testing.T, manifest, sig []byte, files [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	put := func(name string, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("hdr %s: %v", name, err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if manifest != nil {
		put(manifestName, manifest)
	}
	if sig != nil {
		put(sigName, sig)
	}
	for _, f := range files {
		put(f[0], []byte(f[1]))
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}

// --- tests ---

func TestVerify_RoundTrip(t *testing.T) {
	files := map[string]string{
		"bin/keyorix":               "fake-binary-bytes",
		"charts/keyorix-0.82.0.tgz": "fake-chart",
		"crds/secrets.yaml":         "apiVersion: v1",
	}
	raw, reg, _ := signedBundle(t, files, "v0.82.0", "update-2026", "v0.80.0")

	m, err := Verify(bytes.NewReader(raw), reg)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if m.Version != "v0.82.0" || m.KeyID != "update-2026" || m.MinUpgradeFrom != "v0.80.0" {
		t.Fatalf("manifest fields wrong: %+v", m)
	}
	if len(m.Components) != 3 {
		t.Fatalf("want 3 components, got %d", len(m.Components))
	}
	// Components are canonically sorted by path.
	if m.Components[0].Path != "bin/keyorix" {
		t.Fatalf("components not sorted: %+v", m.Components)
	}
}

func TestVerify_FailsClosed_NoTrustedKeys(t *testing.T) {
	raw, _, _ := signedBundle(t, map[string]string{"a": "x"}, "v1.0.0", "update-2026", "")
	// An empty registry (a plain non-release build) trusts nothing.
	if _, err := Verify(bytes.NewReader(raw), trust.NewRegistry()); !errors.Is(err, trust.ErrNoKeys) {
		t.Fatalf("want ErrNoKeys, got %v", err)
	}
}

func TestVerify_FailsClosed_UnknownKeyID(t *testing.T) {
	raw, _, _ := signedBundle(t, map[string]string{"a": "x"}, "v1.0.0", "update-2026", "")
	// Registry trusts a different key-id than the manifest names.
	pub, _, _ := ed25519.GenerateKey(nil)
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "some-other-id", pub)
	if _, err := Verify(bytes.NewReader(raw), reg); !errors.Is(err, trust.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

func TestVerify_FailsClosed_WrongKey(t *testing.T) {
	raw, _, _ := signedBundle(t, map[string]string{"a": "x"}, "v1.0.0", "update-2026", "")
	// Same key-id, but an attacker's public key — signature won't verify.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "update-2026", otherPub)
	if _, err := Verify(bytes.NewReader(raw), reg); !errors.Is(err, trust.ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestVerify_TamperedComponent(t *testing.T) {
	// Build a legitimate manifest, then ship a component whose bytes differ from its
	// pinned digest (same length, so only the hash — not the size — catches it).
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := srcDirWith(t, map[string]string{"bin/keyorix": "AAAA"})
	m, err := BuildManifest(dir, "v1.0.0", "update-2026", "", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := Sign(m, priv)
	manifestBytes, _ := m.MarshalCanonical()
	// "BBBB" has the same length as "AAAA" but a different digest.
	raw := writeRawBundle(t, manifestBytes, sig, [][2]string{{"bin/keyorix", "BBBB"}})

	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "update-2026", pub)
	if _, err := Verify(bytes.NewReader(raw), reg); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
}

func TestVerify_TamperedManifest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := srcDirWith(t, map[string]string{"a": "x"})
	m, _ := BuildManifest(dir, "v1.0.0", "update-2026", "", time.Unix(1_700_000_000, 0))
	sig, _ := Sign(m, priv)

	// Tamper: bump the version in the manifest bytes but keep the old signature.
	m.Version = "v9.9.9"
	tampered, _ := m.MarshalCanonical()
	raw := writeRawBundle(t, tampered, sig, [][2]string{{"a", "x"}})

	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "update-2026", pub)
	if _, err := Verify(bytes.NewReader(raw), reg); !errors.Is(err, trust.ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestVerify_UnlistedComponent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := srcDirWith(t, map[string]string{"a": "x"})
	m, _ := BuildManifest(dir, "v1.0.0", "update-2026", "", time.Unix(1_700_000_000, 0))
	sig, _ := Sign(m, priv)
	manifestBytes, _ := m.MarshalCanonical()
	// Archive carries an extra file the manifest never pinned.
	raw := writeRawBundle(t, manifestBytes, sig, [][2]string{{"a", "x"}, {"evil.sh", "rm -rf"}})

	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "update-2026", pub)
	if _, err := Verify(bytes.NewReader(raw), reg); !errors.Is(err, ErrUnlistedComponent) {
		t.Fatalf("want ErrUnlistedComponent, got %v", err)
	}
}

func TestVerify_MissingComponent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := srcDirWith(t, map[string]string{"a": "x", "b": "y"})
	m, _ := BuildManifest(dir, "v1.0.0", "update-2026", "", time.Unix(1_700_000_000, 0))
	sig, _ := Sign(m, priv)
	manifestBytes, _ := m.MarshalCanonical()
	// Archive omits component "b".
	raw := writeRawBundle(t, manifestBytes, sig, [][2]string{{"a", "x"}})

	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "update-2026", pub)
	if _, err := Verify(bytes.NewReader(raw), reg); !errors.Is(err, ErrMissingComponent) {
		t.Fatalf("want ErrMissingComponent, got %v", err)
	}
}

func TestVerify_NoManifest(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "update-2026", pub)
	// First entry is not manifest.json.
	raw := writeRawBundle(t, nil, nil, [][2]string{{"a", "x"}})
	if _, err := Verify(bytes.NewReader(raw), reg); !errors.Is(err, ErrNoManifest) {
		t.Fatalf("want ErrNoManifest, got %v", err)
	}
}

func TestCheckUpgrade(t *testing.T) {
	cases := []struct {
		name      string
		version   string
		minFrom   string
		installed string
		wantErr   error
	}{
		{"first install passes", "v1.0.0", "", "", nil},
		{"newer is ok", "v1.2.0", "", "v1.1.0", nil},
		{"equal is not an upgrade", "v1.1.0", "", "v1.1.0", ErrNotUpgrade},
		{"older is not an upgrade", "v1.0.0", "", "v1.1.0", ErrNotUpgrade},
		{"meets min-upgrade-from", "v2.0.0", "v1.5.0", "v1.6.0", nil},
		{"below min-upgrade-from is skipped", "v2.0.0", "v1.5.0", "v1.0.0", ErrUpgradeSkipped},
		{"patch bump ok", "v1.1.2", "", "v1.1.1", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Manifest{Version: c.version, MinUpgradeFrom: c.minFrom}
			err := m.CheckUpgrade(c.installed)
			if c.wantErr == nil && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("want %v, got %v", c.wantErr, err)
			}
		})
	}
}

func TestBuildManifest_Rejects(t *testing.T) {
	dir := srcDirWith(t, map[string]string{"a": "x"})
	if _, err := BuildManifest(dir, "", "k", "", time.Now()); err == nil {
		t.Fatal("want error for empty version")
	}
	if _, err := BuildManifest(dir, "not-semver", "k", "", time.Now()); err == nil {
		t.Fatal("want error for bad version")
	}
	if _, err := BuildManifest(dir, "v1.0.0", "", "", time.Now()); err == nil {
		t.Fatal("want error for empty key-id")
	}
	if _, err := BuildManifest(dir, "v1.0.0", "k", "bad", time.Now()); err == nil {
		t.Fatal("want error for bad min-upgrade-from")
	}
	if _, err := BuildManifest(t.TempDir(), "v1.0.0", "k", "", time.Now()); err == nil {
		t.Fatal("want error for empty source dir")
	}
}

func TestParsePrivateKeyPEM_RoundTrip(t *testing.T) {
	// A garbage PEM must be rejected.
	if _, err := ParsePrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("want error for non-PEM input")
	}
}
