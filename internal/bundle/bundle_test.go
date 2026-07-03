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

func TestExtract_StagesVerifiedComponents(t *testing.T) {
	files := map[string]string{
		"images/keyorix-server.tar":    "image-bytes",
		"charts/keyorix-0.82.0.tgz":    "chart-bytes",
		"crds/secrets.keyorix.io.yaml": "crd-bytes",
	}
	raw, reg, _ := signedBundle(t, files, "v0.82.0", "update-2026", "v0.80.0")

	dest := t.TempDir()
	m, err := Extract(bytes.NewReader(raw), reg, dest, "v0.81.0")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if m.Version != "v0.82.0" {
		t.Fatalf("version: %s", m.Version)
	}
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("staged file %s missing: %v", rel, err)
		}
		if string(got) != want {
			t.Fatalf("staged %s = %q, want %q", rel, got, want)
		}
	}
}

func TestExtract_NoDowngrade_StagesNothing(t *testing.T) {
	raw, reg, _ := signedBundle(t, map[string]string{"images/a.tar": "x"}, "v0.82.0", "update-2026", "")
	dest := t.TempDir()
	// Installed is newer than the bundle → must refuse, before writing anything.
	_, err := Extract(bytes.NewReader(raw), reg, dest, "v0.83.0")
	if !errors.Is(err, ErrNotUpgrade) {
		t.Fatalf("want ErrNotUpgrade, got %v", err)
	}
	assertDirEmpty(t, dest)
}

func TestExtract_TamperedComponent_StagesNothing(t *testing.T) {
	// Same-length tamper as the verify test, but through Extract: the digest mismatch must
	// abort and leave no poisoned file on disk.
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := srcDirWith(t, map[string]string{"images/a.tar": "AAAA"})
	m, _ := BuildManifest(dir, "v1.0.0", "update-2026", "", time.Unix(1_700_000_000, 0))
	sig, _ := Sign(m, priv)
	manifestBytes, _ := m.MarshalCanonical()
	raw := writeRawBundle(t, manifestBytes, sig, [][2]string{{"images/a.tar", "BBBB"}})

	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeUpdate, "update-2026", pub)
	dest := t.TempDir()
	if _, err := Extract(bytes.NewReader(raw), reg, dest, ""); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
	assertDirEmpty(t, dest)
}

func TestExtract_FailsClosed_Untrusted_StagesNothing(t *testing.T) {
	raw, _, _ := signedBundle(t, map[string]string{"images/a.tar": "x"}, "v1.0.0", "update-2026", "")
	dest := t.TempDir()
	// Empty registry → fail closed, nothing written.
	if _, err := Extract(bytes.NewReader(raw), trust.NewRegistry(), dest, ""); !errors.Is(err, trust.ErrNoKeys) {
		t.Fatalf("want ErrNoKeys, got %v", err)
	}
	assertDirEmpty(t, dest)
}

func TestExtract_Idempotent(t *testing.T) {
	raw, reg, _ := signedBundle(t, map[string]string{"images/a.tar": "x"}, "v1.0.0", "update-2026", "")
	dest := t.TempDir()
	if _, err := Extract(bytes.NewReader(raw), reg, dest, ""); err != nil {
		t.Fatalf("first extract: %v", err)
	}
	// Re-extracting the same bundle overwrites identical verified content and succeeds.
	if _, err := Extract(bytes.NewReader(raw), reg, dest, ""); err != nil {
		t.Fatalf("second extract (idempotent): %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dest, "images", "a.tar"))
	if string(got) != "x" {
		t.Fatalf("staged content = %q", got)
	}
}

// After an import, the no-downgrade gate enforces itself against the PERSISTED installed
// version (the marker written at the dest), so re-importing an OLDER bundle is refused
// even when the operator passes no --installed-version.
func TestExtract_PersistedVersionBlocksDowngrade(t *testing.T) {
	dest := t.TempDir()

	// Install v1.2.0 (no flag → first install, allowed).
	newRaw, newReg, _ := signedBundle(t, map[string]string{"images/a.tar": "new"}, "v1.2.0", "update-2026", "")
	if _, err := Extract(bytes.NewReader(newRaw), newReg, dest, ""); err != nil {
		t.Fatalf("install v1.2.0: %v", err)
	}

	// Attempt to import an OLDER v1.0.0 with no flag — must be refused via the marker.
	oldRaw, oldReg, _ := signedBundle(t, map[string]string{"images/a.tar": "old"}, "v1.0.0", "update-2026", "")
	if _, err := Extract(bytes.NewReader(oldRaw), oldReg, dest, ""); !errors.Is(err, ErrNotUpgrade) {
		t.Fatalf("downgrade must be refused via the persisted marker, got %v", err)
	}
	// The older content must not have overwritten the installed component.
	got, _ := os.ReadFile(filepath.Join(dest, "images", "a.tar"))
	if string(got) != "new" {
		t.Fatalf("downgrade staged content = %q, want the installed 'new'", got)
	}
}

// TestExtract_MissingMarkerInNonEmptyDestRefused pins #111: the installed-version
// marker is a plaintext file in the SAME operator-writable staging directory the
// import itself writes into — an import-capable adversary who deletes it (to fake
// a "first install") must not be able to re-stage an OLDER signed release over an
// existing, populated install just because there's no marker left to compare
// against. A destDir that already holds staged content but no marker is refused,
// not silently treated as a first install.
func TestExtract_MissingMarkerInNonEmptyDestRefused(t *testing.T) {
	dest := t.TempDir()

	newRaw, newReg, _ := signedBundle(t, map[string]string{"images/a.tar": "new"}, "v1.2.0", "update-2026", "")
	if _, err := Extract(bytes.NewReader(newRaw), newReg, dest, ""); err != nil {
		t.Fatalf("install v1.2.0: %v", err)
	}

	// Attacker: delete the marker to erase the evidence of what's installed.
	if err := os.Remove(filepath.Join(dest, installedVersionMarker)); err != nil {
		t.Fatalf("remove marker: %v", err)
	}

	// Attempt to re-stage an OLDER v1.0.0 with no flag — must be refused because the
	// destination already has staged content, not silently accepted as "first install".
	oldRaw, oldReg, _ := signedBundle(t, map[string]string{"images/a.tar": "old"}, "v1.0.0", "update-2026", "")
	if _, err := Extract(bytes.NewReader(oldRaw), oldReg, dest, ""); err == nil {
		t.Fatalf("expected the downgrade to be refused, but Extract succeeded")
	}

	// The older content must not have overwritten the installed component.
	got, _ := os.ReadFile(filepath.Join(dest, "images", "a.tar"))
	if string(got) != "new" {
		t.Fatalf("downgrade staged content = %q, want the installed 'new'", got)
	}
}

// A genuinely first install (empty/nonexistent destDir, no marker) is still allowed
// — the fix must not break the legitimate case.
func TestExtract_FirstInstallOnEmptyDestStillAllowed(t *testing.T) {
	dest := t.TempDir()
	raw, reg, _ := signedBundle(t, map[string]string{"images/a.tar": "x"}, "v1.0.0", "update-2026", "")
	if _, err := Extract(bytes.NewReader(raw), reg, dest, ""); err != nil {
		t.Fatalf("first install on an empty destination must succeed: %v", err)
	}
}

// TestExtract_RefusesPrePlantedSymlink proves the #152 fix: a symlink pre-planted at a path
// the extraction process would otherwise write into (before the legitimate operator runs a
// genuinely-signed bundle import) must be refused, not followed — the trusted bundle content
// must never land outside the staging root.
func TestExtract_RefusesPrePlantedSymlink(t *testing.T) {
	raw, reg, _ := signedBundle(t, map[string]string{"images/keyorix-server.tar": "image-bytes"}, "v1.0.0", "update-2026", "")

	dest := t.TempDir()
	outside := t.TempDir()
	// Pre-plant "<dest>/images" as a symlink pointing OUTSIDE the staging root, exactly the
	// classic insecure-staging-directory precondition: an attacker with local write access to
	// the destination path plants this before the legitimate import runs.
	if err := os.Symlink(outside, filepath.Join(dest, "images")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := Extract(bytes.NewReader(raw), reg, dest, ""); err == nil {
		t.Fatalf("Extract must refuse to follow a pre-planted symlink, got nil error")
	}

	// Nothing must have been written through the symlink into the outside directory.
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatalf("readdir outside: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("bundle content escaped the staging root into %s: %v", outside, entries)
	}
}

// TestExtract_RefusesSymlinkedStagingRoot proves the staging ROOT itself (not just a nested
// component) is checked: if the operator-supplied --dest path has been pre-planted as a
// symlink, Extract must refuse rather than stage trusted content through it.
func TestExtract_RefusesSymlinkedStagingRoot(t *testing.T) {
	raw, reg, _ := signedBundle(t, map[string]string{"images/a.tar": "x"}, "v1.0.0", "update-2026", "")

	parent := t.TempDir()
	outside := t.TempDir()
	dest := filepath.Join(parent, "staging")
	if err := os.Symlink(outside, dest); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := Extract(bytes.NewReader(raw), reg, dest, ""); err == nil {
		t.Fatalf("Extract must refuse a symlinked staging root, got nil error")
	}

	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatalf("readdir outside: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("bundle content escaped through the symlinked root into %s: %v", outside, entries)
	}
}

// assertDirEmpty fails if dir contains any regular file (temp files included), proving a
// fail-closed Extract staged nothing.
func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	var found []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			found = append(found, p)
		}
		return nil
	})
	if len(found) > 0 {
		t.Fatalf("expected no staged files, found: %v", found)
	}
}
