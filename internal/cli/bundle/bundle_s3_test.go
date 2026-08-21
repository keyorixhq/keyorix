package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	ibundle "github.com/keyorixhq/keyorix/internal/bundle"
	ilicense "github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ed25519KeyPEM generates a fresh ed25519 private key and returns its
// PKCS#8 PEM encoding together with the public and private keys.
func ed25519KeyPEM(t *testing.T) (pemBytes []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return pemBytes, pub, priv
}

// writeKeyFile writes PEM bytes to a temp file and returns the path.
func writeKeyFile(t *testing.T, pemBytes []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sign.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

// srcDirWithFiles creates a temp directory with the given files.
func srcDirWithFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	return dir
}

// resetBuildVars saves and restores all buildCmd package-level vars.
func resetBuildVars(t *testing.T) {
	t.Helper()
	origS, origO, origV, origK, origSK, origR, origMF :=
		buildSrc, buildOut, buildVersion, buildKeyID, buildSignKey, buildReleased, buildMinFrom
	t.Cleanup(func() {
		buildSrc = origS
		buildOut = origO
		buildVersion = origV
		buildKeyID = origK
		buildSignKey = origSK
		buildReleased = origR
		buildMinFrom = origMF
	})
}

// resetDefaultRegistryFn saves and restores defaultRegistryFn.
func resetDefaultRegistryFn(t *testing.T) {
	t.Helper()
	orig := defaultRegistryFn
	t.Cleanup(func() { defaultRegistryFn = orig })
}

// buildSignedBundle builds a real signed bundle to a temp file and returns the path,
// the public key used for signing, and the signing private key.
func buildSignedBundle(t *testing.T, files map[string]string, version, keyID string) (bundlePath string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	_, pub, priv = ed25519KeyPEM(t)

	srcDir := srcDirWithFiles(t, files)
	m, err := ibundle.BuildManifest(srcDir, version, keyID, "", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)
	sig, err := ibundle.Sign(m, priv)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, ibundle.WriteBundle(&buf, srcDir, m, sig))

	bundlePath = filepath.Join(t.TempDir(), "test-bundle.tar.gz")
	require.NoError(t, os.WriteFile(bundlePath, buf.Bytes(), 0o644))
	return bundlePath, pub, priv
}

// makeLicenseToken issues an airgap_updates license token and writes it to a
// temp file. Returns the path and a registry that trusts the license key.
func makeLicenseToken(t *testing.T) (tokenPath string, licPub ed25519.PublicKey) {
	t.Helper()
	licPub, licPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tok, err := ilicense.Issue(ilicense.License{
		Licensee: "ACME", Plan: "enterprise-airgap",
		Features: []string{ilicense.FeatureAirgapUpdates},
		IssuedAt: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyID:    "license-s3-2026",
	}, licPriv)
	require.NoError(t, err)

	tokenPath = filepath.Join(t.TempDir(), "license.tok")
	require.NoError(t, os.WriteFile(tokenPath, []byte(tok), 0o600))
	return tokenPath, licPub
}

// TestBuildCmd_Success exercises the complete buildCmd.RunE success path:
// generate a real ed25519 key, create a src directory with one file, and confirm
// a bundle is written to the --out path.
func TestBuildCmd_Success(t *testing.T) {
	resetBuildVars(t)

	pemBytes, _, _ := ed25519KeyPEM(t)
	keyPath := writeKeyFile(t, pemBytes)

	src := srcDirWithFiles(t, map[string]string{
		"bin/keyorix": "fake-binary-content",
	})
	outPath := filepath.Join(t.TempDir(), "bundle.tar.gz")

	buildSrc = src
	buildOut = outPath
	buildVersion = "v0.99.0"
	buildKeyID = "test-key-2026"
	buildSignKey = keyPath
	buildReleased = ""
	buildMinFrom = ""

	err := buildCmd.RunE(buildCmd, nil)
	require.NoError(t, err)

	info, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0), "bundle file should be non-empty")
}

// TestBuildCmd_Success_WithReleasedAt exercises the valid released-at branch
// and the min-upgrade-from field together with the full build path.
func TestBuildCmd_Success_WithReleasedAt(t *testing.T) {
	resetBuildVars(t)

	pemBytes, _, _ := ed25519KeyPEM(t)
	keyPath := writeKeyFile(t, pemBytes)

	src := srcDirWithFiles(t, map[string]string{
		"charts/keyorix-0.99.0.tgz": "fake-chart",
	})
	outPath := filepath.Join(t.TempDir(), "bundle-ts.tar.gz")

	buildSrc = src
	buildOut = outPath
	buildVersion = "v0.99.0"
	buildKeyID = "test-key-2026"
	buildSignKey = keyPath
	buildReleased = "2026-01-15T12:00:00Z"
	buildMinFrom = "v0.90.0"

	err := buildCmd.RunE(buildCmd, nil)
	require.NoError(t, err)

	info, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))
}

// TestBuildCmd_BadPEM exercises the ParsePrivateKeyPEM error path: the sign key
// file exists but contains garbage PEM (valid PEM header, invalid PKCS8 DER).
func TestBuildCmd_BadPEM(t *testing.T) {
	resetBuildVars(t)

	src := srcDirWithFiles(t, map[string]string{
		"bin/keyorix": "content",
	})

	// Write valid PEM header but invalid DER bytes so pem.Decode succeeds but
	// x509.ParsePKCS8PrivateKey fails.
	badDER := make([]byte, 20)
	_, _ = rand.Read(badDER)
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: badDER})
	keyPath := writeKeyFile(t, badPEM)

	outPath := filepath.Join(t.TempDir(), "bundle.tar.gz")

	buildSrc = src
	buildOut = outPath
	buildVersion = "v0.99.0"
	buildKeyID = "test-key-2026"
	buildSignKey = keyPath
	buildReleased = ""

	err := buildCmd.RunE(buildCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse signing key")
}

// TestBuildCmd_EmptySrcDir exercises the BuildManifest error path when the src
// directory exists but contains no files.
func TestBuildCmd_EmptySrcDir(t *testing.T) {
	resetBuildVars(t)

	pemBytes, _, _ := ed25519KeyPEM(t)
	keyPath := writeKeyFile(t, pemBytes)

	buildSrc = t.TempDir() // empty dir
	buildOut = filepath.Join(t.TempDir(), "bundle.tar.gz")
	buildVersion = "v0.99.0"
	buildKeyID = "test-key-2026"
	buildSignKey = keyPath
	buildReleased = ""

	err := buildCmd.RunE(buildCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no files found")
}

// TestBuildCmd_UnwritableOut exercises the os.Create error path by using an
// output path inside a non-existent subdirectory.
func TestBuildCmd_UnwritableOut(t *testing.T) {
	resetBuildVars(t)

	pemBytes, _, _ := ed25519KeyPEM(t)
	keyPath := writeKeyFile(t, pemBytes)

	src := srcDirWithFiles(t, map[string]string{
		"bin/keyorix": "content",
	})

	buildSrc = src
	buildOut = filepath.Join(t.TempDir(), "nonexistent-subdir", "bundle.tar.gz")
	buildVersion = "v0.99.0"
	buildKeyID = "test-key-2026"
	buildSignKey = keyPath
	buildReleased = ""

	err := buildCmd.RunE(buildCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create bundle")
}

// TestBuildCmd_WriteBundleFails exercises the ibundle.WriteBundle error path: --out is
// pointed at the very component file living under --src. BuildManifest hashes the file's
// original (non-empty) content and pins its size in the manifest; os.Create(buildOut) then
// truncates that same file to zero bytes (same path, O_TRUNC) before WriteBundle re-opens it
// to copy component bytes into the tar stream. The tar writer detects, at Close, that fewer
// bytes were written than the header's declared size and returns an error, which WriteBundle
// propagates — a real (if unusual) operator mistake: naming --out the same as a source file.
func TestBuildCmd_WriteBundleFails(t *testing.T) {
	resetBuildVars(t)

	pemBytes, _, _ := ed25519KeyPEM(t)
	keyPath := writeKeyFile(t, pemBytes)

	src := srcDirWithFiles(t, map[string]string{
		"bin/keyorix": "non-empty original content that will be truncated away",
	})
	selfPath := filepath.Join(src, "bin", "keyorix")

	buildSrc = src
	buildOut = selfPath // same path as the only component file
	buildVersion = "v0.99.0"
	buildKeyID = "test-key-2026"
	buildSignKey = keyPath
	buildReleased = ""

	err := buildCmd.RunE(buildCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write bundle")
}

// TestVerifyCmd_VerifyFailsEmptyRegistry exercises verifyCmd.RunE past the
// os.Open call: a real bundle is opened but the injected registry has no trusted
// keys, so ibundle.Verify returns a "no trusted keys" error. This covers the
// defer close and the Verify call site.
func TestVerifyCmd_VerifyFailsEmptyRegistry(t *testing.T) {
	resetDefaultRegistryFn(t)
	origV := verifyInstalled
	defer func() { verifyInstalled = origV }()
	verifyInstalled = ""

	bundlePath, _, _ := buildSignedBundle(t, map[string]string{
		"bin/keyorix": "binary-content",
	}, "v0.99.0", "test-key-2026")

	// Inject an empty registry so ibundle.Verify fails at key lookup.
	emptyReg := trust.NewRegistry()
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return emptyReg, nil }

	err := verifyCmd.RunE(verifyCmd, []string{bundlePath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

// TestVerifyCmd_Success exercises the full verifyCmd.RunE success path by
// injecting a registry that trusts the signing key.
func TestVerifyCmd_Success(t *testing.T) {
	resetDefaultRegistryFn(t)
	origV := verifyInstalled
	defer func() { verifyInstalled = origV }()
	verifyInstalled = "v0.50.0"

	const keyID = "test-key-s3-2026"
	bundlePath, pub, _ := buildSignedBundle(t, map[string]string{
		"bin/keyorix":      "binary-bytes",
		"charts/chart.tgz": "fake-chart",
	}, "v0.99.0", keyID)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	err := verifyCmd.RunE(verifyCmd, []string{bundlePath})
	require.NoError(t, err)
}

// TestVerifyCmd_Success_WithMinFrom exercises the verifyCmd success path when
// --installed-version satisfies the bundle's min_upgrade_from constraint.
func TestVerifyCmd_Success_WithMinFrom(t *testing.T) {
	resetDefaultRegistryFn(t)
	origV := verifyInstalled
	defer func() { verifyInstalled = origV }()
	verifyInstalled = "v0.95.0"

	const keyID = "test-key-s3-minFrom"
	srcDir := srcDirWithFiles(t, map[string]string{"bin/keyorix": "bytes"})
	pemBytes, kpub, kpriv := ed25519KeyPEM(t)
	_ = pemBytes

	// Build a bundle with min_upgrade_from so CheckUpgrade runs.
	m, err := ibundle.BuildManifest(srcDir, "v0.99.0", keyID, "v0.90.0", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)
	sig, err := ibundle.Sign(m, kpriv)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, ibundle.WriteBundle(&buf, srcDir, m, sig))
	bundlePath := filepath.Join(t.TempDir(), "b.tar.gz")
	require.NoError(t, os.WriteFile(bundlePath, buf.Bytes(), 0o644))

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, kpub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	err = verifyCmd.RunE(verifyCmd, []string{bundlePath})
	require.NoError(t, err)
}

// TestVerifyCmd_CheckUpgradeFails exercises the CheckUpgrade error path:
// the bundle has min_upgrade_from=v0.90.0 but --installed-version is v0.85.0
// (below the floor), so CheckUpgrade returns an error.
func TestVerifyCmd_CheckUpgradeFails(t *testing.T) {
	resetDefaultRegistryFn(t)
	origV := verifyInstalled
	defer func() { verifyInstalled = origV }()
	verifyInstalled = "v0.85.0" // below min_upgrade_from

	const keyID = "test-key-s3-2026"
	srcDir := srcDirWithFiles(t, map[string]string{"bin/keyorix": "bytes"})
	pemBytes, pub, priv := ed25519KeyPEM(t)
	_ = pemBytes

	m, err := ibundle.BuildManifest(srcDir, "v0.99.0", keyID, "v0.90.0", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)
	sig, err := ibundle.Sign(m, priv)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, ibundle.WriteBundle(&buf, srcDir, m, sig))
	bundlePath := filepath.Join(t.TempDir(), "b.tar.gz")
	require.NoError(t, os.WriteFile(bundlePath, buf.Bytes(), 0o644))

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	err = verifyCmd.RunE(verifyCmd, []string{bundlePath})
	require.Error(t, err)
}

// TestImportCmd_Success_FullPath exercises the complete importCmd.RunE success
// path: a valid bundle + license → Extract stages files under --dest.
func TestImportCmd_Success_FullPath(t *testing.T) {
	resetDefaultRegistryFn(t)
	origD, origL, origI := importDest, importLicense, importInstalled
	defer func() { importDest = origD; importLicense = origL; importInstalled = origI }()

	const keyID = "test-key-s3-2026"
	bundlePath, updPub, _ := buildSignedBundle(t, map[string]string{
		"bin/keyorix": "binary-content-for-import",
	}, "v0.99.0", keyID)

	tokenPath, licPub := makeLicenseToken(t)

	// Build a combined registry with BOTH the update key and the license key.
	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, updPub))
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-s3-2026", licPub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	// Point KEYORIX_CONFIG_PATH at a non-existent file so configuredDeploymentID
	// returns "" (no deployment binding configured).
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	destDir := t.TempDir()
	importDest = destDir
	importLicense = tokenPath
	importInstalled = "v0.50.0" // below the bundle's v0.99.0 — a genuine upgrade

	err := importCmd.RunE(importCmd, []string{bundlePath})
	require.NoError(t, err)
}

// TestImportCmd_ExtractFails exercises the ibundle.Extract error path: the
// license gate and the installed-version gate both pass (via --force, since a
// corrupted bundle has no discoverable version), but the bundle itself is
// corrupted, so Extract fails.
func TestImportCmd_ExtractFails(t *testing.T) {
	resetDefaultRegistryFn(t)
	origD, origL, origI, origF := importDest, importLicense, importInstalled, importForce
	defer func() { importDest = origD; importLicense = origL; importInstalled = origI; importForce = origF }()

	tokenPath, licPub := makeLicenseToken(t)

	// Write a corrupted bundle (just random bytes).
	bundlePath := filepath.Join(t.TempDir(), "corrupt.tar.gz")
	require.NoError(t, os.WriteFile(bundlePath, []byte("not-a-valid-bundle"), 0o644))

	const keyID = "test-key-s3-2026"
	reg := trust.NewRegistry()
	// Add a dummy update key (won't matter since bundle is corrupted).
	dummyPub, _, _ := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, dummyPub))
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-s3-2026", licPub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	importDest = t.TempDir()
	importLicense = tokenPath
	importInstalled = ""
	importForce = true

	err := importCmd.RunE(importCmd, []string{bundlePath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "import failed")
}

// TestImportCmd_MissingBundleFile_AfterLicenseGate exercises the os.Open error
// path in importCmd.RunE after requireAirgapUpdates and the installed-version
// gate (bypassed via --force, since a first import into a fresh --dest has
// nothing to auto-discover a version from) both pass.
func TestImportCmd_MissingBundleFile_AfterLicenseGate(t *testing.T) {
	resetDefaultRegistryFn(t)
	origD, origL, origI, origF := importDest, importLicense, importInstalled, importForce
	defer func() { importDest = origD; importLicense = origL; importInstalled = origI; importForce = origF }()

	tokenPath, licPub := makeLicenseToken(t)

	const keyID = "test-key-s3-2026"
	reg := trust.NewRegistry()
	dummyPub, _, _ := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, dummyPub))
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-s3-2026", licPub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	importDest = t.TempDir()
	importLicense = tokenPath
	importInstalled = ""
	importForce = true

	err := importCmd.RunE(importCmd, []string{"/nonexistent/bundle.tar.gz"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open bundle")
}

// TestImportCmd_InstalledVersionDowngradeRejected exercises the no-downgrade gate:
// the bundle is v0.99.0 but importInstalled is v1.0.0 (newer), so Extract fails.
func TestImportCmd_InstalledVersionDowngradeRejected(t *testing.T) {
	resetDefaultRegistryFn(t)
	origD, origL, origI := importDest, importLicense, importInstalled
	defer func() { importDest = origD; importLicense = origL; importInstalled = origI }()

	const keyID = "test-key-s3-2026"
	bundlePath, updPub, _ := buildSignedBundle(t, map[string]string{
		"bin/keyorix": "binary",
	}, "v0.99.0", keyID)

	tokenPath, licPub := makeLicenseToken(t)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, updPub))
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-s3-2026", licPub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	importDest = t.TempDir()
	importLicense = tokenPath
	importInstalled = "v1.0.0" // newer than bundle — downgrade attempt

	err := importCmd.RunE(importCmd, []string{bundlePath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "import failed")
}
