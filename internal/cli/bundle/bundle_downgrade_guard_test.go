package bundle

// Regression tests for cli-project-001 (HIGH, supply-chain): `bundle import` and `bundle
// verify` both derive the no-downgrade / anti-skip (min-upgrade-from) check from an
// operator-supplied --installed-version flag that used to be OPTIONAL with an empty-string
// default. ibundle.Manifest.CheckUpgrade silently no-ops on an empty installed version, so
// the routine, help-text-documented invocation `keyorix bundle import --dest /stage <bundle>`
// (no --installed-version) performed ZERO downgrade protection: a validly-signed but stale
// bundle — substituted by a compromised mirror or staging host — would import cleanly,
// silently downgrading an air-gapped deployment past a release with a mandatory security
// fix or a MinUpgradeFrom-gated migration.
//
// These tests assert the fix: both commands now refuse to skip the check silently. Omitting
// --installed-version is refused with a clear, actionable error unless the operator either
// (a) has a prior import already anchoring the check via the persisted destDir marker
// (import only — see resolveIdempotentInstall in internal/bundle), or (b) passes the
// explicit --force override, in which case a loud warning is printed and the operator's
// choice to skip the check is auditable rather than silent.

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	ibundle "github.com/keyorixhq/keyorix/internal/bundle"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetImportVars saves and restores every importCmd package-level var this test file
// touches.
func resetImportVars(t *testing.T) {
	t.Helper()
	origD, origL, origI, origF := importDest, importLicense, importInstalled, importForce
	t.Cleanup(func() {
		importDest = origD
		importLicense = origL
		importInstalled = origI
		importForce = origF
	})
}

// buildAndSignBundle builds and signs a bundle with an EXISTING signing key (unlike
// buildSignedBundle in bundle_s3_test.go, which always mints a fresh key), so a test can
// build multiple bundle versions signed by the same trusted key.
func buildAndSignBundle(t *testing.T, files map[string]string, version, keyID string, priv ed25519.PrivateKey) string {
	t.Helper()
	srcDir := srcDirWithFiles(t, files)
	m, err := ibundle.BuildManifest(srcDir, version, keyID, "", time.Unix(1_700_000_000, 0))
	require.NoError(t, err)
	sig, err := ibundle.Sign(m, priv)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, ibundle.WriteBundle(&buf, srcDir, m, sig))
	bundlePath := filepath.Join(t.TempDir(), "bundle-"+version+".tar.gz")
	require.NoError(t, os.WriteFile(bundlePath, buf.Bytes(), 0o644))
	return bundlePath
}

// TestImportCmd_RequiresInstalledVersion_OnFirstImport is the core regression test: a
// fresh, never-imported-into --dest with no --installed-version and no --force must be
// refused BEFORE the bundle is even opened — nothing gets staged.
func TestImportCmd_RequiresInstalledVersion_OnFirstImport(t *testing.T) {
	resetDefaultRegistryFn(t)
	resetImportVars(t)

	const keyID = "test-key-guard-2026"
	bundlePath, updPub, _ := buildSignedBundle(t, map[string]string{
		"bin/keyorix": "binary-content",
	}, "v0.99.0", keyID)
	tokenPath, licPub := makeLicenseToken(t)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, updPub))
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-s3-2026", licPub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	destDir := t.TempDir()
	importDest = destDir
	importLicense = tokenPath
	importInstalled = ""
	importForce = false

	err := importCmd.RunE(importCmd, []string{bundlePath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--installed-version is required")

	entries, rerr := os.ReadDir(destDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "refusing the gate must stage nothing")
}

// TestImportCmd_ForceBypassesMissingInstalledVersion verifies the explicit --force
// override lets a genuine first import proceed without --installed-version.
func TestImportCmd_ForceBypassesMissingInstalledVersion(t *testing.T) {
	resetDefaultRegistryFn(t)
	resetImportVars(t)

	const keyID = "test-key-guard-force"
	bundlePath, updPub, _ := buildSignedBundle(t, map[string]string{
		"bin/keyorix": "binary-content",
	}, "v0.99.0", keyID)
	tokenPath, licPub := makeLicenseToken(t)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, updPub))
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-s3-2026", licPub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	destDir := t.TempDir()
	importDest = destDir
	importLicense = tokenPath
	importInstalled = ""
	importForce = true

	err := importCmd.RunE(importCmd, []string{bundlePath})
	require.NoError(t, err)

	entries, rerr := os.ReadDir(destDir)
	require.NoError(t, rerr)
	assert.NotEmpty(t, entries, "--force must actually stage the bundle")
}

// TestImportCmd_PriorMarkerSatisfiesRequirement_NoForceNeeded verifies the existing
// auto-discovery mechanism (#111's persisted destDir marker) still lets a routine
// re-import into an ALREADY-imported-into --dest proceed without --installed-version or
// --force — only a genuine first import (no marker yet) requires an affirmative choice.
func TestImportCmd_PriorMarkerSatisfiesRequirement_NoForceNeeded(t *testing.T) {
	resetDefaultRegistryFn(t)
	resetImportVars(t)

	const keyID = "test-key-guard-marker"
	_, pub, priv := ed25519KeyPEM(t)
	tokenPath, licPub := makeLicenseToken(t)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-s3-2026", licPub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	destDir := t.TempDir()
	importDest = destDir
	importLicense = tokenPath

	// First import (explicit --installed-version) establishes the persisted marker at
	// v0.90.0.
	firstPath := buildAndSignBundle(t, map[string]string{"bin/keyorix": "v1"}, "v0.90.0", keyID, priv)
	importInstalled = "v0.10.0"
	importForce = false
	require.NoError(t, importCmd.RunE(importCmd, []string{firstPath}))

	// Second import of a newer bundle with NO --installed-version and NO --force must
	// succeed: the marker written by the first import anchors the gate automatically.
	secondPath := buildAndSignBundle(t, map[string]string{"bin/keyorix": "v2"}, "v0.95.0", keyID, priv)
	importInstalled = ""
	importForce = false
	err := importCmd.RunE(importCmd, []string{secondPath})
	require.NoError(t, err, "a prior import's persisted marker should satisfy the gate without --force")
}

// TestImportCmd_DowngradeStillBlockedWhenInstalledVersionSupplied verifies the actual
// no-downgrade protection this whole gate exists to guarantee still fires once
// --installed-version IS supplied: an older, validly-signed bundle must still be
// rejected, and nothing staged.
func TestImportCmd_DowngradeStillBlockedWhenInstalledVersionSupplied(t *testing.T) {
	resetDefaultRegistryFn(t)
	resetImportVars(t)

	const keyID = "test-key-guard-downgrade"
	_, pub, priv := ed25519KeyPEM(t)
	tokenPath, licPub := makeLicenseToken(t)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-s3-2026", licPub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	oldBundle := buildAndSignBundle(t, map[string]string{"bin/keyorix": "old"}, "v0.50.0", keyID, priv)

	destDir := t.TempDir()
	importDest = destDir
	importLicense = tokenPath
	importInstalled = "v0.99.0" // currently running something much newer than the bundle
	importForce = false

	err := importCmd.RunE(importCmd, []string{oldBundle})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "import failed")

	entries, rerr := os.ReadDir(destDir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "a rejected downgrade must stage nothing")
}

// TestImportCmd_AmbiguousDestWithoutMarker_FailsClosed verifies the new gate correctly
// surfaces the existing #111 fail-closed behavior: a --dest that already holds staged
// content but no marker (e.g. a prior import failed partway through, or the marker was
// deleted) is refused, not silently treated as a first install.
func TestImportCmd_AmbiguousDestWithoutMarker_FailsClosed(t *testing.T) {
	resetDefaultRegistryFn(t)
	resetImportVars(t)

	const keyID = "test-key-guard-ambiguous"
	bundlePath, pub, _ := buildSignedBundle(t, map[string]string{"bin/keyorix": "bytes"}, "v0.99.0", keyID)
	tokenPath, licPub := makeLicenseToken(t)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-s3-2026", licPub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	destDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(destDir, "leftover-file"), []byte("x"), 0o644))

	importDest = destDir
	importLicense = tokenPath
	importInstalled = ""
	importForce = false

	err := importCmd.RunE(importCmd, []string{bundlePath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already contains staged content but no installed-version marker")
}

// TestVerifyCmd_RequiresInstalledVersion verifies that offline `bundle verify` — which has
// no destDir/marker to fall back on — refuses to skip the downgrade check silently.
func TestVerifyCmd_RequiresInstalledVersion(t *testing.T) {
	resetDefaultRegistryFn(t)
	origV, origF := verifyInstalled, verifyForce
	defer func() { verifyInstalled = origV; verifyForce = origF }()

	const keyID = "test-key-guard-verify"
	bundlePath, pub, _ := buildSignedBundle(t, map[string]string{"bin/keyorix": "bytes"}, "v0.99.0", keyID)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	verifyInstalled = ""
	verifyForce = false

	err := verifyCmd.RunE(verifyCmd, []string{bundlePath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--installed-version is required")
}

// TestVerifyCmd_ForceBypassesMissingInstalledVersion verifies --force lets an operator
// explicitly verify signature/digests only, with no downgrade check.
func TestVerifyCmd_ForceBypassesMissingInstalledVersion(t *testing.T) {
	resetDefaultRegistryFn(t)
	origV, origF := verifyInstalled, verifyForce
	defer func() { verifyInstalled = origV; verifyForce = origF }()

	const keyID = "test-key-guard-verify-force"
	bundlePath, pub, _ := buildSignedBundle(t, map[string]string{"bin/keyorix": "bytes"}, "v0.99.0", keyID)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	verifyInstalled = ""
	verifyForce = true

	err := verifyCmd.RunE(verifyCmd, []string{bundlePath})
	require.NoError(t, err)
}

// TestVerifyCmd_DowngradeStillBlockedWhenInstalledVersionSupplied verifies verify's actual
// downgrade detection still fires once --installed-version IS supplied.
func TestVerifyCmd_DowngradeStillBlockedWhenInstalledVersionSupplied(t *testing.T) {
	resetDefaultRegistryFn(t)
	origV, origF := verifyInstalled, verifyForce
	defer func() { verifyInstalled = origV; verifyForce = origF }()

	const keyID = "test-key-guard-verify-downgrade"
	bundlePath, pub, _ := buildSignedBundle(t, map[string]string{"bin/keyorix": "bytes"}, "v0.50.0", keyID)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	verifyInstalled = "v0.99.0" // newer than the bundle — a downgrade
	verifyForce = false

	err := verifyCmd.RunE(verifyCmd, []string{bundlePath})
	require.Error(t, err)
}
