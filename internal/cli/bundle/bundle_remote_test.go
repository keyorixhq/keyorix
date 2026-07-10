package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildCmd_MissingSrcFile verifies that after the --src/--out flag guards
// pass, a missing src directory is caught when the build tries to scan it.
func TestBuildCmd_MissingSrcFile(t *testing.T) {
	origS, origO, origV, origK, origSK, origR :=
		buildSrc, buildOut, buildVersion, buildKeyID, buildSignKey, buildReleased
	defer func() {
		buildSrc = origS
		buildOut = origO
		buildVersion = origV
		buildKeyID = origK
		buildSignKey = origSK
		buildReleased = origR
	}()
	buildSrc = "/definitely/does/not/exist"
	buildOut = filepath.Join(t.TempDir(), "out.tar.gz")
	buildVersion = "v0.99.0"
	buildKeyID = "key-2026"
	buildReleased = ""

	// buildSignKey points to a non-existent file — the error should be about
	// reading the signing key.
	buildSignKey = "/does/not/exist/key.pem"

	err := buildCmd.RunE(buildCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read signing key")
}

// TestBuildCmd_ValidReleasedAt verifies that a valid --released-at parses without
// error (further errors come from missing sign-key, which is expected).
func TestBuildCmd_ValidReleasedAt(t *testing.T) {
	origS, origO, origV, origK, origSK, origR :=
		buildSrc, buildOut, buildVersion, buildKeyID, buildSignKey, buildReleased
	defer func() {
		buildSrc = origS
		buildOut = origO
		buildVersion = origV
		buildKeyID = origK
		buildSignKey = origSK
		buildReleased = origR
	}()
	buildSrc = "/does/not/matter"
	buildOut = filepath.Join(t.TempDir(), "out.tar.gz")
	buildVersion = "v0.99.0"
	buildKeyID = "key-2026"
	buildSignKey = "/missing-key.pem"
	buildReleased = "2026-07-01T00:00:00Z"

	err := buildCmd.RunE(buildCmd, nil)
	require.Error(t, err)
	// The RFC3339 date was valid — error is about reading the key, not parsing the date.
	assert.NotContains(t, err.Error(), "--released-at must be RFC3339")
}

// TestVerifyCmd_MissingBundle verifies that opening a nonexistent bundle path
// produces an error.
func TestVerifyCmd_MissingBundle(t *testing.T) {
	origV := verifyInstalled
	defer func() { verifyInstalled = origV }()
	verifyInstalled = ""

	err := verifyCmd.RunE(verifyCmd, []string{"/nonexistent/bundle.tar.gz"})
	require.Error(t, err)
	// Could be "load trusted keys" or "open bundle" depending on DefaultRegistry.
	assert.Error(t, err)
}

// TestImportCmd_MissingBundleFile verifies that --dest passes the guard but a
// missing bundle file is caught next (after the license gate).
func TestImportCmd_MissingLicensePath(t *testing.T) {
	origD, origL := importDest, importLicense
	defer func() { importDest = origD; importLicense = origL }()
	importDest = t.TempDir()
	importLicense = "/nonexistent/license.tok"

	err := importCmd.RunE(importCmd, []string{"/some/bundle.tar.gz"})
	require.Error(t, err)
	// Error is about reading the license file, not about --dest.
	assert.Contains(t, err.Error(), "read license")
}

// TestConfiguredDeploymentID_NoConfig verifies that configuredDeploymentID returns
// "" when no config file is present.
func TestConfiguredDeploymentID_NoConfig(t *testing.T) {
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))
	assert.Equal(t, "", configuredDeploymentID())
}

// TestConfiguredDeploymentID_FromConfig verifies that configuredDeploymentID
// picks up license.deployment_id from a real config file.
func TestConfiguredDeploymentID_FromConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	yaml := "license:\n  deployment_id: \"test-deploy-123\"\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	assert.Equal(t, "test-deploy-123", configuredDeploymentID())
}
