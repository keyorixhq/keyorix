package bundle

import (
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingRegistryFn returns a defaultRegistryFn stub that always returns an error.
func failingRegistryFn(msg string) func() (*trust.KeyRegistry, error) {
	return func() (*trust.KeyRegistry, error) {
		return nil, fmt.Errorf("%s", msg)
	}
}

// TestVerifyCmd_RegistryLoadError exercises the "load trusted keys" error branch
// inside verifyCmd.RunE. That branch fires when defaultRegistryFn itself fails,
// before the bundle file is ever opened. It is not covered by any existing test.
func TestVerifyCmd_RegistryLoadError(t *testing.T) {
	resetDefaultRegistryFn(t)
	origV := verifyInstalled
	defer func() { verifyInstalled = origV }()
	verifyInstalled = ""

	defaultRegistryFn = failingRegistryFn("simulated registry failure")

	err := verifyCmd.RunE(verifyCmd, []string{"/any/bundle.tar.gz"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load trusted keys")
	assert.Contains(t, err.Error(), "simulated registry failure")
}

// TestImportCmd_RegistryLoadError exercises the "load trusted keys" error branch
// inside importCmd.RunE. That branch fires immediately after the --dest guard,
// before requireAirgapUpdates or os.Open are reached.
func TestImportCmd_RegistryLoadError(t *testing.T) {
	resetDefaultRegistryFn(t)
	origD, origL := importDest, importLicense
	defer func() { importDest = origD; importLicense = origL }()

	importDest = t.TempDir()
	importLicense = "" // irrelevant — registry load fails before license is read

	defaultRegistryFn = failingRegistryFn("registry init error")

	err := importCmd.RunE(importCmd, []string{"/any/bundle.tar.gz"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load trusted keys")
	assert.Contains(t, err.Error(), "registry init error")
}

// TestImportCmd_DestGuardBeforeRegistryLoad verifies that the --dest guard fires
// before the registry is loaded. If registryFn errors but --dest is empty, the
// error must be about --dest, not "load trusted keys".
func TestImportCmd_DestGuardBeforeRegistryLoad(t *testing.T) {
	resetDefaultRegistryFn(t)
	origD := importDest
	defer func() { importDest = origD }()

	importDest = ""
	defaultRegistryFn = failingRegistryFn("must not be reached")

	err := importCmd.RunE(importCmd, []string{"/any/bundle.tar.gz"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--dest is required")
	assert.NotContains(t, err.Error(), "load trusted keys")
}

// TestVerifyCmd_Success_MultipleComponents exercises the component-listing loop
// in verifyCmd.RunE with more than one component in the manifest.
func TestVerifyCmd_Success_MultipleComponents(t *testing.T) {
	resetDefaultRegistryFn(t)
	origV := verifyInstalled
	defer func() { verifyInstalled = origV }()
	verifyInstalled = ""

	const keyID = "test-key-s25-multi"
	bundlePath, pub, _ := buildSignedBundle(t, map[string]string{
		"bin/keyorix":      "binary-bytes",
		"charts/chart.tgz": "fake-chart-data",
		"images/app.tar":   "fake-image-data",
	}, "v0.99.0", keyID)

	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	defaultRegistryFn = func() (*trust.KeyRegistry, error) { return reg, nil }

	err := verifyCmd.RunE(verifyCmd, []string{bundlePath})
	require.NoError(t, err)
}

// TestBundleCmd_Metadata verifies BundleCmd has non-empty Short and Long descriptions.
func TestBundleCmd_Metadata(t *testing.T) {
	assert.NotEmpty(t, BundleCmd.Short)
	assert.NotEmpty(t, BundleCmd.Long)
}

// TestVerifyCmd_HasInstalledVersionFlag verifies the verify subcommand registers
// --installed-version (registered in init()).
func TestVerifyCmd_HasInstalledVersionFlag(t *testing.T) {
	f := verifyCmd.Flags().Lookup("installed-version")
	assert.NotNil(t, f, "verify should have --installed-version flag")
}
