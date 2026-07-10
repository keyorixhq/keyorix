package bundle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundleCmdStructure(t *testing.T) {
	assert.Equal(t, "bundle", BundleCmd.Use)
	names := make(map[string]bool)
	for _, c := range BundleCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{"build", "verify", "import"} {
		assert.True(t, names[expected], "expected subcommand %q registered", expected)
	}
}

func TestBuildCmd_SrcAndOutRequired(t *testing.T) {
	origS, origO := buildSrc, buildOut
	defer func() { buildSrc = origS; buildOut = origO }()
	buildSrc = ""
	buildOut = ""
	err := buildCmd.RunE(buildCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--src and --out are required")
}

func TestBuildCmd_BadReleasedAt(t *testing.T) {
	origS, origO, origR := buildSrc, buildOut, buildReleased
	defer func() { buildSrc = origS; buildOut = origO; buildReleased = origR }()
	buildSrc = "/some/src"
	buildOut = "/some/out.tar.gz"
	buildReleased = "not-a-date"
	err := buildCmd.RunE(buildCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--released-at must be RFC3339")
}

func TestImportCmd_DestRequired(t *testing.T) {
	orig := importDest
	defer func() { importDest = orig }()
	importDest = ""
	err := importCmd.RunE(importCmd, []string{"/some/bundle.tar.gz"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--dest is required")
}

func TestVerifyCmd_NeedsExactlyOneArg(t *testing.T) {
	assert.Error(t, verifyCmd.Args(verifyCmd, []string{}))
	assert.NoError(t, verifyCmd.Args(verifyCmd, []string{"bundle.tar.gz"}))
}

func TestBuildCmd_HasExpectedFlags(t *testing.T) {
	for _, name := range []string{"src", "out", "version", "key-id", "sign-key", "min-upgrade-from", "released-at"} {
		assert.NotNil(t, buildCmd.Flags().Lookup(name), "build should have --%s", name)
	}
}

func TestImportCmd_HasExpectedFlags(t *testing.T) {
	for _, name := range []string{"dest", "installed-version", "license"} {
		assert.NotNil(t, importCmd.Flags().Lookup(name), "import should have --%s", name)
	}
}
