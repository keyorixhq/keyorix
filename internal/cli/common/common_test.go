package common

import (
	"os"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

// TestResolveProject_FlagWins verifies the --project flag has highest priority.
func TestResolveProject_FlagWins(t *testing.T) {
	t.Setenv("KEYORIX_PROJECT", "env-project")
	got, err := ResolveProject("flag-project")
	require.NoError(t, err)
	assert.Equal(t, "flag-project", got)
}

// TestResolveProject_EnvVarFallback verifies KEYORIX_PROJECT is used when no flag set.
func TestResolveProject_EnvVarFallback(t *testing.T) {
	t.Setenv("KEYORIX_PROJECT", "env-project")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // isolate cli.yaml
	got, err := ResolveProject("")
	require.NoError(t, err)
	assert.Equal(t, "env-project", got)
}

// TestResolveProject_NoProjectReturnsError verifies an error is returned when nothing is set.
func TestResolveProject_NoProjectReturnsError(t *testing.T) {
	t.Setenv("KEYORIX_PROJECT", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no active project in cli.yaml
	_, err := ResolveProject("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no project specified")
}

// TestResolveRemote_EnvVars verifies KEYORIX_SERVER + KEYORIX_TOKEN resolves to ok=true.
func TestResolveRemote_EnvVars(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://localhost:8080")
	t.Setenv("KEYORIX_TOKEN", "test-tok")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	endpoint, token, ok := ResolveRemote()
	assert.True(t, ok)
	assert.Equal(t, "http://localhost:8080", endpoint)
	assert.Equal(t, "test-tok", token)
}

// TestResolveRemote_NeitherSet verifies ok=false when nothing is configured.
func TestResolveRemote_NeitherSet(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	_, _, ok := ResolveRemote()
	assert.False(t, ok)
}

// TestResolveRemote_OnlyServer verifies ok=false when only the server is set (no token).
func TestResolveRemote_OnlyServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://localhost:8080")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	_, _, ok := ResolveRemote()
	assert.False(t, ok)
}

// TestNewRemoteClient_FromEnvVars verifies NewRemoteClient succeeds with env vars.
func TestNewRemoteClient_FromEnvVars(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://localhost:8080")
	t.Setenv("KEYORIX_TOKEN", "my-token")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	rc, ok := NewRemoteClient()
	assert.True(t, ok)
	require.NotNil(t, rc)
	assert.Equal(t, "http://localhost:8080", rc.Endpoint)
	assert.Equal(t, "my-token", rc.Token)
}

// TestNewRemoteClient_NotConnected verifies NewRemoteClient returns false when not configured.
func TestNewRemoteClient_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	rc, ok := NewRemoteClient()
	assert.False(t, ok)
	assert.Nil(t, rc)
}

// TestEndpointIsSecure verifies the scheme/loopback classification.
func TestEndpointIsSecure(t *testing.T) {
	cases := []struct {
		endpoint string
		want     bool
	}{
		{"https://keyorix.example.com", true},
		{"http://keyorix.example.com", false},
		{"http://localhost:8080", true},
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:8080", true},
		{"http://10.0.0.1:8080", false},
		{"not-a-url", false},
	}
	for _, c := range cases {
		got := endpointIsSecure(c.endpoint)
		assert.Equal(t, c.want, got, "endpointIsSecure(%q)", c.endpoint)
	}
}

// TestPrintProvisionResult_OOB verifies the out-of-band (link for admin) path.
func TestPrintProvisionResult_OOB(t *testing.T) {
	// Just check it doesn't panic with a nil ProvisionSetupResult.
	PrintProvisionResult(nil)
}

// TestPrintOneTimePasswordResult_Nil verifies nil is a no-op.
func TestPrintOneTimePasswordResult_Nil(t *testing.T) {
	PrintOneTimePasswordResult(nil)
}

// TestInitializeCoreService_DefaultConfig verifies InitializeCoreService returns a non-nil
// service when invoked with a temp dir config (no server env).
func TestInitializeCoreService_DefaultConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	// Write a minimal config so config.Load finds it.
	cfgPath := dir + "/keyorix.yaml"
	err := os.WriteFile(cfgPath, []byte(`storage:
  type: local
  database:
    path: "`+dir+`/test.db"
locale:
  language: "en"
  fallback_language: "en"
`), 0600)
	require.NoError(t, err)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	svc, err := InitializeCoreService()
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

// TestRegisterPassphraseFlags_FDNotPassedLeavesFDUnset verifies that when
// --passphrase-fd is never passed on the command line, FDSet stays false —
// so ResolvePassphrase correctly falls through to weaker sources instead of
// treating the flag's zero value as an explicit fd 0.
func TestRegisterPassphraseFlags_FDNotPassedLeavesFDUnset(t *testing.T) {
	var src crypto.PassphraseSource
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterPassphraseFlags(fs, &src, "", "master passphrase")

	require.NoError(t, fs.Parse(nil))
	assert.False(t, src.FDSet, "FDSet must stay false when --passphrase-fd was never passed")
	assert.Equal(t, 0, src.FD)
}

// TestRegisterPassphraseFlags_FDZeroIsExplicit is the regression test for the
// bug this fix closes: an earlier version of this check used `FD > 0`, which
// silently treated an explicit `--passphrase-fd=0` identically to the flag
// never having been passed at all, falling through to a weaker source with no
// error. --passphrase-fd=0 must set FDSet=true so ResolvePassphrase routes
// through the fd path instead.
func TestRegisterPassphraseFlags_FDZeroIsExplicit(t *testing.T) {
	var src crypto.PassphraseSource
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterPassphraseFlags(fs, &src, "", "master passphrase")

	require.NoError(t, fs.Parse([]string{"--passphrase-fd=0"}))
	assert.True(t, src.FDSet, "FDSet must be true for an explicit --passphrase-fd=0")
	assert.Equal(t, 0, src.FD)
}

// TestRegisterPassphraseFlags_MutualExclusionNames verifies the prefix is
// applied consistently to all three returned flag names, so callers wire
// MarkFlagsMutuallyExclusive against the flags actually registered.
func TestRegisterPassphraseFlags_MutualExclusionNames(t *testing.T) {
	var src crypto.PassphraseSource
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fdFlag, fileFlag, stdinFlag := RegisterPassphraseFlags(fs, &src, "new-", "new master passphrase")

	assert.Equal(t, "new-passphrase-fd", fdFlag)
	assert.Equal(t, "new-passphrase-file", fileFlag)
	assert.Equal(t, "new-passphrase-stdin", stdinFlag)
	assert.NotNil(t, fs.Lookup(fdFlag))
	assert.NotNil(t, fs.Lookup(fileFlag))
	assert.NotNil(t, fs.Lookup(stdinFlag))
}
