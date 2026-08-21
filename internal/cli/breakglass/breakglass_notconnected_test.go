package breakglass

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// isolateFromLocalConfig points HOME/XDG_CONFIG_HOME at an empty scratch
// directory so ResolveRemote can't pick up a real ~/.keyorix/cli.yaml or
// ./keyorix.yaml left on the developer's machine (see
// breakglass_s24_test.go's TestActivate_NotConnected/TestList_NotConnected/
// TestRevoke_NotConnected, which are pre-existing and fail locally for
// exactly this reason). With no config file to find, ResolveRemote is
// guaranteed to return ok=false whenever KEYORIX_SERVER/KEYORIX_TOKEN are
// also unset, which is what these tests need to reliably exercise the
// "not connected to a server" branch in each RunE.
func isolateFromLocalConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
}

func TestActivate_NotConnected_Isolated(t *testing.T) {
	isolateFromLocalConfig(t)
	bgProject, bgJustify = 5, "reason"
	t.Cleanup(func() { bgProject, bgJustify = 0, "" })

	err := activateCmd.RunE(nil, nil)
	require.ErrorContains(t, err, "not connected to a server — run: keyorix connect <server>")
}

func TestList_NotConnected_Isolated(t *testing.T) {
	isolateFromLocalConfig(t)
	bgProject = 5
	t.Cleanup(func() { bgProject = 0 })

	err := listCmd.RunE(nil, nil)
	require.ErrorContains(t, err, "not connected to a server — run: keyorix connect <server>")
}

func TestRevoke_NotConnected_Isolated(t *testing.T) {
	isolateFromLocalConfig(t)
	bgProject, bgActivation = 5, 9
	t.Cleanup(func() { bgProject, bgActivation = 0, 0 })

	err := revokeCmd.RunE(nil, nil)
	require.ErrorContains(t, err, "not connected to a server — run: keyorix connect <server>")
}
