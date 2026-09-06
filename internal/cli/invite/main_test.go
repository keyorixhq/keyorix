package invite

import (
	"os"
	"testing"
)

// TestMain isolates every test in this package from a real, developer-machine
// ~/.keyorix/cli.yaml (mode: client) or ambient KEYORIX_SERVER/KEYORIX_TOKEN --
// invite's local-mode tests never intend to exercise the remote branch these
// commands gained (fix-cli-remote-mode-enforcement), but with no isolation a
// stale personal cli.yaml silently redirects them there, where they then fail
// against whatever unreachable address that file happens to name. A single,
// package-wide isolation point (rather than one t.Setenv per test function)
// means a test added later is covered automatically, matching the same
// choke-point-over-convention reasoning behind the remote-mode guards
// themselves. Individual tests that need a REAL remote branch under test
// still set KEYORIX_SERVER/KEYORIX_TOKEN explicitly, which override the blank
// defaults set here.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "invite-test-isolated-home")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)           //nolint:errcheck
	os.Setenv("HOME", dir)            //nolint:errcheck
	os.Setenv("XDG_CONFIG_HOME", dir) //nolint:errcheck
	os.Setenv("KEYORIX_SERVER", "")   //nolint:errcheck
	os.Setenv("KEYORIX_TOKEN", "")    //nolint:errcheck
	os.Exit(m.Run())
}
