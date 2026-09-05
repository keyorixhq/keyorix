package migrate

import (
	"os"
	"testing"
)

// TestMain isolates every test in this package from a real, developer-machine
// ~/.keyorix/cli.yaml (mode: client) or ambient KEYORIX_SERVER/KEYORIX_TOKEN --
// runUserToMachine's new runtime remote-refusal check
// (internal/cli/migrate/user_to_machine.go) reads exactly this configuration,
// and this package's existing tests all assume local-only execution. Without
// isolation, a stale personal cli.yaml makes common.NewRemoteClient() report
// ok=true and every one of these tests hits the refusal error instead of the
// local logic under test. A single, package-wide isolation point (rather than
// one t.Setenv per test function) means a test added later is covered
// automatically.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "migrate-test-isolated-home")
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
