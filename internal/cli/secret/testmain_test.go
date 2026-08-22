package secret

import (
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testhelper"
)

// TestMain isolates $HOME so tests never read a developer's real
// ~/.keyorix/cli.yaml (internal/cli/config.LoadCLIConfig) -- see
// testhelper.IsolateCLIHome's doc comment for why this belongs here, not in
// each test.
func TestMain(m *testing.M) {
	cleanup := testhelper.IsolateCLIHome()
	code := m.Run()
	cleanup()
	os.Exit(code)
}
