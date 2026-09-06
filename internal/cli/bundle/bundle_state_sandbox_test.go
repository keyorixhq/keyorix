package bundle

import (
	"os"
	"testing"
)

// TestMain sandboxes every test in this package against a throwaway
// KEYORIX_BUNDLE_STATE_DIR, so running `go test ./internal/cli/bundle/...` never reads or
// writes the real developer/CI-runner home directory's ~/.keyorix/bundle-installs (see
// internal/bundle/install_state.go's externalStateBaseDir). This package's import/verify
// tests exercise ibundle.Extract for real, which — with no override in place — would
// otherwise write genuine external install-state records into $HOME/.keyorix/bundle-installs
// on whatever machine runs `go test`, one file per distinct --dest used across the suite.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "keyorix-cli-bundle-state-test-*")
	if err != nil {
		os.Exit(1)
	}
	if err := os.Setenv("KEYORIX_BUNDLE_STATE_DIR", dir); err != nil {
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
