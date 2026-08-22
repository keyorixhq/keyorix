package testhelper

import "os"

// IsolateCLIHome points $HOME at a fresh temp directory (and clears
// XDG_CONFIG_HOME) for the duration of a package's test binary run, so tests
// that transitively read ~/.keyorix/cli.yaml via
// internal/cli/config.LoadCLIConfig never see a developer's real config.
// getDefaultCLIConfigPath (internal/cli/config/cli_config.go) checks
// XDG_CONFIG_HOME first, then falls back to os.UserHomeDir() ($HOME on
// unix) -- both must be overridden for isolation to hold.
//
// Call from TestMain, not from individual tests: env vars are process-wide,
// so a per-test t.Setenv would still leave a window where a test running
// before HOME is overridden (or a t.Parallel() sibling) reads the real file.
// Returns a cleanup func restoring the previous environment and removing the
// temp directory; call it after m.Run() and before os.Exit.
func IsolateCLIHome() (cleanup func()) {
	dir, err := os.MkdirTemp("", "keyorix-cli-test-home-*")
	if err != nil {
		// TestMain has no *testing.T to fail through; a broken temp dir
		// means every test in the package would silently fall through to
		// the real $HOME instead, which is worse than crashing loudly here.
		panic("testhelper.IsolateCLIHome: " + err.Error())
	}

	prevHome, hadHome := os.LookupEnv("HOME")
	prevXDG, hadXDG := os.LookupEnv("XDG_CONFIG_HOME")
	_ = os.Setenv("HOME", dir)
	_ = os.Unsetenv("XDG_CONFIG_HOME")

	return func() {
		if hadHome {
			_ = os.Setenv("HOME", prevHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
		if hadXDG {
			_ = os.Setenv("XDG_CONFIG_HOME", prevXDG)
		} else {
			_ = os.Unsetenv("XDG_CONFIG_HOME")
		}
		_ = os.RemoveAll(dir)
	}
}
