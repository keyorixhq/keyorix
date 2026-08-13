package system

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/keyorixhq/keyorix/internal/startup"
	"github.com/spf13/cobra"
)

// fixFilePermConfigFile mirrors audit.go's --config flag: an empty default
// defers to config.Load's own resolution order (KEYORIX_CONFIG_PATH env var,
// then "keyorix.yaml") rather than baking in a literal filename that silently
// diverges from --config / KEYORIX_CONFIG_PATH on any non-default deployment.
var fixFilePermConfigFile string

var FixFilePermCmd = &cobra.Command{
	Use:   "fixfileperm",
	Short: "Fix file permissions on critical files (config, salt, DEK)",
	Run: func(cmd *cobra.Command, args []string) {
		runFixFilePerm()
	},
}

func init() {
	FixFilePermCmd.Flags().StringVar(&fixFilePermConfigFile, "config", "", "Path to config file (defaults to $KEYORIX_CONFIG_PATH or keyorix.yaml)")
}

func runFixFilePerm() {
	if runFixFilePermNoExit() {
		os.Exit(1)
	}
}

// runFixFilePermNoExit performs the fix and reports the outcome on stdout,
// returning true if it failed. Splitting this out from runFixFilePerm lets
// tests exercise the real config-path resolution and path-sanitization logic
// (including a deliberate failure) without a failing case tearing down the
// test binary — mirrors runAuditNoExit in audit.go.
func runFixFilePermNoExit() bool {
	resolvedPath := config.ResolvedPath(fixFilePermConfigFile)
	cfg, err := config.Load(fixFilePermConfigFile)
	if err != nil {
		fmt.Println("Failed to load config:", err)
		return true
	}

	// #G59: every path below is config-driven (a config field or the config
	// file's own resolved path) and about to be Chmod'd — sanitized through
	// the same containment check validateFilePermissions applies before
	// FixFilePerms, so a config-driven '..' can't chmod an unintended file.
	var files []securefiles.FilePermSpec
	for _, spec := range []struct{ label, path string }{
		{"KEK salt", cfg.Storage.Encryption.SaltPath},
		{"DEK", cfg.Storage.Encryption.DEKPath},
		{"config file", resolvedPath},
	} {
		if spec.path == "" {
			continue
		}
		clean, cerr := startup.SafeFilePermPath(spec.label, spec.path)
		if cerr != nil {
			fmt.Println("Failed to fix file permissions:", cerr)
			return true
		}
		files = append(files, securefiles.FilePermSpec{Path: clean, Mode: 0600})
	}

	// fix permissions: autofix = true
	if err := securefiles.FixFilePerms(files, true); err != nil {
		fmt.Printf("❌ Failed to fix file permissions: %v\n", err)
		return true
	}
	fmt.Println("✅ All file permissions fixed successfully")
	return false
}
