package system

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit critical files for permissions and ownership",
	Run: func(cmd *cobra.Command, args []string) {
		runAudit()
	},
}

// auditConfigFile mirrors the --config flag on `keyorix system validate`: an
// empty default so an unset flag defers to config.Load's own resolution order
// (KEYORIX_CONFIG_PATH env var, then "keyorix.yaml"), rather than baking in a
// literal filename that ignores both the flag and the env var.
var auditConfigFile string

func init() {
	auditCmd.Flags().StringVar(&auditConfigFile, "config", "", "Path to config file (defaults to $KEYORIX_CONFIG_PATH or keyorix.yaml)")
}

// auditCmd is now added to SystemCmd in system.go

func runAudit() {
	if runAuditNoExit() {
		os.Exit(1)
	}
}

// runAuditNoExit performs the audit and reports the outcome on stdout,
// returning true if it failed. Splitting this out from runAudit lets tests
// exercise the real config-path resolution logic (including a deliberate
// failure) without a failing case tearing down the test binary via os.Exit.
func runAuditNoExit() bool {
	// Resolve the same way config.Load will, so the path we report/check below is
	// the file actually loaded — not a hardcoded "keyorix.yaml" that silently
	// diverges from --config / KEYORIX_CONFIG_PATH on any non-default deployment.
	configPath := filepath.Clean(config.ResolvedPath(auditConfigFile))
	fmt.Printf("Auditing config file: %s\n", configPath)

	cfg, err := config.Load(auditConfigFile)
	if err != nil {
		fmt.Println("Failed to load config:", err)
		return true
	}

	// #G59 (sibling gap): every key-material path below is config-driven and about
	// to be Lstat'd/opened — sanitized the same way validateFilePermissions and
	// fixfileperm.go's autofix path do, so a config-driven '..' can't probe an
	// unintended file's permissions even in audit-only mode.
	files := []securefiles.FilePermSpec{{Path: configPath, Mode: 0600}}
	specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
	if err != nil {
		fmt.Println("Failed to fix file permissions:", err)
		return true
	}
	files = append(files, specs...)

	if err := securefiles.FixFilePerms(files, false); err != nil { // false = audit only
		fmt.Println("\nAudit finished with warnings/errors. Please fix the issues.")
		return true
	}

	fmt.Println("✅ Audit passed: all critical files have correct permissions and ownership.")
	return false
}
