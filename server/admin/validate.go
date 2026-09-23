package admin

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/startup"
	"github.com/spf13/cobra"
)

// Ported near-verbatim from internal/cli/system/validate.go per ADR-108 §B1
// and docs/cli-split-inventory.md §7 PR 11 -- wraps the same
// internal/startup.ValidateStartup the server's own boot path
// (runStartupValidation in server/main.go) runs. Never starts a listener.
var validateFixIssues bool

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate config, file permissions, encryption keys, and database",
	Long: `Perform comprehensive validation of the Keyorix system including:
- Configuration file validation
- File permissions and ownership
- Encryption key validation
- Database accessibility

This performs the same validation that runs on server startup.`,
	RunE: runAdminValidate,
}

func init() {
	validateCmd.Flags().BoolVar(&validateFixIssues, "fix", false, "Attempt to fix file-permission issues automatically")
}

func runAdminValidate(cmd *cobra.Command, args []string) error { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	configPath := configPathFlag
	if configPath == "" {
		configPath = config.ResolvedPath("")
	}

	fmt.Println("Validating Keyorix System")
	fmt.Println("=========================")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("Config file not found: %s\n", configPath)
		fmt.Println("Run 'keyorix-server admin init' to create the configuration")
		return fmt.Errorf("config file not found")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	// fixIssues (--fix) is read here and forwarded explicitly, so the flag
	// actually drives remediation instead of silently depending on the
	// Security.AutoFixFilePermissions field read from the same config file
	// being validated (mirrors the CLI command's own comment).
	result, err := startup.ValidateStartup(configPath, validateFixIssues)
	if err != nil {
		fmt.Printf("Validation failed: %v\n", err)
		if result != nil {
			startup.PrintValidationResult(result)
		}
		return err
	}

	startup.PrintValidationResult(result)

	if len(result.Warnings) > 0 || len(result.Errors) > 0 {
		fmt.Println("\nRecommendations:")
		if len(result.Errors) > 0 {
			fmt.Println("   • Fix the errors listed above before starting the system")
		}
		for _, warning := range result.Warnings {
			if warning == "File permission checks are disabled" {
				fmt.Println("   • Consider enabling file permission checks for better security")
			}
			if warning == "Encryption is disabled" {
				fmt.Println("   • Consider enabling encryption for sensitive data protection")
			}
		}
		fmt.Println("   • Run 'keyorix-server admin init --overwrite-existing' to reinitialize components")
		fmt.Println("   • Run 'keyorix-server admin audit' to check file permissions")
		fmt.Println("   • Run 'keyorix-server admin migrate' to apply pending migrations")
	}

	return nil
}
