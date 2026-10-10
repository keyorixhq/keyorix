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

This performs the same validation that runs on server startup.

Exit codes: 0 on success, 1 on any failure (see the printed error message).`,
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

	if recs := validateRecommendations(result); len(recs) > 0 {
		fmt.Println("\nRecommendations:")
		for _, r := range recs {
			fmt.Println("   • " + r)
		}
	}

	return nil
}

// validateRecommendations returns only recommendations tied to a finding in
// result (#2940): a healthy install used to be told to re-run
// "init --overwrite-existing" and "migrate" after "All validations passed!".
func validateRecommendations(result *startup.ValidationResult) []string {
	var recs []string
	if len(result.Errors) > 0 {
		recs = append(recs, "Fix the errors listed above before starting the system")
	}
	for _, warning := range result.Warnings {
		if warning == "File permission checks are disabled" {
			recs = append(recs,
				"Consider enabling file permission checks for better security",
				"Run 'keyorix-server admin audit' to check file permissions")
		}
		if warning == "Encryption is disabled" {
			recs = append(recs, "Consider enabling encryption for sensitive data protection")
		}
	}
	return recs
}
