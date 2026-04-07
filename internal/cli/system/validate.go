package system

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/startup"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate system configuration and setup",
	Long: `Perform comprehensive validation of the Keyorix system including:
- Configuration file validation
- File permissions and ownership
- Encryption key validation
- Database accessibility
- TLS certificate validation (if enabled)

This command performs the same validation that runs on system startup.`,
	RunE: runValidate,
}

var (
	configFile string
	fixIssues  bool
)

func init() {
	validateCmd.Flags().StringVar(&configFile, "config", "keyorix.yaml", "Path to config file")
	validateCmd.Flags().BoolVar(&fixIssues, "fix", false, "Attempt to fix issues automatically")
}

func runValidate(cmd *cobra.Command, args []string) error {
	fmt.Println("🔍 Validating Keyorix System")
	fmt.Println("============================")

	// Check if config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Printf("❌ Config file not found: %s\n", configFile)
		fmt.Println("💡 Run 'keyorix system init' to create the configuration")
		return fmt.Errorf("config file not found")
	}

	// Perform validation
	result, err := startup.ValidateStartup(configFile)
	if err != nil {
		fmt.Printf("❌ Validation failed: %v\n", err)

		// Print partial results if available
		if result != nil {
			startup.PrintValidationResult(result)
		}

		return err
	}

	// Print results
	startup.PrintValidationResult(result)

	// Provide recommendations
	if len(result.Warnings) > 0 || len(result.Errors) > 0 {
		fmt.Println("\n💡 Recommendations:")

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

		fmt.Println("   • Run 'keyorix system init --force' to reinitialize components")
		fmt.Println("   • Run 'keyorix encryption init' to set up encryption")
		fmt.Println("   • Run 'keyorix system audit' to check file permissions")
	}

	return nil
}
