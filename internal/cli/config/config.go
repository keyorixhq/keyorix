package config

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/spf13/cobra"
)

// ConfigCmd represents the config command
var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage CLI configuration",
	Long:  "Configure how the CLI connects to storage (local database or remote server)",
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current configuration status",
	RunE:  runStatus,
}

var setRemoteCmd = &cobra.Command{
	Use:   "set-remote",
	Short: "Configure CLI to use remote server",
	Long:  "Switch CLI to use a remote server instead of local database",
	RunE:  runSetRemote,
}

var useLocalCmd = &cobra.Command{
	Use:   "use-local",
	Short: "Configure CLI to use local database",
	Long:  "Switch CLI to use local database instead of remote server",
	RunE:  runUseLocal,
}

var testConnectionCmd = &cobra.Command{
	Use:   "test-connection",
	Short: "Test connection to configured storage",
	RunE:  runTestConnection,
}

func init() {
	// Add flags for set-remote command
	setRemoteCmd.Flags().String("url", "", "Remote server URL (required)")
	setRemoteCmd.Flags().String("api-key", "", "API key for authentication (optional)")
	setRemoteCmd.Flags().Int("timeout", 30, "Request timeout in seconds")
	setRemoteCmd.MarkFlagRequired("url") // #nosec G104

	// Add subcommands
	ConfigCmd.AddCommand(statusCmd)
	ConfigCmd.AddCommand(setRemoteCmd)
	ConfigCmd.AddCommand(useLocalCmd)
	ConfigCmd.AddCommand(testConnectionCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	fmt.Println("📋 Current Configuration")
	fmt.Println("========================")
	
	switch cfg.Storage.Type {
	case "remote":
		fmt.Printf("Storage Type: 🌐 Remote\n")
		fmt.Printf("Server URL:   %s\n", cfg.Storage.Remote.BaseURL)
		if cfg.Storage.Remote.APIKey != "" {
			fmt.Printf("API Key:      %s\n", maskAPIKey(cfg.Storage.Remote.APIKey))
		} else {
			fmt.Printf("API Key:      (not set)\n")
		}
		fmt.Printf("Timeout:      %ds\n", cfg.Storage.Remote.TimeoutSeconds)
	default:
		fmt.Printf("Storage Type: 💾 Local\n")
		fmt.Printf("Database:     %s\n", cfg.Storage.Database.Path)
		if _, err := os.Stat(cfg.Storage.Database.Path); err == nil {
			fmt.Printf("Status:       ✅ Database file exists\n")
		} else {
			fmt.Printf("Status:       ⚠️  Database file will be created on first use\n")
		}
	}

	return nil
}

func runSetRemote(cmd *cobra.Command, args []string) error {
	url, _ := cmd.Flags().GetString("url")
	apiKey, _ := cmd.Flags().GetString("api-key")
	timeout, _ := cmd.Flags().GetInt("timeout")

	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		// Create default config if it doesn't exist
		cfg = &config.Config{}
	}

	// Configure remote storage
	cfg.Storage.Type = "remote"
	if cfg.Storage.Remote == nil {
		cfg.Storage.Remote = &config.RemoteConfig{}
	}
	cfg.Storage.Remote.BaseURL = url
	cfg.Storage.Remote.APIKey = apiKey
	cfg.Storage.Remote.TimeoutSeconds = timeout
	cfg.Storage.Remote.TLSVerify = true

	if err := config.Save("keyorix.yaml", cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✅ Configuration updated successfully!\n")
	fmt.Printf("🌐 CLI now uses remote server: %s\n", url)
	if apiKey == "" {
		fmt.Printf("💡 Tip: Set API key with --api-key flag if server requires authentication\n")
	}

	return nil
}

func runUseLocal(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		// Create default config if it doesn't exist
		cfg = &config.Config{}
	}

	// Configure local storage
	cfg.Storage.Type = "local"
	if cfg.Storage.Database.Path == "" {
		cfg.Storage.Database.Path = "./secrets.db"
	}

	if err := config.Save("keyorix.yaml", cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✅ Configuration updated successfully!\n")
	fmt.Printf("💾 CLI now uses local database: %s\n", cfg.Storage.Database.Path)

	return nil
}

func runTestConnection(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	fmt.Printf("🔍 Testing connection...\n")

	switch cfg.Storage.Type {
	case "remote":
		return testRemoteConnection(cfg)
	default:
		return testLocalConnection(cfg)
	}
}

func testRemoteConnection(cfg *config.Config) error {
	if cfg.Storage.Remote == nil {
		return fmt.Errorf("remote configuration not found")
	}

	// TODO: Implement actual connection test
	// For now, just validate configuration
	if cfg.Storage.Remote.BaseURL == "" {
		return fmt.Errorf("remote server URL not configured")
	}

	fmt.Printf("🌐 Remote server: %s\n", cfg.Storage.Remote.BaseURL)
	fmt.Printf("✅ Configuration appears valid\n")
	fmt.Printf("💡 Note: Actual connection test will be implemented in next phase\n")

	return nil
}

func testLocalConnection(cfg *config.Config) error {
	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}

	if _, err := os.Stat(dbPath); err == nil {
		fmt.Printf("💾 Local database: %s\n", dbPath)
		fmt.Printf("✅ Database file exists and is accessible\n")
	} else {
		fmt.Printf("💾 Local database: %s\n", dbPath)
		fmt.Printf("⚠️  Database file doesn't exist yet (will be created on first use)\n")
	}

	return nil
}

func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "***"
	}
	return apiKey[:4] + "..." + apiKey[len(apiKey)-4:]
}