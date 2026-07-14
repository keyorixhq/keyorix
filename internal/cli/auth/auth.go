package auth

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/spf13/cobra"
)

const (
	configFilename = "keyorix.yaml"
)

// AuthCmd represents the auth command
var AuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication",
	Long:  "Manage authentication credentials for remote servers",
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Set up API key for remote authentication",
	Long:  "Configure API key for authenticating with remote server",
	RunE:  runLogin,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear authentication credentials",
	Long:  "Remove stored API key and authentication credentials",
	RunE:  runLogout,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check authentication status",
	Long:  "Show current authentication status and configuration",
	RunE:  runStatus,
}

func init() {
	// Add flags for login command. --api-key is INSECURE on the command line (visible
	// via ps/proc and saved in shell history); prefer the KEYORIX_API_KEY env var, or
	// omit it to be prompted.
	loginCmd.Flags().String("api-key", "", "API key for authentication (INSECURE on the command line — prefer KEYORIX_API_KEY env var, or omit to be prompted)")
	loginCmd.Flags().String("server", "", "Server URL to authenticate with")

	// Add subcommands
	AuthCmd.AddCommand(loginCmd)
	AuthCmd.AddCommand(logoutCmd)
	AuthCmd.AddCommand(statusCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")

	// Load current configuration
	cfg, err := config.Load(configFilename)
	if err != nil {
		// Create default config if it doesn't exist
		cfg = &config.Config{
			Storage: config.StorageConfig{
				Type: "local",
				Database: config.DatabaseConfig{
					Path: "./secrets.db",
				},
			},
		}
	}

	// Get server URL if not provided
	if server == "" {
		if cfg.Storage.Remote != nil && cfg.Storage.Remote.BaseURL != "" {
			server = cfg.Storage.Remote.BaseURL
		} else {
			fmt.Print("Enter server URL: ")
			_, _ = fmt.Scanln(&server) // #nosec G104
		}
	}

	// Resolve the API key without ever requiring it on the command line: the
	// (insecure, warned) --api-key flag if set, else KEYORIX_API_KEY, else an
	// interactive no-echo prompt.
	apiKey, err := common.ResolveAPIKey(cmd, true)
	if err != nil {
		return err
	}

	if apiKey == "" {
		return fmt.Errorf("API key is required")
	}

	if server == "" {
		return fmt.Errorf("server URL is required")
	}

	// Update configuration
	cfg.Storage.Type = "remote"
	if cfg.Storage.Remote == nil {
		cfg.Storage.Remote = &config.RemoteConfig{}
	}
	cfg.Storage.Remote.BaseURL = server
	cfg.Storage.Remote.APIKey = apiKey
	cfg.Storage.Remote.TLSVerify = config.BoolPtr(true)
	cfg.Storage.Remote.TimeoutSeconds = 30
	cfg.Storage.Remote.RetryAttempts = 3

	// Save configuration
	if err := config.Save(configFilename, cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✅ Successfully authenticated with %s\n", server)
	fmt.Printf("💡 CLI is now configured to use remote server\n")

	return nil
}

func runLogout(cmd *cobra.Command, args []string) error {
	// Load current configuration
	cfg, err := config.Load(configFilename)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Switch to local storage and clear remote credentials
	cfg.Storage.Type = "local"
	if cfg.Storage.Database.Path == "" {
		cfg.Storage.Database.Path = "./secrets.db"
	}
	cfg.Storage.Remote = nil

	// Save configuration
	if err := config.Save(configFilename, cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✅ Successfully logged out\n")
	fmt.Printf("💾 CLI is now configured to use local database\n")

	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configFilename)
	if err != nil {
		fmt.Printf("❌ No configuration found\n")
		return nil
	}

	fmt.Println("🔐 Authentication Status")
	fmt.Println("========================")

	switch cfg.Storage.Type {
	case "remote":
		if cfg.Storage.Remote != nil {
			fmt.Printf("Status:       ✅ Authenticated\n")
			fmt.Printf("Server:       %s\n", cfg.Storage.Remote.BaseURL)
			if cfg.Storage.Remote.APIKey != "" {
				fmt.Printf("API Key:      %s\n", maskAPIKey(cfg.Storage.Remote.APIKey))
			} else {
				fmt.Printf("API Key:      ❌ Not set\n")
			}
		} else {
			fmt.Printf("Status:       ❌ Remote configured but no credentials\n")
		}
	default:
		fmt.Printf("Status:       💾 Using local storage (not authenticated)\n")
		fmt.Printf("Note:         Use 'keyorix auth login' to authenticate with a remote server\n")
	}

	return nil
}

func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "***"
	}
	return apiKey[:4] + "..." + apiKey[len(apiKey)-4:]
}
