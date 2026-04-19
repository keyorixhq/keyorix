package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/spf13/cobra"
)

// ConnectCmd represents the connect command
var ConnectCmd = &cobra.Command{
	Use:   "connect [endpoint]",
	Short: "Connect to a remote server",
	Long:  "Switch CLI to client mode and connect to a remote server",
	Args:  cobra.ExactArgs(1),
	RunE:  runConnect,
}

var disconnectCmd = &cobra.Command{
	Use:   "disconnect",
	Short: "Disconnect from remote server",
	Long:  "Switch CLI back to embedded mode (local database)",
	RunE:  runDisconnect,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show connection status",
	RunE:  runStatus,
}

func init() {
	// Add flags for connect command
	ConnectCmd.Flags().String("api-key", "", "API key for authentication")
	ConnectCmd.Flags().String("username", "", "Username for authentication (obtains token automatically)")
	ConnectCmd.Flags().String("password", "", "Password for authentication (obtains token automatically)")
	ConnectCmd.Flags().String("timeout", "30s", "Request timeout")
	ConnectCmd.Flags().Bool("test", true, "Test connection before saving")

	// Add subcommands
	ConnectCmd.AddCommand(disconnectCmd)
	ConnectCmd.AddCommand(statusCmd)
}

func runConnect(cmd *cobra.Command, args []string) error {
	endpoint := args[0]
	apiKey, _ := cmd.Flags().GetString("api-key")
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	timeoutStr, _ := cmd.Flags().GetString("timeout")
	testConnection, _ := cmd.Flags().GetBool("test")

	// Parse timeout
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return fmt.Errorf("invalid timeout format: %w", err)
	}

	fmt.Printf("🔗 Connecting to %s...\n", endpoint)

	// If username/password provided, log in and get token
	if username != "" && password != "" {
		fmt.Printf("🔑 Logging in as %s...\n", username)
		token, err := loginWithCredentials(endpoint, username, password, timeout)
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}
		apiKey = token
		fmt.Printf("✅ Login successful\n")
	}

	// Test connection if requested
	if testConnection {
		if err := testServerConnection(endpoint, apiKey, timeout); err != nil {
			return fmt.Errorf("connection test failed: %w", err)
		}
		fmt.Printf("✅ Connection test successful\n")
	}

	// Load or create CLI configuration
	cfg, err := cliconfig.LoadCLIConfig("")
	if err != nil {
		cfg = cliconfig.DefaultCLIConfig()
	}

	// Configure client mode
	cfg.SetClientMode(endpoint, apiKey)
	cfg.Client.Timeout = timeoutStr

	// Save configuration
	if err := cliconfig.SaveCLIConfig(cfg, ""); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✅ Connected to %s\n", endpoint)
	fmt.Printf("🌐 CLI is now in client mode\n")

	if apiKey == "" {
		fmt.Printf("💡 Tip: Use --api-key flag if the server requires authentication\n")
	}

	return nil
}

func runDisconnect(cmd *cobra.Command, args []string) error {
	fmt.Printf("🔌 Disconnecting from remote server...\n")

	// Load CLI configuration
	cfg, err := cliconfig.LoadCLIConfig("")
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Check if already in embedded mode
	if cfg.IsEmbeddedMode() {
		fmt.Printf("💾 Already in embedded mode (using local database)\n")
		return nil
	}

	// Switch to embedded mode
	cfg.SetEmbeddedMode()

	// Save configuration
	if err := cliconfig.SaveCLIConfig(cfg, ""); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✅ Disconnected from remote server\n")
	fmt.Printf("💾 CLI is now in embedded mode (using local database)\n")

	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := cliconfig.LoadCLIConfig("")
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	fmt.Println("📊 Connection Status")
	fmt.Println("===================")

	if cfg.IsClientMode() {
		fmt.Printf("Mode:     🌐 Client Mode\n")
		fmt.Printf("Server:   %s\n", cfg.Client.Endpoint)
		fmt.Printf("Auth:     %s\n", cfg.Client.Auth.Type)
		fmt.Printf("Timeout:  %s\n", cfg.Client.Timeout)

		// Test connection
		fmt.Printf("\n🔍 Testing connection...\n")
		if err := testServerConnection(cfg.Client.Endpoint, cfg.Client.Auth.GetAPIKey(), cfg.GetTimeout()); err != nil {
			fmt.Printf("❌ Connection failed: %v\n", err)
		} else {
			fmt.Printf("✅ Connection successful\n")
		}
	} else {
		fmt.Printf("Mode:     💾 Embedded Mode\n")
		fmt.Printf("Database: %s\n", cfg.Embedded.DatabasePath)
		fmt.Printf("Status:   Using local database\n")
	}

	return nil
}

// loginWithCredentials calls the login endpoint and returns a session token.
func loginWithCredentials(endpoint, username, password string, timeout time.Duration) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Data.Token == "" {
		return "", fmt.Errorf("no token in response")
	}

	return result.Data.Token, nil
}

func testServerConnection(endpoint, apiKey string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func getAuthType(apiKey string) string {
	if apiKey == "" {
		return "none"
	}
	return "api_key"
}

func getLocalDatabasePath(cfg *config.Config) string {
	if cfg.Storage.Database.Path != "" {
		return cfg.Storage.Database.Path
	}
	return "./secrets.db"
}
