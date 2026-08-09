package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
	// Add flags for connect command. Secrets default to the secure path (env var /
	// interactive no-echo prompt); passing them as literal flags is insecure (visible
	// via ps and saved in shell history) and warned about at runtime.
	ConnectCmd.Flags().String("api-key", "", "API key (INSECURE on the command line — prefer KEYORIX_API_KEY env var)")
	ConnectCmd.Flags().String("username", "", "Username for authentication (prompts for the password, or reads KEYORIX_PASSWORD)")
	ConnectCmd.Flags().String("password", "", "Password (INSECURE on the command line — omit to be prompted, or set KEYORIX_PASSWORD)")
	ConnectCmd.Flags().String("timeout", "30s", "Request timeout")
	ConnectCmd.Flags().Bool("test", true, "Test connection before saving")
	ConnectCmd.Flags().Bool("insecure", false, "Allow a non-HTTPS (cleartext) endpoint — credentials and tokens would be sent unencrypted")

	// Add subcommands
	ConnectCmd.AddCommand(disconnectCmd)
	ConnectCmd.AddCommand(statusCmd)
}

func runConnect(cmd *cobra.Command, args []string) error {
	endpoint := args[0]
	username, _ := cmd.Flags().GetString("username")
	timeoutStr, _ := cmd.Flags().GetString("timeout")
	testConnection, _ := cmd.Flags().GetBool("test")

	// Resolve the API key without ever requiring it on the command line.
	apiKey := resolveAPIKey(cmd)

	// Refuse to send credentials/tokens over a cleartext (non-HTTPS) endpoint, where a
	// network attacker could capture them, unless --insecure is explicitly given (and a
	// loopback target, used for local testing, is always allowed).
	insecure, _ := cmd.Flags().GetBool("insecure")
	if err := requireSecureEndpoint(endpoint, insecure); err != nil {
		return err
	}

	// Parse timeout
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return fmt.Errorf("invalid timeout format: %w", err)
	}

	fmt.Printf("🔗 Connecting to %s...\n", endpoint)

	// If a username is provided, log in for a token — resolving the password securely
	// (interactive no-echo prompt or KEYORIX_PASSWORD), never requiring it on argv.
	if username != "" {
		password, perr := resolveConnectPassword(cmd, username)
		if perr != nil {
			return perr
		}
		if password == "" {
			return fmt.Errorf("a password is required to log in as %s", username)
		}
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
		fmt.Printf("💡 Tip: set KEYORIX_API_KEY (preferred over --api-key, which leaks via ps/history)\n")
	}

	return nil
}

// requireSecureEndpoint rejects a non-HTTPS endpoint (over which the password/token
// would travel in cleartext, MITM-capturable) unless the caller opted in with --insecure.
// A loopback target is always allowed (local development). An https endpoint is fine.
func requireSecureEndpoint(endpoint string, insecure bool) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	if insecure {
		fmt.Fprintf(os.Stderr, "⚠️  Connecting to %q over cleartext (%s) — credentials and tokens are sent UNENCRYPTED.\n", endpoint, u.Scheme)
		return nil
	}
	return fmt.Errorf("refusing to connect to a non-HTTPS endpoint %q: credentials/tokens would be sent in cleartext. Use an https:// URL, or pass --insecure to override (not recommended)", endpoint)
}

// isLoopbackHost reports whether host is localhost or a loopback IP.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if strings.HasPrefix(host, "127.") || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// resolveAPIKey returns the API key from the (insecure, warned) --api-key flag if set,
// else from the KEYORIX_API_KEY env var. A literal flag value is visible via ps and the
// shell history, so its use is flagged.
func resolveAPIKey(cmd *cobra.Command) string {
	if k, _ := cmd.Flags().GetString("api-key"); k != "" {
		fmt.Fprintln(os.Stderr, "⚠️  Passing --api-key on the command line is insecure (visible via ps/proc and saved in shell history); prefer the KEYORIX_API_KEY environment variable.")
		return k
	}
	return os.Getenv("KEYORIX_API_KEY")
}

// resolveConnectPassword obtains the login password without ever requiring it on argv:
// the (insecure, warned) --password flag if set, else KEYORIX_PASSWORD, else an
// interactive no-echo prompt (mirroring `keyorix auth login`).
func resolveConnectPassword(cmd *cobra.Command, username string) (string, error) {
	if pw, _ := cmd.Flags().GetString("password"); pw != "" {
		fmt.Fprintln(os.Stderr, "⚠️  Passing --password on the command line is insecure (visible via ps/proc and saved in shell history); omit it to be prompted, or set KEYORIX_PASSWORD.")
		return pw, nil
	}
	if pw := os.Getenv("KEYORIX_PASSWORD"); pw != "" {
		return pw, nil
	}
	fmt.Fprintf(os.Stderr, "Password for %s: ", username)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(b), nil
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

// connectHTTPClient is used instead of http.DefaultClient so a 3xx response from
// the target server can't bounce the credential/token-bearing request to an
// internal host (e.g. cloud IMDS) — CWE-918. Matches the CheckRedirect idiom
// used by this codebase's other Keyorix API clients.
var connectHTTPClient = &http.Client{CheckRedirect: refuseConnectRedirect}

func refuseConnectRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("keyorix: refusing to follow redirect to %q", req.URL)
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

	resp, err := connectHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

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

	resp, err := connectHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}
