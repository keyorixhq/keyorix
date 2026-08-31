package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/spf13/cobra"
)

const (
	configFilename = "keyorix.yaml"
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
	// Add flags for set-remote command. --api-key is INSECURE on the command line
	// (visible via ps/proc and saved in shell history); prefer the KEYORIX_API_KEY
	// env var.
	setRemoteCmd.Flags().String("url", "", "Remote server URL (required)")
	setRemoteCmd.Flags().String("api-key", "", "API key for authentication (optional; INSECURE on the command line — prefer KEYORIX_API_KEY env var)")
	setRemoteCmd.Flags().Int("timeout", 30, "Request timeout in seconds")
	_ = setRemoteCmd.MarkFlagRequired("url") // #nosec G104

	// Add subcommands
	ConfigCmd.AddCommand(statusCmd)
	ConfigCmd.AddCommand(setRemoteCmd)
	ConfigCmd.AddCommand(useLocalCmd)
	ConfigCmd.AddCommand(testConnectionCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configFilename)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	fmt.Println("📋 Current Configuration")
	fmt.Println("========================")

	switch cfg.Storage.Type {
	case "remote": //nolint:goconst
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

// warnIfInsecureRemoteURL prints the same cleartext-transmission warning as
// internal/cli/common.WarnIfInsecureEndpoint when a server URL that a real API
// key is about to be persisted against is not HTTPS (and not a loopback
// target used for local testing). Duplicated here (not imported) rather than
// calling common.WarnIfInsecureEndpoint: internal/cli/common already imports
// this package (internal/cli/config) for the CLI-connect config, so importing
// it back here would cycle. Keep this message in sync with that one. #G74
func warnIfInsecureRemoteURL(raw string) {
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "https" {
		return
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" {
		return
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return
	}
	fmt.Fprintf(os.Stderr, "⚠️  Remote endpoint %q is not HTTPS — the access token is sent in cleartext and is MITM-capturable.\n", raw)
}

func runSetRemote(cmd *cobra.Command, args []string) error {
	remoteURL, _ := cmd.Flags().GetString("url")
	timeout, _ := cmd.Flags().GetInt("timeout")

	// #G74: about to persist a real API key against this server URL — warn
	// before it's written if the URL isn't HTTPS (and not a loopback target),
	// since the token will be sent in cleartext on every subsequent request.
	warnIfInsecureRemoteURL(remoteURL)

	// Resolve the API key without ever requiring it on the command line: the
	// (insecure, warned) --api-key flag if set, else KEYORIX_API_KEY. The key is
	// optional here, so an unset value is left empty rather than prompted for.
	apiKey := resolveAPIKey(cmd)

	// #1644: check whether an existing config file fails to parse BEFORE writing anything
	// -- distinguishes "no config file yet" (safe to proceed) from "a config file is there
	// and failed to parse" (must NOT proceed; see auth.runLogin's identical guard for the
	// full rationale). The loaded value itself isn't needed: SaveFields below only ever
	// touches the specific fields this command sets, so there's nothing to carry over.
	if _, cerr := config.Load(configFilename); cerr != nil && !config.IsNotExist(cerr) {
		return fmt.Errorf("failed to load existing configuration: %w", cerr)
	}

	// Persist only the fields this command sets (#1644): everything else already in the
	// file round-trips untouched instead of being silently reconstituted from this
	// in-memory *Config's zero values -- see SaveFields' doc comment.
	if err := config.SaveFields(configFilename, map[string]any{
		"storage.type":                   "remote",
		"storage.remote.base_url":        remoteURL,
		"storage.remote.api_key":         apiKey,
		"storage.remote.timeout_seconds": timeout,
		"storage.remote.tls_verify":      true,
	}); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✅ Configuration updated successfully!\n")
	fmt.Printf("🌐 CLI now uses remote server: %s\n", remoteURL)
	if apiKey == "" {
		fmt.Printf("💡 Tip: set the KEYORIX_API_KEY environment variable if the server requires authentication (preferred over --api-key, which leaks via ps/history)\n")
	}

	return nil
}

func runUseLocal(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configFilename)
	if err != nil {
		// #1644: distinguish "no config file yet" (safe to proceed with defaults) from
		// "a config file is there and failed to parse" (must NOT proceed -- see
		// auth.runLogin's identical guard for the full rationale).
		if !config.IsNotExist(err) {
			return fmt.Errorf("failed to load existing configuration: %w", err)
		}
		cfg = &config.Config{}
	}

	// Configure local storage — read the existing path (if the config loaded
	// successfully) to decide whether a default is needed; the write below only ever
	// touches the two fields actually being set.
	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db" //nolint:goconst
	}

	// Persist only the fields this command sets (#1644): everything else already in the
	// file round-trips untouched instead of being silently reconstituted from this
	// in-memory *Config's zero values -- see SaveFields' doc comment.
	if err := config.SaveFields(configFilename, map[string]any{
		"storage.type":          "local",
		"storage.database.path": dbPath,
	}); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✅ Configuration updated successfully!\n")
	fmt.Printf("💾 CLI now uses local database: %s\n", dbPath)

	return nil
}

func runTestConnection(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configFilename)
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

// refuseConfigRedirect stops the connectivity-test client from following any
// redirect: without this, a 3xx response from the configured server could
// bounce the request to an internal host (e.g. cloud IMDS) at request time,
// even though BaseURL itself looked fine when it was set (CWE-918).
func refuseConfigRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("keyorix: refusing to follow redirect to %q", req.URL)
}

func testRemoteConnection(cfg *config.Config) error {
	if cfg.Storage.Remote == nil {
		return fmt.Errorf("remote configuration not found")
	}

	if cfg.Storage.Remote.BaseURL == "" {
		return fmt.Errorf("remote server URL not configured")
	}
	// #G73: this is about to issue an outbound HTTP request (SSRF exposure,
	// including link-local/metadata addresses) to a server URL sourced from
	// ./keyorix.yaml — an untrusted, CWD-relative, attacker-plantable file —
	// with no user confirmation. Duplicated here (not imported) rather than
	// calling internal/cli/common.WarnUntrustedCWDConfigServerURL: that
	// package already imports internal/cli/config for the CLI-connect config,
	// so importing it back here would cycle. Keep this message in sync with
	// that one.
	fmt.Fprintln(os.Stderr, "⚠️  Testing connection using a remote server config from ./keyorix.yaml in the current directory. If you did not place it here, a malicious file could be redirecting the CLI — prefer 'keyorix connect'.")
	fmt.Printf("🌐 Remote server: %s\n", cfg.Storage.Remote.BaseURL)

	timeout := time.Duration(cfg.Storage.Remote.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.Storage.Remote.VerifyTLS()}, // #nosec G402 — honors tls_verify (secure by default)
		},
		CheckRedirect: refuseConfigRedirect,
	}

	// Any HTTP response (even 401) proves the server is reachable; only a
	// transport error means we couldn't connect. We probe a real API path.
	resp, err := client.Get(cfg.Storage.Remote.BaseURL + "/api/v1/system/info")
	if err != nil {
		return fmt.Errorf("could not reach remote server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Printf("✅ Reachable (HTTP %d)\n", resp.StatusCode)
	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Printf("💡 Server is up; this probe is unauthenticated, so credentials were not verified\n")
	}
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

// resolveAPIKey returns the API key from the (insecure, warned) --api-key flag if set,
// else from the KEYORIX_API_KEY env var. A literal flag value is visible via ps and the
// shell history, so its use is flagged — mirrors `keyorix connect`'s resolveAPIKey.
func resolveAPIKey(cmd *cobra.Command) string {
	if k, _ := cmd.Flags().GetString("api-key"); k != "" {
		fmt.Fprintln(os.Stderr, "⚠️  Passing --api-key on the command line is insecure (visible via ps/proc and saved in shell history); prefer the KEYORIX_API_KEY environment variable.")
		return k
	}
	return os.Getenv("KEYORIX_API_KEY")
}

func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "***"
	}
	return apiKey[:4] + "..." + apiKey[len(apiKey)-4:]
}
