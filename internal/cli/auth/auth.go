package auth

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/spf13/cobra"
)

const (
	configFilename = "keyorix.yaml"
)

// resolveAPIKey is a test seam over common.ResolveAPIKey: production code
// always uses the real implementation, but tests can stub it to exercise the
// "API key is required" branch in runLogin without needing a real TTY (the
// real implementation's interactive prompt uses term.ReadPassword, which
// requires an actual terminal fd and errors — rather than returning "" — on
// a pipe or other non-terminal stdin).
var resolveAPIKey = common.ResolveAPIKey

// verifyRemoteCredentialsFn is a test seam over verifyRemoteCredentials: production
// code always performs the real GET /auth/profile round trip, but tests exercising
// unrelated runLogin behavior (the cleartext-endpoint warning, the --api-key flag
// warning) can stub this out instead of standing up a live HTTP server for every one
// of them. Tests that specifically exercise the verification step itself
// (TestRunLogin_HappyPath et al., auth_remote_test.go) use the real implementation
// against an httptest server, so the actual check stays covered end-to-end.
var verifyRemoteCredentialsFn = verifyRemoteCredentials

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
		// #1644: a Load error means EITHER "no config file yet" (safe to proceed with
		// defaults) OR "a config file is there and failed to parse" (must NOT proceed --
		// falling through to the write below would silently replace an existing,
		// merely-unparseable file, discarding whatever security-relevant settings it
		// held, e.g. security.require_transport_tls: true). Only the first case may
		// fall back to a fresh default config.
		if !config.IsNotExist(err) {
			return fmt.Errorf("failed to load existing configuration: %w", err)
		}
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
			// #G73: this is about to persist a freshly-entered real API key
			// against whatever server ./keyorix.yaml (an untrusted, CWD-
			// relative, attacker-plantable file) named — carry the same
			// warning ResolveRemote's other CLI callers already get.
			common.WarnUntrustedCWDConfigServerURL()
		} else {
			fmt.Print("Enter server URL: ")
			_, _ = fmt.Scanln(&server) // #nosec G104
		}
	}

	// Resolve the API key without ever requiring it on the command line: the
	// (insecure, warned) --api-key flag if set, else KEYORIX_API_KEY, else an
	// interactive no-echo prompt.
	apiKey, err := resolveAPIKey(cmd, true)
	if err != nil {
		return err
	}

	if apiKey == "" {
		return fmt.Errorf("API key is required")
	}

	if server == "" {
		return fmt.Errorf("server URL is required")
	}

	// #G74: about to persist a real API key against this server URL — warn
	// before it's written if the URL isn't HTTPS (and not a loopback target),
	// since the token will be sent in cleartext on every subsequent request.
	common.WarnIfInsecureEndpoint(server)

	// Verify the API key actually authenticates against this server BEFORE persisting
	// anything or printing "Successfully authenticated": previously this command wrote
	// storage.type: remote plus the given URL/key unconditionally and printed that
	// message without ever contacting the server, so a mistyped URL or a bad/revoked
	// key silently produced a config file claiming a working remote login. GET
	// /auth/profile is authenticated but not permission-gated (self-service "My
	// Account" endpoint, ADR-021/ADR-027 — see server/http/router.go), so it proves
	// "this key authenticates against this server" for ANY valid credential regardless
	// of the caller's specific role/permission grants, which a permission-gated probe
	// (e.g. /system/info) could not do without false-negatives for a low-privileged key.
	username, verr := verifyRemoteCredentialsFn(server, apiKey)
	if verr != nil {
		return fmt.Errorf("could not verify credentials against %s: %w", server, verr)
	}

	// Persist only the fields this command sets (#1644): SaveFields edits the on-disk
	// YAML in place, so anything else already in the file -- security.*, other storage
	// settings, comments, key order -- round-trips untouched, instead of being silently
	// reconstituted from whatever this in-memory *Config happens to have (or not have) set.
	if err := config.SaveFields(configFilename, map[string]any{
		"storage.type":                   "remote",
		"storage.remote.base_url":        server,
		"storage.remote.api_key":         apiKey,
		"storage.remote.tls_verify":      true,
		"storage.remote.timeout_seconds": 30,
		"storage.remote.retry_attempts":  3,
	}); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✅ Successfully authenticated with %s as %s\n", server, username)
	fmt.Printf("💡 CLI is now configured to use remote server\n")

	return nil
}

// verifyRemoteCredentials confirms apiKey actually authenticates against server by
// calling the self-service profile endpoint (GET /auth/profile — authenticated but
// not permission-gated, so it works for any valid credential regardless of the
// caller's specific role/permission grants). Returns the authenticated username on
// success, so the operator sees a concrete, verified result rather than a bare
// "success" claim.
func verifyRemoteCredentials(server, apiKey string) (string, error) {
	rc, ok := common.NewRemoteClientWithCredentials(server, apiKey)
	if !ok {
		return "", fmt.Errorf("invalid remote endpoint %q", server)
	}
	var profile struct {
		Username string `json:"username"`
	}
	if err := rc.Get(context.Background(), "/auth/profile", &profile); err != nil {
		return "", err
	}
	if profile.Username == "" {
		return "", fmt.Errorf("server did not return a username for this credential")
	}
	return profile.Username, nil
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
		// #1644: a Load error means EITHER "no config file yet" OR "a config file is
		// there and failed to parse" -- reporting the latter as "no configuration
		// found" is actively misleading, so surface the real error instead.
		if !config.IsNotExist(err) {
			return fmt.Errorf("failed to load existing configuration: %w", err)
		}
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
