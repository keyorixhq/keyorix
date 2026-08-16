package system

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	configPath     string
	interactive    bool
	initAll        bool
	initEncryption bool
	initDatabase   bool
	initLogging    bool
	force          bool

	// Remote bootstrap flags (--server triggers a different code path).
	initServer         string
	initAdminUsername  string
	initAdminPassword  string
	initAdminEmail     string
	initBootstrapToken string
)

var InitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Keyorix system with config and keys",
	Long: `Initialize the Keyorix system.

Local mode (default): creates configuration files, encryption keys, and the database.

Remote mode (--server): bootstraps a running Keyorix server — creates the admin
user, default RBAC roles, and default workspace (project + 3 environments) via
the HTTP API. Safe to run more than once: idempotent.

Examples:
  keyorix system init                              # local file setup
  keyorix system init --server http://localhost:8080
  keyorix system init --server https://vault.example.com \
      --admin-username admin --admin-password secret --admin-email admin@example.com
  keyorix system init --encryption                 # local: encryption keys only
  keyorix system init --force                      # local: overwrite existing files`,
	RunE: runInit,
}

func init() {
	// Local-mode flags
	InitCmd.Flags().StringVar(&configPath, "config", "./keyorix.yaml", "Path to output config file")
	InitCmd.Flags().BoolVar(&interactive, "interactive", false, "Launch interactive setup wizard")
	InitCmd.Flags().BoolVar(&initAll, "all", true, "Initialize all components")
	InitCmd.Flags().BoolVar(&initEncryption, "encryption", false, "Initialize encryption keys")
	InitCmd.Flags().BoolVar(&initDatabase, "database", false, "Initialize database")
	InitCmd.Flags().BoolVar(&initLogging, "logging", false, "Initialize logging")
	InitCmd.Flags().BoolVar(&force, "force", false, "Overwrite existing files (dangerous)")

	// Remote-bootstrap flags
	InitCmd.Flags().StringVar(&initServer, "server", "", "Bootstrap a remote Keyorix server (triggers remote mode)")
	InitCmd.Flags().StringVar(&initAdminUsername, "admin-username", "admin", "Admin username to create")
	// #G76: no default. A defaulted "admin" password bootstrapped a live remote
	// server with a well-known admin/admin credential pair, and the only
	// feedback (the trailing success banner) arrived AFTER the account already
	// existed — an operator who forgot the flag never saw a warning until the
	// account was already live. Now it's REQUIRED for --server mode, checked
	// before the request is ever sent (see runRemoteInit).
	InitCmd.Flags().StringVar(&initAdminPassword, "admin-password", "", "Admin password (required for --server; INSECURE on the command line — prefer KEYORIX_ADMIN_PASSWORD env var, or omit to be prompted)")
	InitCmd.Flags().StringVar(&initAdminEmail, "admin-email", "admin@localhost", "Admin email address")
	InitCmd.Flags().StringVar(&initBootstrapToken, "bootstrap-token", "", "Bootstrap token authorizing first-admin creation (or env KEYORIX_BOOTSTRAP_TOKEN; printed in the server log on first boot)")
}

func runInit(cmd *cobra.Command, args []string) error { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	if initServer != "" {
		password, err := resolveAdminPassword(cmd)
		if err != nil {
			return err
		}
		initAdminPassword = password
		return runRemoteInit()
	}

	fmt.Println("Keyorix System Initialization")
	fmt.Println("=================================")

	if initEncryption || initDatabase || initLogging {
		initAll = false
	}

	if err := generateConfigFile(); err != nil {
		return fmt.Errorf("failed to generate config file: %w", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if initAll || initEncryption {
		if err := initializeEncryption(cfg); err != nil {
			return fmt.Errorf("failed to initialize encryption: %w", err)
		}
	}

	if initAll || initDatabase {
		if err := initializeDatabase(cfg); err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
	}

	if initAll || initLogging {
		if err := initializeLogging(); err != nil {
			return fmt.Errorf("failed to initialize logging: %w", err)
		}
	}

	fmt.Println("\n✅ Keyorix system initialization completed successfully!")
	fmt.Printf("📋 Config file: %s\n", configPath)
	fmt.Println("🔐 Run 'keyorix encryption status' to check encryption setup")
	fmt.Println("🛡️  Run 'keyorix system audit' to validate file permissions")

	return nil
}

func generateConfigFile() error {
	fmt.Printf("📄 Generating config file: %s\n", configPath)

	if _, err := os.Stat(configPath); err == nil && !force {
		fmt.Printf("⚠️  Config file already exists: %s\n", configPath)
		fmt.Println("   Use --force to overwrite")
		return nil
	}

	templateData, err := securefiles.SafeReadFile(".", "keyorix_template.yaml")
	if err != nil {
		return fmt.Errorf("failed to read template file: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := securefiles.SecureWriteFileSync(".", configPath, templateData, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("✅ Config file created: %s\n", configPath)
	return nil
}

func initializeDatabase(cfg *config.Config) error {
	dbPath := filepath.Clean(cfg.Storage.Database.Path)
	if strings.Contains(dbPath, "..") {
		return fmt.Errorf("invalid path for database: %s", dbPath)
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}
	// O_EXCL makes the create atomic: no TOCTOU window between stat and open.
	// If the file already exists, OpenFile returns an error we treat as "ok".
	file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if cerr := file.Close(); cerr != nil {
			return fmt.Errorf("failed to close database file: %w", cerr)
		}
	} else if !os.IsExist(err) {
		return fmt.Errorf("failed to create database file: %w", err)
	}
	return nil
}

func initializeEncryption(cfg *config.Config) error {
	// The KEK is passphrase-derived and never on disk (ADR-004); only the salt
	// and the wrapped DEK need directories.
	dekDir := filepath.Dir(cfg.Storage.Encryption.DEKPath)
	saltDir := filepath.Dir(cfg.Storage.Encryption.SaltPath)
	if err := os.MkdirAll(dekDir, 0750); err != nil {
		return fmt.Errorf("failed to create DEK directory: %w", err)
	}
	if err := os.MkdirAll(saltDir, 0750); err != nil {
		return fmt.Errorf("failed to create salt directory: %w", err)
	}
	return nil
}

func initializeLogging() error {
	logPath := filepath.Clean("keyorix.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0750); err != nil {
		return fmt.Errorf("failed to create logging directory: %w", err)
	}
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if cerr := file.Close(); cerr != nil {
			return fmt.Errorf("failed to close log file: %w", cerr)
		}
	} else if !os.IsExist(err) {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	return nil
}

// resolveAdminPassword resolves the remote-bootstrap admin password in order
// of preference, mirroring common.ResolveAPIKey's tiered shape for "supply a
// secret to a CLI command safely":
//  1. the (insecure, warned) --admin-password flag, if set;
//  2. the KEYORIX_ADMIN_PASSWORD environment variable;
//  3. an interactive no-echo prompt.
//
// #G76: --admin-password used to default to the literal "admin", silently
// bootstrapping a live remote server with a well-known admin/admin credential
// pair — the only feedback was a warning in the trailing success banner,
// printed AFTER the account already existed. Requiring an explicit choice
// here, before runRemoteInit ever POSTs to the server, closes that gap.
func resolveAdminPassword(cmd *cobra.Command) (string, error) {
	if initAdminPassword != "" {
		common.WarnInsecureFlag(cmd, "admin-password", "prefer the KEYORIX_ADMIN_PASSWORD environment variable, or omit it to be prompted.")
		return initAdminPassword, nil
	}
	if p := os.Getenv("KEYORIX_ADMIN_PASSWORD"); p != "" {
		return p, nil
	}
	fmt.Fprint(os.Stderr, "Enter admin password for the new account: ")
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read admin password: %w", err)
	}
	if len(b) == 0 {
		return "", fmt.Errorf("admin password is required to bootstrap a remote server (--admin-password, KEYORIX_ADMIN_PASSWORD, or enter one at the prompt)")
	}
	return string(b), nil
}

// ── Remote bootstrap ──────────────────────────────────────────────────────────

// bootstrapResponseData mirrors the JSON data block returned by POST /system/init.
type bootstrapResponseData struct {
	AlreadyInitialized bool `json:"already_initialized"`
	User               *struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"user"`
	Project      string   `json:"project"`
	Environments []string `json:"environments"`
}

type bootstrapAPIResponse struct {
	Success bool                  `json:"success"`
	Data    bootstrapResponseData `json:"data"`
	Message string                `json:"message"`
	Error   string                `json:"error"`
}

// runRemoteInit bootstraps a running Keyorix server by calling POST /system/init.
// The server creates the admin user, RBAC roles/permissions, and seeds the default
// project and environments in a single idempotent call.
func runRemoteInit() error { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	server := strings.TrimRight(initServer, "/")
	url := server + "/system/init"

	// #G74: about to POST the admin username/email/password and bootstrap
	// token to this server as JSON — warn before it's sent if the URL isn't
	// HTTPS (and not a loopback target), since those credentials would
	// otherwise leave the machine in cleartext, MITM-capturable.
	common.WarnIfInsecureEndpoint(server)

	token := initBootstrapToken
	if token == "" {
		token = strings.TrimSpace(os.Getenv("KEYORIX_BOOTSTRAP_TOKEN"))
	}
	payload := map[string]string{
		"username":        initAdminUsername,
		"email":           initAdminEmail,
		"password":        initAdminPassword,
		"display_name":    "Administrator",
		"bootstrap_token": token,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body)) // #nosec G107
	if err != nil {
		return fmt.Errorf("could not reach server at %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errResp bootstrapAPIResponse
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if json.Unmarshal(respBody, &errResp) == nil {
			if errResp.Message != "" {
				msg = errResp.Message
			} else if errResp.Error != "" {
				msg = errResp.Error
			}
		}
		return fmt.Errorf("initialisation failed: %s", msg)
	}

	var apiResp bootstrapAPIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("unexpected response from server: %w", err)
	}

	d := apiResp.Data

	if d.AlreadyInitialized {
		fmt.Fprintf(os.Stderr, "Server at %s is already initialised.\n", server)
		fmt.Fprintf(os.Stderr, "Use 'keyorix auth login' to authenticate.\n")
		return nil
	}

	// Success banner — workspace details come from the actual server response.
	envList := strings.Join(d.Environments, ", ")
	if envList == "" {
		envList = "development, staging, production"
	}
	username := initAdminUsername
	if d.User != nil && d.User.Username != "" {
		username = d.User.Username
	}

	fmt.Printf("Keyorix initialised successfully\n\n")
	fmt.Printf("Your workspace is ready:\n")
	fmt.Printf("  +-- Project: %s\n", d.Project)
	fmt.Printf("  +-- Environments: %s\n", envList)
	fmt.Printf("  +-- Admin user: %s (change password after first login)\n", username)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  keyorix connect --server %s\n", server)
	fmt.Printf("  keyorix secret create my-first-secret --value \"hello\"\n")
	fmt.Printf("  keyorix run --env production -- your-app\n")

	if initAdminPassword == "admin" {
		// Deliberately doesn't interpolate initAdminPassword: it's already known to be
		// literally "admin" inside this branch, and echoing a caller-supplied secret
		// back to stdout (terminal scrollback, CI logs) is itself a cleartext-logging
		// exposure independent of what value it happens to be.
		fmt.Printf("\nWARNING: You are using the default password %q. Change it immediately.\n", "admin")
	}

	return nil
}
