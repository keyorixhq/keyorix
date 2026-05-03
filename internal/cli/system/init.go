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
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
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
	initServer        string
	initAdminUsername string
	initAdminPassword string
	initAdminEmail    string
)

var InitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Keyorix system with config and keys",
	Long: `Initialize the Keyorix system.

Local mode (default): creates configuration files, encryption keys, and the database.

Remote mode (--server): bootstraps a running Keyorix server — creates the admin
user, default RBAC roles, and default workspace (namespace + 3 environments) via
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
	InitCmd.Flags().StringVar(&initAdminPassword, "admin-password", "admin", "Admin password (change after first login)")
	InitCmd.Flags().StringVar(&initAdminEmail, "admin-email", "admin@localhost", "Admin email address")
}

func runInit(cmd *cobra.Command, args []string) error {
	if initServer != "" {
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

	if err := securefiles.SecureWriteFile(".", configPath, templateData, 0600); err != nil {
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
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to create database file: %w", err)
		}
		if cerr := file.Close(); cerr != nil {
			return fmt.Errorf("failed to close database file: %w", cerr)
		}
	}
	return nil
}

func initializeEncryption(cfg *config.Config) error {
	kekDir := filepath.Dir(cfg.Storage.Encryption.KEKPath)
	dekDir := filepath.Dir(cfg.Storage.Encryption.DEKPath)
	if err := os.MkdirAll(kekDir, 0750); err != nil {
		return fmt.Errorf("failed to create KEK directory: %w", err)
	}
	if err := os.MkdirAll(dekDir, 0750); err != nil {
		return fmt.Errorf("failed to create DEK directory: %w", err)
	}
	return nil
}

func initializeLogging() error {
	logPath := filepath.Clean("keyorix.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0750); err != nil {
		return fmt.Errorf("failed to create logging directory: %w", err)
	}
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to create log file: %w", err)
		}
		if cerr := file.Close(); cerr != nil {
			return fmt.Errorf("failed to close log file: %w", cerr)
		}
	}
	return nil
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
	Namespace    string   `json:"namespace"`
	Zone         string   `json:"zone"`
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
// namespace, zone, and environments in a single idempotent call.
func runRemoteInit() error {
	server := strings.TrimRight(initServer, "/")
	url := server + "/system/init"

	payload := map[string]string{
		"username":     initAdminUsername,
		"email":        initAdminEmail,
		"password":     initAdminPassword,
		"display_name": "Administrator",
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
	defer resp.Body.Close()

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
	fmt.Printf("  +-- Project: %s\n", d.Namespace)
	fmt.Printf("  +-- Environments: %s\n", envList)
	fmt.Printf("  +-- Admin user: %s (change password after first login)\n", username)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  keyorix connect --server %s\n", server)
	fmt.Printf("  keyorix secret create my-first-secret --value \"hello\"\n")
	fmt.Printf("  keyorix run --env production -- your-app\n")

	if initAdminPassword == "admin" {
		fmt.Printf("\nWARNING: You are using the default password %q. Change it immediately.\n", initAdminPassword)
	}

	return nil
}
