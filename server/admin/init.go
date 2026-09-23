package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/configs"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
)

// Ported near-verbatim from internal/cli/system/init.go's LOCAL-mode path
// (generateConfigFile/initializeEncryption/initializeDatabase) per ADR-108 §B1
// and docs/cli-split-inventory.md §7 PR 11 -- the remote-bootstrap branch
// (`system init --server ...`, POST /system/init) stays a CLI/API command; it
// talks to a server over the network and has no place in a host-side admin
// subcommand. This command never starts a listener.
var (
	initAll            bool
	initEncryptionOnly bool
	initDatabaseOnly   bool
	initLoggingOnly    bool
	initOverwrite      bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create config, encryption keys, and the database on this host",
	Long: `Initialize the files a Keyorix server needs to start: the config file,
encryption key directories, and an empty database file. Never starts a
listener; run 'keyorix-server' (no subcommand) or 'keyorix-server admin
migrate' afterward.`,
	RunE: runAdminInit,
}

func init() {
	initCmd.Flags().BoolVar(&initAll, "all", true, "Initialize all components")
	initCmd.Flags().BoolVar(&initEncryptionOnly, "encryption", false, "Initialize encryption key directories only")
	initCmd.Flags().BoolVar(&initDatabaseOnly, "database", false, "Initialize the database only")
	initCmd.Flags().BoolVar(&initLoggingOnly, "logging", false, "Initialize logging only")
	initCmd.Flags().BoolVar(&initOverwrite, "overwrite-existing", false, "Overwrite an existing config file (dangerous)")
}

func runAdminInit(cmd *cobra.Command, args []string) error { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	configPath := configPathFlag
	if configPath == "" {
		configPath = "./keyorix.yaml"
	}

	fmt.Println("Keyorix Server Admin: init")
	fmt.Println("==========================")

	setupAll := initAll
	if initEncryptionOnly || initDatabaseOnly || initLoggingOnly {
		setupAll = false
	}

	if err := generateAdminConfigFile(configPath); err != nil {
		return fmt.Errorf("failed to generate config file: %w", err)
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

	if setupAll || initEncryptionOnly {
		if err := initializeAdminEncryption(cfg); err != nil {
			return fmt.Errorf("failed to initialize encryption: %w", err)
		}
	}

	if setupAll || initDatabaseOnly {
		if err := initializeAdminDatabase(cfg); err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
	}

	if setupAll || initLoggingOnly {
		if err := initializeAdminLogging(); err != nil {
			return fmt.Errorf("failed to initialize logging: %w", err)
		}
	}

	fmt.Println("\nKeyorix system initialization completed successfully.")
	fmt.Printf("Config file: %s\n", configPath)
	fmt.Println("Run 'keyorix-server admin validate' to check the setup")
	fmt.Println("Run 'keyorix-server admin migrate' to create the database schema")
	fmt.Println("Run 'keyorix-server admin audit' to check file permissions")

	recordAdminAction(cfg, "admin.init", fmt.Sprintf("ran `keyorix-server admin init` (config=%s)", configPath), true)

	return nil
}

func generateAdminConfigFile(configPath string) error {
	fmt.Printf("Generating config file: %s\n", configPath)

	if _, err := os.Stat(configPath); err == nil && !initOverwrite {
		fmt.Printf("Config file already exists: %s\n", configPath)
		fmt.Println("   Use --overwrite-existing to overwrite")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := securefiles.SecureWriteFileSync(".", configPath, configs.DefaultConfigTemplate, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Config file created: %s\n", configPath)
	return nil
}

func initializeAdminDatabase(cfg *config.Config) error {
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

func initializeAdminEncryption(cfg *config.Config) error {
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

func initializeAdminLogging() error {
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
