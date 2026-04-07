package cli

import (
	"context"
	"fmt"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/client"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// CLIMode represents the operating mode of the CLI
type CLIMode int

const (
	EmbeddedMode CLIMode = iota // Use local core service (default)
	ClientMode                  // Use HTTP client to remote server
)

// String returns the string representation of the CLI mode
func (m CLIMode) String() string {
	switch m {
	case EmbeddedMode:
		return "embedded"
	case ClientMode:
		return "client"
	default:
		return "unknown"
	}
}

// CLI represents the main CLI application with mode-aware service
type CLI struct {
	mode        CLIMode
	config      *cliconfig.CLIConfig
	coreService *core.KeyorixCore  // For embedded mode
	httpClient  *client.HTTPClient // For client mode
}

// NewCLI creates a new CLI instance with automatic mode detection
func NewCLI() (*CLI, error) {
	// Load CLI configuration
	cfg, err := cliconfig.LoadCLIConfig("")
	if err != nil {
		return nil, fmt.Errorf("failed to load CLI config: %w", err)
	}

	cli := &CLI{
		config: cfg,
	}

	// Detect and initialize mode
	if err := cli.initializeMode(); err != nil {
		return nil, fmt.Errorf("failed to initialize CLI mode: %w", err)
	}

	return cli, nil
}

// initializeMode detects the appropriate mode and initializes the service
func (c *CLI) initializeMode() error {
	c.mode = c.detectMode()

	switch c.mode {
	case EmbeddedMode:
		return c.initEmbeddedMode()
	case ClientMode:
		return c.initClientMode()
	default:
		return fmt.Errorf("unsupported CLI mode: %s", c.mode)
	}
}

// detectMode determines which mode to use based on configuration
func (c *CLI) detectMode() CLIMode {
	// Use configured mode
	if c.config.IsClientMode() {
		return ClientMode
	}

	// Default to embedded mode
	return EmbeddedMode
}

// initEmbeddedMode initializes the CLI for embedded mode (local core service)
func (c *CLI) initEmbeddedMode() error {
	// Convert CLI config to main config format
	mainConfig := &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Database: config.DatabaseConfig{
				Path: c.config.Embedded.DatabasePath,
			},
		},
	}

	// Set default database path if not specified
	if mainConfig.Storage.Database.Path == "" {
		mainConfig.Storage.Database.Path = "./secrets.db"
	}

	// Create storage using factory
	factory := storage.NewStorageFactory()
	storageImpl, err := factory.CreateStorage(mainConfig)
	if err != nil {
		return fmt.Errorf("failed to create storage: %w", err)
	}

	// Create core service
	c.coreService = core.NewKeyorixCore(storageImpl)

	return nil
}

// initClientMode initializes the CLI for client mode (remote storage)
func (c *CLI) initClientMode() error {
	if c.config.Client.Endpoint == "" {
		return fmt.Errorf("client endpoint is required for client mode")
	}

	// Convert CLI config to main config format
	mainConfig := &config.Config{
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        c.config.Client.Endpoint,
				APIKey:         c.config.Client.Auth.GetAPIKey(),
				TimeoutSeconds: int(c.config.GetTimeout().Seconds()),
				RetryAttempts:  3,
				TLSVerify:      true,
			},
		},
	}

	// Create storage using factory
	factory := storage.NewStorageFactory()
	storageImpl, err := factory.CreateStorage(mainConfig)
	if err != nil {
		return fmt.Errorf("failed to create remote storage: %w", err)
	}

	// Create core service with remote storage
	c.coreService = core.NewKeyorixCore(storageImpl)

	return nil
}

// GetMode returns the current CLI mode
func (c *CLI) GetMode() CLIMode {
	return c.mode
}

// GetConfig returns the CLI configuration
func (c *CLI) GetConfig() *cliconfig.CLIConfig {
	return c.config
}

// Health checks the health of the current service
func (c *CLI) Health(ctx context.Context) error {
	if c.coreService == nil {
		return fmt.Errorf("core service not initialized")
	}

	// Use the core service's health check which will delegate to the appropriate storage
	return c.coreService.HealthCheck(ctx)
}

// GetCoreService returns the core service instance
func (c *CLI) GetCoreService() *core.KeyorixCore {
	return c.coreService
}
