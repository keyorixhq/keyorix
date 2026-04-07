package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// CLIConfig represents the CLI-specific configuration
type CLIConfig struct {
	Mode        string             `yaml:"mode"`        // "embedded" or "client"
	Embedded    EmbeddedConfig     `yaml:"embedded"`    // For embedded mode
	Client      ClientConfig       `yaml:"client"`      // For client mode
	Connections []ConnectionConfig `yaml:"connections"` // Saved connections
}

// EmbeddedConfig holds configuration for embedded mode (local database)
type EmbeddedConfig struct {
	DatabasePath string           `yaml:"database_path"`
	Encryption   EncryptionConfig `yaml:"encryption"`
}

// ClientConfig holds configuration for client mode (remote server)
type ClientConfig struct {
	Endpoint string     `yaml:"endpoint"`
	Auth     AuthConfig `yaml:"auth"`
	Timeout  string     `yaml:"timeout"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Type   string `yaml:"type"`    // "none", "api_key"
	APIKey string `yaml:"api_key"` // use KEYORIX_API_KEY env var instead
}

// GetAPIKey returns the resolved API key, preferring the KEYORIX_API_KEY environment variable.
func (a *AuthConfig) GetAPIKey() string {
	if v := os.Getenv("KEYORIX_API_KEY"); v != "" {
		return v
	}
	return a.APIKey
}

// EncryptionConfig holds encryption settings for embedded mode
type EncryptionConfig struct {
	Enabled bool   `yaml:"enabled"`
	KeyPath string `yaml:"key_path"`
}

// ConnectionConfig represents a saved connection
type ConnectionConfig struct {
	Name     string     `yaml:"name"`
	Endpoint string     `yaml:"endpoint"`
	Auth     AuthConfig `yaml:"auth"`
	Default  bool       `yaml:"default,omitempty"`
}

// DefaultCLIConfig returns a default CLI configuration
func DefaultCLIConfig() *CLIConfig {
	return &CLIConfig{
		Mode: "embedded",
		Embedded: EmbeddedConfig{
			DatabasePath: "./secrets.db",
			Encryption: EncryptionConfig{
				Enabled: true,
				KeyPath: "./encryption.key",
			},
		},
		Client: ClientConfig{
			Timeout: "30s",
		},
		Connections: []ConnectionConfig{},
	}
}

// LoadCLIConfig loads CLI configuration from file
func LoadCLIConfig(configPath string) (*CLIConfig, error) {
	// If no path specified, use default
	if configPath == "" {
		configPath = getDefaultCLIConfigPath()
	}

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Return default config if file doesn't exist
		return DefaultCLIConfig(), nil
	}

	// Read file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var config CLIConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults for missing fields
	if config.Mode == "" {
		config.Mode = "embedded"
	}
	if config.Client.Timeout == "" {
		config.Client.Timeout = "30s"
	}
	if config.Embedded.DatabasePath == "" {
		config.Embedded.DatabasePath = "./secrets.db"
	}

	return &config, nil
}

// SaveCLIConfig saves CLI configuration to file
func SaveCLIConfig(config *CLIConfig, configPath string) error {
	// If no path specified, use default
	if configPath == "" {
		configPath = getDefaultCLIConfigPath()
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write file with secure permissions
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetMode returns the current CLI mode
func (c *CLIConfig) GetMode() string {
	return c.Mode
}

// IsEmbeddedMode returns true if CLI is in embedded mode
func (c *CLIConfig) IsEmbeddedMode() bool {
	return c.Mode == "embedded" || c.Mode == ""
}

// IsClientMode returns true if CLI is in client mode
func (c *CLIConfig) IsClientMode() bool {
	return c.Mode == "client"
}

// GetTimeout returns the client timeout as duration
func (c *CLIConfig) GetTimeout() time.Duration {
	if c.Client.Timeout == "" {
		return 30 * time.Second
	}

	duration, err := time.ParseDuration(c.Client.Timeout)
	if err != nil {
		return 30 * time.Second
	}

	return duration
}

// SetEmbeddedMode switches CLI to embedded mode
func (c *CLIConfig) SetEmbeddedMode() {
	c.Mode = "embedded"
}

// SetClientMode switches CLI to client mode with given endpoint
func (c *CLIConfig) SetClientMode(endpoint, apiKey string) {
	c.Mode = "client"
	c.Client.Endpoint = endpoint
	c.Client.Auth.APIKey = apiKey
	if apiKey == "" {
		c.Client.Auth.Type = "none"
	} else {
		c.Client.Auth.Type = "api_key"
	}
}

// AddConnection adds a saved connection
func (c *CLIConfig) AddConnection(name, endpoint, apiKey string, setDefault bool) {
	// Remove existing connection with same name
	c.RemoveConnection(name)

	// Clear default flag from other connections if setting this as default
	if setDefault {
		for i := range c.Connections {
			c.Connections[i].Default = false
		}
	}

	// Add new connection
	conn := ConnectionConfig{
		Name:     name,
		Endpoint: endpoint,
		Auth: AuthConfig{
			APIKey: apiKey,
		},
		Default: setDefault,
	}

	if apiKey == "" {
		conn.Auth.Type = "none"
	} else {
		conn.Auth.Type = "api_key"
	}

	c.Connections = append(c.Connections, conn)
}

// RemoveConnection removes a saved connection by name
func (c *CLIConfig) RemoveConnection(name string) {
	for i, conn := range c.Connections {
		if conn.Name == name {
			c.Connections = append(c.Connections[:i], c.Connections[i+1:]...)
			break
		}
	}
}

// GetConnection returns a saved connection by name
func (c *CLIConfig) GetConnection(name string) (*ConnectionConfig, error) {
	for _, conn := range c.Connections {
		if conn.Name == name {
			return &conn, nil
		}
	}
	return nil, fmt.Errorf("connection '%s' not found", name)
}

// GetDefaultConnection returns the default connection if any
func (c *CLIConfig) GetDefaultConnection() *ConnectionConfig {
	for _, conn := range c.Connections {
		if conn.Default {
			return &conn
		}
	}
	return nil
}

// getDefaultCLIConfigPath returns the default path for CLI config
func getDefaultCLIConfigPath() string {
	// Try to use XDG config directory
	if configDir := os.Getenv("XDG_CONFIG_HOME"); configDir != "" {
		return filepath.Join(configDir, "keyorix", "cli.yaml")
	}

	// Fall back to home directory
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".keyorix", "cli.yaml")
	}

	// Last resort: current directory
	return "./keyorix-cli.yaml"
}

// GetConfigPath returns the current config file path
func GetConfigPath() string {
	return getDefaultCLIConfigPath()
}
