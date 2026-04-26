package remote

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds the configuration for remote storage
type Config struct {
	BaseURL        string `yaml:"base_url" json:"base_url"`
	APIKey         string `yaml:"api_key" json:"api_key"`
	TimeoutSeconds int    `yaml:"timeout_seconds" json:"timeout_seconds"`
	RetryAttempts  int    `yaml:"retry_attempts" json:"retry_attempts"`
	TLSVerify      bool   `yaml:"tls_verify" json:"tls_verify"`
}

// Validate validates the remote storage configuration
func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return fmt.Errorf("base_url is required for remote storage")
	}

	if c.APIKey == "" {
		return fmt.Errorf("api_key is required for remote storage")
	}

	// Expand environment variables
	c.APIKey = expandEnvVars(c.APIKey)
	c.BaseURL = expandEnvVars(c.BaseURL)

	// Set defaults
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = 30
	}

	if c.RetryAttempts <= 0 {
		c.RetryAttempts = 3
	}

	return nil
}

// GetTimeout returns the timeout duration
func (c *Config) GetTimeout() time.Duration {
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// expandEnvVars expands environment variables in the format ${VAR_NAME}
func expandEnvVars(s string) string {
	return os.Expand(s, func(key string) string {
		return os.Getenv(key)
	})
}

// GetAPIKeyFromEnv gets the API key from environment variable if not set
func (c *Config) GetAPIKeyFromEnv() string {
	if c.APIKey != "" && !strings.HasPrefix(c.APIKey, "${") {
		return c.APIKey
	}

	// Try common environment variable names
	envVars := []string{
		"KEYORIX_API_KEY",
		"KEYORIX_TOKEN",
		"API_KEY",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			return value
		}
	}

	return c.APIKey
}
