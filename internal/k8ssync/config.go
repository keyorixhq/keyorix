package k8ssync

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the Keyorix Kubernetes sync agent's configuration: where the Keyorix
// server is, how often to reconcile, and which secrets map to which Kubernetes
// Secrets. The Keyorix auth token is NOT part of this file — it is read from the
// KEYORIX_TOKEN environment variable so it can come from a mounted Secret.
type Config struct {
	KeyorixURL string          `yaml:"keyorix_url"`
	Interval   string          `yaml:"interval"` // Go duration (e.g. "5m"); default 5m
	Mappings   []SecretMapping `yaml:"mappings"`
}

const defaultSyncInterval = 5 * time.Minute

// LoadConfig reads and validates the agent config at path.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-provided config path
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if strings.TrimSpace(c.KeyorixURL) == "" {
		return fmt.Errorf("keyorix_url is required")
	}
	if len(c.Mappings) == 0 {
		return fmt.Errorf("at least one mapping is required")
	}
	for i, m := range c.Mappings {
		if err := validateMapping(m); err != nil {
			return fmt.Errorf("mapping %d: %w", i, err)
		}
	}
	if c.Interval != "" {
		if _, err := time.ParseDuration(c.Interval); err != nil {
			return fmt.Errorf("invalid interval %q: %w", c.Interval, err)
		}
	}
	return nil
}

// GetInterval returns the reconcile interval, defaulting to 5m when unset.
func (c *Config) GetInterval() time.Duration {
	if c.Interval != "" {
		if d, err := time.ParseDuration(c.Interval); err == nil && d > 0 {
			return d
		}
	}
	return defaultSyncInterval
}
