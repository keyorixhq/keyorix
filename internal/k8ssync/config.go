package k8ssync

import (
	"fmt"
	"net/url"
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
	KeyorixURL string `yaml:"keyorix_url"`
	// ProjectID is the numeric id of the single Keyorix project this agent's
	// machine-identity token belongs to (a MachineIdentity — and so its tokens — is
	// always scoped to exactly one project). Every mapping's Ref names only an
	// environment and a secret ("<environment>/<name>"), never a project, because
	// environment names are unique per-project, not globally: two different
	// projects can each have a "production" environment. Without ProjectID pinning
	// every secret lookup to this one project server-side, the fetcher would have
	// to search across every project/environment the token can see and could
	// return a same-named secret from the WRONG project (#Bug1). Required.
	ProjectID  uint            `yaml:"project_id"`
	Interval   string          `yaml:"interval"`    // Go duration (e.g. "5m"); default 5m
	HealthPort int             `yaml:"health_port"` // probe/status HTTP port; default 8080
	Cleanup    bool            `yaml:"cleanup"`     // reap orphaned owned Secrets; default false
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
	// The agent sends the machine-identity token (KEYORIX_TOKEN) as a Bearer header on
	// every request, so keyorix_url MUST be https (http only for loopback in dev) — an
	// http endpoint would ship a secrets-read-capable token in cleartext over the cluster
	// network. The operator (CRD) path already requires https; this matches it.
	if err := requireHTTPSURL(c.KeyorixURL); err != nil {
		return err
	}
	if c.ProjectID == 0 {
		return fmt.Errorf("project_id is required")
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

// requireHTTPSURL rejects a keyorix_url that is not https (http is allowed only for a
// loopback host, for local development/testing).
func requireHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid keyorix_url %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		// K8SSYNC-007: only the hostname "localhost" is allowed over http, not any
		// loopback IP — an attacker who controls DNS can map a loopback IP to a
		// hostname of their choosing, so accepting raw IPs widens the bypass surface.
		return fmt.Errorf("keyorix_url %q must use https (http is allowed only for localhost); sending the bearer token over plaintext would expose it", raw)
	default:
		return fmt.Errorf("keyorix_url %q must use https", raw)
	}
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

const defaultHealthPort = 8080

// GetHealthPort returns the health/probe HTTP port, defaulting to 8080 when unset.
func (c *Config) GetHealthPort() int {
	if c.HealthPort > 0 {
		return c.HealthPort
	}
	return defaultHealthPort
}
