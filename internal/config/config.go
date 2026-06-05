package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/securefiles"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Environment string           `yaml:"environment"` // development, staging, production
	Locale      LocaleConfig     `yaml:"locale"`
	Server      ServerConfig     `yaml:"server"`
	Storage     StorageConfig    `yaml:"storage"`
	Client      *ClientConfig    `yaml:"client,omitempty"`
	Secrets     SecretsConfig    `yaml:"secrets"`
	Security    SecurityConfig   `yaml:"security"`
	SoftDelete  SoftDeleteConfig `yaml:"soft_delete"`
	Purge       PurgeConfig      `yaml:"purge"`
	Audit       AuditConfig      `yaml:"audit"`
	Membership  MembershipConfig `yaml:"membership"`

	// PasswordPolicy is optional. When the block is absent (zero value), the
	// server keeps its conservative built-in defaults (see core.DefaultPasswordPolicy);
	// when present, the install's values fully replace them.
	PasswordPolicy PasswordPolicyConfig `yaml:"password_policy"`
}

// PasswordPolicyConfig mirrors the password rules from ADR-025: synchronous
// complexity rules plus the stateful rules (reject_common_passwords,
// history_count, max_age_days) backed by the password-history table.
type PasswordPolicyConfig struct {
	MinLength          int  `yaml:"min_length"`
	RequireUppercase   bool `yaml:"require_uppercase"`
	RequireLowercase   bool `yaml:"require_lowercase"`
	RequireDigit       bool `yaml:"require_digit"`
	RequireSpecial     bool `yaml:"require_special"`
	RejectPersonalInfo bool `yaml:"reject_personal_info"`
	// RejectCommonPasswords rejects passwords on the curated common-password list.
	RejectCommonPasswords bool `yaml:"reject_common_passwords"`
	// HistoryCount forbids reusing the last N passwords (0 = no history check).
	HistoryCount int `yaml:"history_count"`
	// MaxAgeDays expires a password after N days (0 = never expires).
	MaxAgeDays int `yaml:"max_age_days"`
}

// IsZero reports whether the password_policy block was effectively absent, so
// the caller can fall back to the built-in defaults instead of an all-off policy.
func (p PasswordPolicyConfig) IsZero() bool {
	return p == PasswordPolicyConfig{}
}

type LocaleConfig struct {
	Language         string `yaml:"language"`
	FallbackLanguage string `yaml:"fallback_language"`
}

type ServerConfig struct {
	HTTP ServerInstanceConfig `yaml:"http"`
	GRPC ServerInstanceConfig `yaml:"grpc"`
}

type ServerInstanceConfig struct {
	Enabled           bool            `yaml:"enabled"`
	Port              string          `yaml:"port"`
	ProtocolVersions  []string        `yaml:"protocol_versions"`
	TLS               TLSConfig       `yaml:"tls"`
	RateLimit         RateLimitConfig `yaml:"ratelimit"`
	SwaggerEnabled    bool            `yaml:"swagger_enabled,omitempty"`
	ReflectionEnabled bool            `yaml:"reflection_enabled,omitempty"`
	// Web dashboard specific settings (HTTP only)
	WebAssetsPath  string   `yaml:"web_assets_path,omitempty"`
	AllowedOrigins []string `yaml:"allowed_origins,omitempty"`
	Domain         string   `yaml:"domain,omitempty"`
}

type TLSConfig struct {
	Enabled        bool     `yaml:"enabled"`
	AutoCert       bool     `yaml:"auto_cert,omitempty"`
	Domains        []string `yaml:"domains,omitempty"`
	CertFile       string   `yaml:"cert_file"`
	KeyFile        string   `yaml:"key_file"`
	AllowedCiphers []string `yaml:"allowed_ciphers"`
}

type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerSecond int  `yaml:"requests_per_second"`
	Burst             int  `yaml:"burst"`
}

type StorageConfig struct {
	Type       string           `yaml:"type"` // "local", "postgres", "postgresql", "remote"
	Database   DatabaseConfig   `yaml:"database"`
	Remote     *RemoteConfig    `yaml:"remote,omitempty"`
	Encryption EncryptionConfig `yaml:"encryption"`
}

type DatabaseConfig struct {
	// SQLite
	Path string `yaml:"path"`

	// PostgreSQL — use DSN directly or set individual fields
	DSN      string `yaml:"dsn"` // e.g. "host=localhost user=keyorix dbname=keyorix port=5432 sslmode=require"
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Name     string `yaml:"name"`
	User     string `yaml:"user"`
	Password string `yaml:"password"` // use KEYORIX_DB_PASSWORD env var instead
	SSLMode  string `yaml:"ssl_mode"` // disable, require, verify-full

	// Shared pool settings
	MaxOpenConns           int `yaml:"max_open_conns"`
	MaxIdleConns           int `yaml:"max_idle_conns"`
	ConnMaxLifetimeMinutes int `yaml:"conn_max_lifetime_minutes"`
}

// GetPassword returns the resolved DB password, preferring the environment variable.
func (d *DatabaseConfig) GetPassword() string {
	return resolveSecret("KEYORIX_DB_PASSWORD", d.Password)
}

// BuildPostgresDSN returns a ready-to-use PostgreSQL DSN.
// If DSN is set directly it is returned as-is; otherwise it is built from individual fields.
func BuildPostgresDSN(d *DatabaseConfig) string {
	if d.DSN != "" {
		return d.DSN
	}
	host := d.Host
	if host == "" {
		host = "localhost"
	}
	port := d.Port
	if port == "" {
		port = "5432"
	}
	sslMode := d.SSLMode
	if sslMode == "" {
		sslMode = "require"
	}
	dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s sslmode=%s",
		host, port, d.Name, d.User, sslMode)
	if pw := d.GetPassword(); pw != "" {
		dsn += " password=" + pw
	}
	return dsn
}

type RemoteConfig struct {
	BaseURL        string `yaml:"base_url"`
	APIKey         string `yaml:"api_key"` // use KEYORIX_REMOTE_API_KEY env var instead
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	RetryAttempts  int    `yaml:"retry_attempts"`
	TLSVerify      bool   `yaml:"tls_verify"`
}

// GetAPIKey returns the resolved API key, preferring the environment variable.
func (r *RemoteConfig) GetAPIKey() string {
	return resolveSecret("KEYORIX_REMOTE_API_KEY", r.APIKey)
}

type ClientConfig struct {
	Endpoint string     `yaml:"endpoint"`
	Auth     AuthConfig `yaml:"auth"`
	Timeout  string     `yaml:"timeout"`
}

type AuthConfig struct {
	Type   string `yaml:"type"`    // "none", "api_key"
	APIKey string `yaml:"api_key"` // use KEYORIX_API_KEY env var instead
}

// GetAPIKey returns the resolved API key, preferring the environment variable.
func (a *AuthConfig) GetAPIKey() string {
	return resolveSecret("KEYORIX_API_KEY", a.APIKey)
}

// EncryptionConfig configures the ADR-004 envelope scheme. The KEK is derived
// from the master passphrase at runtime (PBKDF2) and never touches disk, so the
// only key material on disk is the salt and the wrapped DEK.
type EncryptionConfig struct {
	Enabled  bool   `yaml:"enabled"`
	DEKPath  string `yaml:"dek_path"`
	SaltPath string `yaml:"salt_path"`
}

type SecretsConfig struct {
	Chunking ChunkingConfig `yaml:"chunking"`
	Limits   LimitsConfig   `yaml:"limits"`
}

type ChunkingConfig struct {
	Enabled            bool `yaml:"enabled"`
	MaxChunkSizeKB     int  `yaml:"max_chunk_size_kb"`
	MaxChunksPerSecret int  `yaml:"max_chunks_per_secret"`
}

type LimitsConfig struct {
	MaxSecretsPerUser int `yaml:"max_secrets_per_user"`
}

type SecurityConfig struct {
	EnableFilePermissionCheck  bool `yaml:"enable_file_permission_check"`
	AutoFixFilePermissions     bool `yaml:"auto_fix_file_permissions"`
	AllowUnsafeFilePermissions bool `yaml:"allow_unsafe_file_permissions"`
}

type SoftDeleteConfig struct {
	Enabled       bool `yaml:"enabled"`
	RetentionDays int  `yaml:"retention_days"`
}

// AuditConfig groups audit-log delivery integrations.
type AuditConfig struct {
	SIEM SIEMConfig `yaml:"siem"`
}

// MembershipConfig configures the project membership lifecycle (ADR-022).
type MembershipConfig struct {
	// ValidationMode controls how a new invite onboards: "open" (active
	// immediately), "allowlist" (admin steps through each state), or "idp"
	// (IdP-resolved users skip the early states). Empty = allowlist.
	ValidationMode string `yaml:"validation_mode"`
}

// SIEMConfig configures native push of audit events to an external SIEM.
// The token is resolved from KEYORIX_SIEM_TOKEN when that env var is set, so it
// need not be written into the config file.
type SIEMConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Provider           string `yaml:"provider"` // splunk | datadog | webhook
	Endpoint           string `yaml:"endpoint"`
	Token              string `yaml:"token"` // use KEYORIX_SIEM_TOKEN env var instead
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// GetToken returns the resolved SIEM token, preferring the environment variable.
func (s *SIEMConfig) GetToken() string {
	return resolveSecret("KEYORIX_SIEM_TOKEN", s.Token)
}

type PurgeConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// resolveSecret returns the value of envVar if set and non-empty, otherwise fallback.
func resolveSecret(envVar string, fallback string) string {
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return fallback
}

const appRootDir = "."

// Load loads the YAML configuration file.
//
// Path resolution when path is empty (the default / LoadConfig case):
//  1. KEYORIX_CONFIG_PATH env var, if set (used by container deployments);
//  2. otherwise "keyorix.yaml" in the application root.
//
// An explicit non-empty path argument always wins over the env var.
// Absolute paths (e.g. KEYORIX_CONFIG_PATH=/app/config/production.yaml) are read
// with the safe-read rooted at the file's own directory, so the traversal guard
// still applies; relative paths remain rooted at the application directory.
func Load(path string) (*Config, error) {
	if path == "" {
		path = resolveSecret("KEYORIX_CONFIG_PATH", "")
	}
	if path == "" {
		path = filepath.Join(appRootDir, "keyorix.yaml")
	}

	baseDir, readPath := appRootDir, path
	if filepath.IsAbs(path) {
		baseDir, readPath = filepath.Dir(path), filepath.Base(path)
	}

	data, err := securefiles.SafeReadFile(baseDir, readPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// LoadConfig loads configuration using the default path.
// Used for server module compatibility.
func LoadConfig() (*Config, error) {
	return Load("")
}

// Validate checks the configuration for required fields and correctness.
func (c *Config) Validate() error {
	if c.Server.HTTP.Enabled && c.Server.HTTP.Port == "" {
		return fmt.Errorf("HTTP server is enabled but no port is specified")
	}

	if c.Server.GRPC.Enabled && c.Server.GRPC.Port == "" {
		return fmt.Errorf("gRPC server is enabled but no port is specified")
	}

	if c.Server.HTTP.TLS.Enabled {
		if c.Server.HTTP.TLS.AutoCert {
			if len(c.Server.HTTP.TLS.Domains) == 0 {
				return fmt.Errorf("autocert is enabled but no domains are specified")
			}
		} else {
			if c.Server.HTTP.TLS.CertFile == "" || c.Server.HTTP.TLS.KeyFile == "" {
				return fmt.Errorf("TLS is enabled but cert_file or key_file is missing")
			}
		}
	}

	if c.Server.GRPC.TLS.Enabled {
		if !c.Server.GRPC.TLS.AutoCert {
			if c.Server.GRPC.TLS.CertFile == "" || c.Server.GRPC.TLS.KeyFile == "" {
				return fmt.Errorf("gRPC TLS is enabled but cert_file or key_file is missing")
			}
		}
	}

	switch c.Storage.Type {
	case "remote":
		// remote storage uses its own connection — no local DB config required
	case "postgres", "postgresql":
		db := c.Storage.Database
		if db.DSN == "" && (db.Host == "" || db.Name == "" || db.User == "") {
			return fmt.Errorf("postgres storage requires either database.dsn or all of host, name, and user to be set")
		}
	default: // "local", ""
		if c.Storage.Database.Path == "" {
			return fmt.Errorf("database path is not specified")
		}
	}

	if c.Locale.Language == "" {
		c.Locale.Language = "en"
	}
	if c.Locale.FallbackLanguage == "" {
		c.Locale.FallbackLanguage = "en"
	}

	supportedLanguages := map[string]bool{
		"en": true, "ru": true, "es": true, "fr": true, "de": true,
	}
	if !supportedLanguages[c.Locale.Language] {
		return fmt.Errorf("unsupported language: %s. Supported languages: en, ru, es, fr, de", c.Locale.Language)
	}
	if !supportedLanguages[c.Locale.FallbackLanguage] {
		return fmt.Errorf("unsupported fallback language: %s. Supported languages: en, ru, es, fr, de", c.Locale.FallbackLanguage)
	}

	return nil
}

// Save saves the configuration to a YAML file.
func Save(path string, cfg *Config) error {
	if path == "" {
		path = filepath.Join(appRootDir, "keyorix.yaml")
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := securefiles.SecureWriteFile(appRootDir, path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %q: %w", path, err)
	}

	return nil
}
