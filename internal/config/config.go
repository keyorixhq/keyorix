package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/keyorixhq/keyorix/internal/delivery"
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
	// RotationReminders configures the opt-in background scheduler that notifies
	// project admins of secrets overdue / approaching their rotation deadline.
	RotationReminders RotationRemindersConfig `yaml:"rotation_reminders"`
	// AuditCheckpoints configures the opt-in background scheduler that writes
	// signed checkpoints of the audit hash chain (ADR-029) for on-box truncation
	// detection. Requires encryption enabled (the signing key is DEK-derived).
	AuditCheckpoints AuditCheckpointsConfig `yaml:"audit_checkpoints"`
	// JITAccessExpiry configures the opt-in background sweeper that removes
	// time-bound role grants whose expiry has passed (just-in-time access).
	JITAccessExpiry JITAccessExpiryConfig `yaml:"jit_access_expiry"`
	// BreakGlass configures opt-in self-service emergency access (incident response).
	BreakGlass BreakGlassConfig `yaml:"break_glass"`
	// DualControl configures N-of-M approval for access-request grants (A.5.3).
	DualControl DualControlConfig `yaml:"dual_control"`
	// AnomalyAlerts configures proactive alerting for detected access anomalies.
	AnomalyAlerts AnomalyAlertsConfig `yaml:"anomaly_alerts"`
	// DataRetention configures the opt-in scheduler that hard-deletes compliance
	// records past their per-record-type retention window (ISO 27001 A.5.33 /
	// GDPR storage-limitation / DORA). Respects legal hold; audit events are never
	// purged (append-only, ADR-029).
	DataRetention DataRetentionConfig `yaml:"data_retention"`
	// EvidenceDelivery configures the opt-in scheduler that periodically generates
	// the auditor evidence pack and writes it to an output directory for off-box
	// archival (ISO 27001 / SOC 2 continuous evidence).
	EvidenceDelivery EvidenceDeliveryConfig `yaml:"evidence_delivery"`
	// Recertification configures the opt-in scheduler that enforces an access-review
	// cadence (ISO 27001 A.5.18): reminding admins of (or auto-opening) recert
	// campaigns for projects overdue for review.
	Recertification RecertificationConfig `yaml:"recertification"`
	// Notifications configures external delivery (email/webhook) of the in-app
	// notifications Keyorix creates (approvals, anomalies, reminders, break-glass).
	Notifications NotificationsConfig `yaml:"notifications"`
	// SCIM configures the SCIM 2.0 provisioning endpoints (RFC 7644) used by an IdP
	// to provision/deprovision users. Disabled (zero value) = /scim/v2 is not served.
	SCIM SCIMConfig `yaml:"scim"`
	// DynamicSecrets configures the on-demand database-credentials engine and its
	// auto-revoke sweep (ADR-035). Disabled (zero value) = the API is still served
	// but no background sweeper runs; enable to auto-revoke leases at expiry.
	DynamicSecrets DynamicSecretsConfig `yaml:"dynamic_secrets"`
	// WebAuthn configures passkey / FIDO2 second-factor auth (ADR-036). Disabled
	// (zero value) = passkey endpoints return "not enabled"; enable + set the RP ID
	// and origins to allow registration and assertion.
	WebAuthn WebAuthnConfig `yaml:"webauthn"`
	// OIDC configures machine-identity federation (ADR-031): trusted issuers
	// whose JWTs (e.g. Kubernetes projected service-account tokens) Keyorix
	// verifies and maps to a machine identity. Empty/disabled = OIDC auth off.
	OIDC       OIDCConfig       `yaml:"oidc"`
	Audit      AuditConfig      `yaml:"audit"`
	Membership MembershipConfig `yaml:"membership"`
	Session    SessionConfig    `yaml:"session"`

	// CredentialDelivery configures how a new principal receives their first-credential
	// setup link (ADR-028). Absent (zero value) = auto mode, out-of-band when no SMTP.
	CredentialDelivery CredentialDeliveryConfig `yaml:"credential_delivery"`

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
	// TLSVerify is a pointer so "unset" is distinguishable from an explicit
	// false: omitting tls_verify must NOT disable certificate verification on
	// the (highly sensitive) secrets-manager API channel. Resolve via VerifyTLS.
	TLSVerify *bool `yaml:"tls_verify"`
}

// GetAPIKey returns the resolved API key, preferring the environment variable.
func (r *RemoteConfig) GetAPIKey() string {
	return resolveSecret("KEYORIX_REMOTE_API_KEY", r.APIKey)
}

// VerifyTLS reports whether TLS certificate verification is enabled for the
// remote connection. Secure by default: verification is on unless the operator
// EXPLICITLY sets `tls_verify: false`. An omitted key verifies.
func (r *RemoteConfig) VerifyTLS() bool {
	return r.TLSVerify == nil || *r.TLSVerify
}

// BoolPtr returns a pointer to b — for setting optional *bool config fields.
func BoolPtr(b bool) *bool { return &b }

type ClientConfig struct {
	Endpoint string     `yaml:"endpoint"`
	Auth     AuthConfig `yaml:"auth"`
	Timeout  string     `yaml:"timeout"`
}

type AuthConfig struct {
	Type   string `yaml:"type"`    // "none", "api_key"
	APIKey string `yaml:"api_key"` // use KEYORIX_API_KEY env var instead
}

// OIDCConfig is the trusted-issuer allowlist for machine-identity federation.
type OIDCConfig struct {
	Enabled bool               `yaml:"enabled"`
	Issuers []OIDCIssuerConfig `yaml:"issuers"`
}

// OIDCIssuerConfig describes one trusted token issuer.
type OIDCIssuerConfig struct {
	Name      string   `yaml:"name"`      // operator label
	Issuer    string   `yaml:"issuer"`    // must equal the JWT `iss` exactly
	JWKSURI   string   `yaml:"jwks_uri"`  // where the issuer's signing keys live
	Audiences []string `yaml:"audiences"` // the JWT `aud` must contain one of these
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
	// KeyProvider selects where the KEK comes from (ADR-038). Absent/zero value =
	// the default passphrase derivation (KEYORIX_MASTER_PASSWORD + on-disk salt),
	// byte-identical to the historical behaviour.
	KeyProvider KeyProviderConfig `yaml:"key_provider"`
}

// KeyProviderConfig selects the KEK source. type: "password" (default) derives the
// KEK from KEYORIX_MASTER_PASSWORD; "file" reads raw key material from FilePath;
// "env" reads it from the EnvVar's value (hex or base64); "aws-kms" / "gcp-kms" /
// "azure-kms" envelope-wrap the KEK with a cloud KMS/HSM key (ADR-041) and store
// the wrapped blob at WrappedKeyPath. file/env suit a KEK injected by a sealed/SOPS
// secret or CSI driver; the KMS providers keep the wrapping key in the cloud HSM.
type KeyProviderConfig struct {
	Type     string `yaml:"type"`
	FilePath string `yaml:"file_path"`
	EnvVar   string `yaml:"env_var"`
	// KMSKeyID is the cloud KMS key for type aws-kms / gcp-kms / azure-kms: an AWS
	// key ID, ARN, or alias; a GCP crypto-key resource name
	// (projects/P/locations/L/keyRings/R/cryptoKeys/K); or an Azure Key Vault key
	// identifier URL (https://{vault}.vault.azure.net/keys/{name}[/{version}]).
	// Region/credentials come from the standard cloud environment, not from here.
	KMSKeyID string `yaml:"kms_key_id"`
	// WrappedKeyPath is where the KMS-wrapped KEK blob lives (aws-kms / gcp-kms /
	// azure-kms).
	WrappedKeyPath string `yaml:"wrapped_key_path"`
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
	// RequireMFA mandates TOTP MFA for interactive login: a session-authenticated
	// user without MFA enabled is confined to the MFA-enrolment endpoints until
	// they enrol. Non-interactive credentials (PAT/machine/OIDC) are exempt.
	RequireMFA bool `yaml:"require_mfa"`
}

type SoftDeleteConfig struct {
	Enabled       bool `yaml:"enabled"`
	RetentionDays int  `yaml:"retention_days"`
}

// GetRetentionDays returns the soft-delete grace period in days, defaulting to
// 30 when unset (ADR-032).
func (c SoftDeleteConfig) GetRetentionDays() int {
	if c.RetentionDays <= 0 {
		return 30
	}
	return c.RetentionDays
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

// CredentialDeliveryConfig configures the ADR-028 credential-delivery subsystem:
// how a brand-new principal receives their first-credential setup link.
type CredentialDeliveryConfig struct {
	// Mode selects the channel: auto | smtp | out_of_band | log ("" = auto).
	Mode string `yaml:"mode"`
	// SetupTokenTTL is the single-use setup/invite link lifetime (e.g. "24h").
	// Empty = DefaultSetupTokenTTLString.
	SetupTokenTTL string `yaml:"setup_token_ttl"`
	// BaseURL is required for any link-producing mode; used to build absolute setup
	// links (e.g. "https://keyorix.acme.internal"). A relative link is a
	// misconfiguration, not a fallback, so link minting refuses an empty BaseURL.
	BaseURL string               `yaml:"base_url"`
	SMTP    CredentialSMTPConfig `yaml:"smtp"`
}

// CredentialSMTPConfig is the operator's own mail relay. The password is resolved
// from KEYORIX_SMTP_PASSWORD when set, so it need not be written into the file
// (same convention as the DB password).
type CredentialSMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"` // use KEYORIX_SMTP_PASSWORD env var instead
	From     string `yaml:"from"`
	TLS      string `yaml:"tls"` // starttls | implicit | none(dev-only)
}

// DefaultSetupTokenTTLString is the fallback link lifetime when none is configured.
const DefaultSetupTokenTTLString = "24h"

// GetSetupTokenTTL parses SetupTokenTTL, falling back to 24h when empty or invalid.
func (c *CredentialDeliveryConfig) GetSetupTokenTTL() time.Duration {
	raw := c.SetupTokenTTL
	if raw == "" {
		raw = DefaultSetupTokenTTLString
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		d, _ = time.ParseDuration(DefaultSetupTokenTTLString)
	}
	return d
}

// SessionConfig tunes session-token lifetimes for short-lived tokens with silent
// auto-refresh. Absent (zero value) keeps the backward-compatible behaviour: a 24h
// access window and no absolute ceiling (refreshable indefinitely). An install that
// wants short-lived tokens sets a short access_ttl plus an absolute_ttl ceiling and
// relies on the client to refresh silently before each access window lapses.
type SessionConfig struct {
	// AccessTTL is how long an issued access token is valid before it must be
	// refreshed (e.g. "30m"). Empty = DefaultAccessTTLString (24h).
	AccessTTL string `yaml:"access_ttl"`
	// AbsoluteTTL caps total session lifetime from login: refreshing the access
	// window can never extend a session past it (e.g. "12h"). Empty or "0" = no
	// ceiling, so a session can be refreshed indefinitely (legacy behaviour).
	AbsoluteTTL string `yaml:"absolute_ttl"`
}

// DefaultAccessTTLString is the fallback access-token lifetime. It matches the
// historic hard-coded 24h so an install that does not configure a session block
// keeps exactly the old behaviour (no un-refreshing client is logged out).
const DefaultAccessTTLString = "24h"

// GetAccessTTL parses AccessTTL, falling back to 24h when empty or invalid.
func (c *SessionConfig) GetAccessTTL() time.Duration {
	raw := c.AccessTTL
	if raw == "" {
		raw = DefaultAccessTTLString
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		d, _ = time.ParseDuration(DefaultAccessTTLString)
	}
	return d
}

// GetAbsoluteTTL parses AbsoluteTTL. Empty, "0", or an unparseable/non-positive
// value means "no ceiling" and returns 0 — sessions are then refreshable forever.
func (c *SessionConfig) GetAbsoluteTTL() time.Duration {
	if c.AbsoluteTTL == "" {
		return 0
	}
	d, err := time.ParseDuration(c.AbsoluteTTL)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// GetPassword returns the resolved SMTP password, preferring the environment variable.
func (s *CredentialSMTPConfig) GetPassword() string {
	return resolveSecret("KEYORIX_SMTP_PASSWORD", s.Password)
}

// DeliveryConfig maps the credential-delivery config block onto the delivery package's
// channel selector, resolving the SMTP password from the environment. Shared by the
// server and CLI wiring (ADR-028) so the mapping lives in exactly one place.
func (c *CredentialDeliveryConfig) DeliveryConfig() delivery.Config {
	return delivery.Config{
		Mode:    c.Mode,
		BaseURL: c.BaseURL,
		SMTP: delivery.SMTPSettings{
			Host:     c.SMTP.Host,
			Port:     c.SMTP.Port,
			Username: c.SMTP.Username,
			Password: c.SMTP.GetPassword(),
			From:     c.SMTP.From,
			TLS:      c.SMTP.TLS,
		},
	}
}

type PurgeConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// DataRetentionConfig configures the data-retention scheduler (ISO 27001 A.5.33 /
// GDPR storage-limitation / DORA): a background job that hard-deletes compliance
// records past their per-record-type retention window. Each *_days window is a
// number of days; 0 (the zero value) disables retention for that type — those
// records are kept indefinitely. Opt-in (Enabled, default off). Respects legal
// hold: while a hold is active nothing is purged. Audit events are NEVER purged
// (append-only tamper-evidence, ADR-029) and soft-deleted rows are handled by the
// separate ADR-032 purge — this scheduler covers the compliance records that would
// otherwise accumulate forever.
type DataRetentionConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	// AnomalyAlertsDays ages out resolved/old access-anomaly alerts on detected_at.
	AnomalyAlertsDays int `yaml:"anomaly_alerts_days"`
	// ClosedAccessReviewsDays ages out closed recertification campaigns (and their
	// snapshot items) on closed_at. Open campaigns are never purged.
	ClosedAccessReviewsDays int `yaml:"closed_access_reviews_days"`
	// BreakGlassDays ages out non-active emergency-access activations on created_at.
	// Active activations are never purged.
	BreakGlassDays int `yaml:"break_glass_days"`
	// ResolvedAccessRequestsDays ages out terminal-state access requests (and their
	// approval records) on resolved_at. Pending requests are never purged.
	ResolvedAccessRequestsDays int `yaml:"resolved_access_requests_days"`
}

// GetInterval returns the data-retention run interval, parsing Schedule as a Go
// duration (e.g. "24h", "6h"); defaults to 24h when unset or unparseable.
func (c DataRetentionConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// EvidenceDeliveryConfig configures the scheduled compliance-evidence export
// (ISO 27001 / SOC 2 continuous evidence): a background job that periodically
// generates the auditor evidence pack (the posture plus the records that
// substantiate it) and delivers it to the configured targets — a timestamped JSON
// file under OutputDir, and/or a Webhook that POSTs the pack off-box (so evidence
// survives the node without a mounted volume). Each run also emits a
// compliance.evidence_exported audit event, so an installed SIEM forwarder receives
// the delivery signal too. Opt-in (Enabled, default off); at least one target
// (OutputDir or Webhook) must be configured.
type EvidenceDeliveryConfig struct {
	Enabled   bool                  `yaml:"enabled"`
	Schedule  string                `yaml:"schedule"`
	OutputDir string                `yaml:"output_dir"`
	Webhook   EvidenceWebhookConfig `yaml:"webhook"`
}

// EvidenceWebhookConfig configures the off-box webhook target: each run POSTs the
// evidence pack JSON to Endpoint, optionally bearer-authenticated.
type EvidenceWebhookConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Endpoint           string `yaml:"endpoint"`
	Token              string `yaml:"token"` // use KEYORIX_EVIDENCE_WEBHOOK_TOKEN env var instead
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// GetToken returns the resolved webhook token, preferring the environment variable.
func (c *EvidenceWebhookConfig) GetToken() string {
	return resolveSecret("KEYORIX_EVIDENCE_WEBHOOK_TOKEN", c.Token)
}

// HasTarget reports whether at least one delivery target is configured.
func (c EvidenceDeliveryConfig) HasTarget() bool {
	return c.OutputDir != "" || c.Webhook.Enabled
}

// GetInterval returns the evidence-export run interval, parsing Schedule as a Go
// duration (e.g. "24h"); defaults to 24h when unset or unparseable.
func (c EvidenceDeliveryConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// RecertificationConfig configures scheduled access recertification (ISO 27001
// A.5.18, "review access rights at planned intervals"). When Enabled, a background
// job finds projects whose access is due for review — never reviewed, or last
// reviewed more than CadenceDays ago — and, if AutoOpen, opens a recert campaign for
// each (system-actored); otherwise it reminds the project's admins to. It also nudges
// admins of in-flight campaigns that still have pending items. Opt-in (default off).
type RecertificationConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	// CadenceDays is the review interval; a project becomes due this many days after
	// its last campaign closed. 0 = the default (90 days).
	CadenceDays int `yaml:"cadence_days"`
	// AutoOpen, when true, opens a campaign automatically for an overdue project;
	// when false the scheduler only reminds admins to open one themselves.
	AutoOpen bool `yaml:"auto_open"`
}

// GetInterval returns the recertification run interval, parsing Schedule as a Go
// duration (e.g. "24h"); defaults to 24h when unset or unparseable.
func (c RecertificationConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// NotificationsConfig configures external delivery channels for in-app
// notifications (ISO 27001 A.5.5 / SOC 2 operational alerting). Each channel is
// opt-in; with none enabled, notifications remain in-app only. When more than one
// is enabled, each notification is fanned out to all of them.
type NotificationsConfig struct {
	Webhook NotificationWebhookConfig `yaml:"webhook"`
	Email   NotificationEmailConfig   `yaml:"email"`
}

// NotificationEmailConfig configures the SMTP notification channel: each
// notification is emailed (plaintext) to the recipient via the operator's relay.
// Mirrors the credential-delivery SMTP settings (ADR-028).
type NotificationEmailConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"` // use KEYORIX_NOTIFY_SMTP_PASSWORD env var instead
	From     string `yaml:"from"`
	TLS      string `yaml:"tls"` // starttls | implicit | none(dev-only)
}

// GetPassword returns the resolved SMTP password, preferring the environment variable.
func (c *NotificationEmailConfig) GetPassword() string {
	return resolveSecret("KEYORIX_NOTIFY_SMTP_PASSWORD", c.Password)
}

// NotificationWebhookConfig configures the webhook notification channel: each
// notification is POSTed as JSON to Endpoint, optionally bearer-authenticated.
type NotificationWebhookConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Endpoint           string `yaml:"endpoint"`
	Token              string `yaml:"token"` // use KEYORIX_NOTIFY_WEBHOOK_TOKEN env var instead
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// GetToken returns the resolved webhook token, preferring the environment variable.
func (c *NotificationWebhookConfig) GetToken() string {
	return resolveSecret("KEYORIX_NOTIFY_WEBHOOK_TOKEN", c.Token)
}

// SCIMConfig configures SCIM 2.0 provisioning (RFC 7644). When Enabled, the
// /scim/v2 endpoints are served, authenticated by a static bearer token an IdP
// presents. Opt-in (default off).
type SCIMConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"` // use KEYORIX_SCIM_TOKEN env var instead
}

// GetToken returns the resolved SCIM bearer token, preferring the env var.
func (s *SCIMConfig) GetToken() string {
	return resolveSecret("KEYORIX_SCIM_TOKEN", s.Token)
}

// RotationRemindersConfig configures the rotation-reminder scheduler: a background
// job that notifies project admins of secrets overdue/approaching their rotation
// deadline under an active rotation policy. Opt-in (default off).
type RotationRemindersConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// GetInterval returns the rotation-reminder run interval (Go duration, e.g. "24h");
// defaults to 24h when unset or unparseable.
func (c RotationRemindersConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// AuditCheckpointsConfig configures the audit-checkpoint scheduler: a background
// job that signs the audit hash-chain head (ADR-029) so tail-truncation / re-seed
// is detectable on-box. Opt-in (default off); requires encryption enabled.
type AuditCheckpointsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// GetInterval returns the checkpoint write interval (Go duration, e.g. "12h");
// defaults to 24h when unset or unparseable.
func (c AuditCheckpointsConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// JITAccessExpiryConfig configures the just-in-time access-expiry sweeper: a
// background job that removes time-bound role grants whose expiry has passed and
// audits each as role.expired. Expired grants stop authorizing immediately (the
// authorization queries filter on expiry); this sweep reclaims the rows. Opt-in
// (default off).
type JITAccessExpiryConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// GetInterval returns the expiry-sweep interval (Go duration, e.g. "1h"); defaults
// to 1h when unset or unparseable.
func (c JITAccessExpiryConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

// BreakGlassConfig configures self-service emergency access (break-glass): a user
// can immediately self-grant a time-bound emergency role with a written
// justification, loudly audited, for incident response (NIS2/DORA). Opt-in
// (default off — disabled means the endpoint refuses).
type BreakGlassConfig struct {
	Enabled       bool   `yaml:"enabled"`
	EmergencyRole string `yaml:"emergency_role"` // role granted on activation (e.g. "project_admin")
	DefaultTTL    string `yaml:"default_ttl"`    // grant lifetime when none requested (e.g. "4h")
	MaxTTL        string `yaml:"max_ttl"`        // ceiling on a requested TTL (e.g. "24h")
}

// GetDefaultTTL returns the default emergency-grant lifetime; defaults to 4h.
func (c BreakGlassConfig) GetDefaultTTL() time.Duration {
	if c.DefaultTTL != "" {
		if d, err := time.ParseDuration(c.DefaultTTL); err == nil && d > 0 {
			return d
		}
	}
	return 4 * time.Hour
}

// GetMaxTTL returns the ceiling on a requested emergency-grant TTL; defaults to 24h.
func (c BreakGlassConfig) GetMaxTTL() time.Duration {
	if c.MaxTTL != "" {
		if d, err := time.ParseDuration(c.MaxTTL); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// AnomalyAlertsConfig configures proactive alerting for detected access anomalies
// (NIS2 detection & response). The hourly detection scan always runs; when this is
// enabled, each newly detected anomaly is also pushed to the project's admins
// (in-app) and the audit trail / SIEM. Opt-in (default off).
type AnomalyAlertsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// GetInterval returns the anomaly scan/alert interval (Go duration); defaults to 1h.
func (c AnomalyAlertsConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

// DualControlConfig configures N-of-M approval (dual control) for access-request
// grants (ISO 27001 A.5.3 / SOX): a request grants its role only once this many
// distinct approvers (none the requester) have approved. 0 or 1 = disabled (a
// single approval grants, the default behaviour).
type DualControlConfig struct {
	RequiredApprovals int `yaml:"required_approvals"`
}

// GetRequiredApprovals returns the dual-control threshold (minimum 1).
func (c DualControlConfig) GetRequiredApprovals() int {
	if c.RequiredApprovals > 1 {
		return c.RequiredApprovals
	}
	return 1
}

// WebAuthnConfig configures the WebAuthn relying party (ADR-036). RPID is the
// effective domain (e.g. "keyorix.example.com", no scheme/port); RPOrigins are the
// full origins permitted to authenticate (e.g. "https://keyorix.example.com").
type WebAuthnConfig struct {
	Enabled       bool     `yaml:"enabled"`
	RPID          string   `yaml:"rp_id"`
	RPDisplayName string   `yaml:"rp_display_name"`
	RPOrigins     []string `yaml:"rp_origins"`
}

// DynamicSecretsConfig configures the dynamic-secrets auto-revoke sweep (ADR-035).
type DynamicSecretsConfig struct {
	// SweepEnabled turns on the background sweeper that revokes leases past expiry.
	SweepEnabled bool `yaml:"sweep_enabled"`
	// SweepInterval is the sweep cadence as a Go duration (e.g. "1m", "5m").
	SweepInterval string `yaml:"sweep_interval"`
}

// GetSweepInterval returns the auto-revoke sweep cadence, parsing SweepInterval
// as a Go duration; defaults to 1m when unset or unparseable (ADR-035).
func (c DynamicSecretsConfig) GetSweepInterval() time.Duration {
	if c.SweepInterval != "" {
		if d, err := time.ParseDuration(c.SweepInterval); err == nil && d > 0 {
			return d
		}
	}
	return 1 * time.Minute
}

// GetInterval returns the purge run interval, parsing Schedule as a Go duration
// (e.g. "24h", "6h"); defaults to 24h when unset or unparseable (ADR-032).
func (c PurgeConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
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
