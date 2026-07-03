package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	// ExpiryReminders configures the opt-in background scheduler that notifies project
	// admins of secrets that have expired or are approaching their expiration.
	ExpiryReminders ExpiryRemindersConfig `yaml:"expiry_reminders"`
	// CertificateExpiry configures the opt-in background scan (ADR-055) that parses
	// certificate-typed secrets and notifies project admins of certificates expired or
	// expiring within the lead window (using the real cert notAfter).
	CertificateExpiry CertificateExpiryConfig `yaml:"certificate_expiry"`
	// AutoRotation configures the opt-in background scheduler that actually rotates
	// auto-rotate-enabled secrets overdue under a policy (ADR-046), regenerating their
	// value. Distinct from rotation_reminders, which only notifies.
	AutoRotation AutoRotationConfig `yaml:"auto_rotation"`
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
	// ComplianceDigest configures the opt-in scheduler that periodically broadcasts a
	// posture + control-matrix summary to the configured notification channels.
	ComplianceDigest ComplianceDigestConfig `yaml:"compliance_digest"`
	// SCIM configures the SCIM 2.0 provisioning endpoints (RFC 7644) used by an IdP
	// to provision/deprovision users. Disabled (zero value) = /scim/v2 is not served.
	SCIM SCIMConfig `yaml:"scim"`
	// SSO configures human single-sign-on login via OIDC (authorization-code flow):
	// users sign in through their IdP and Keyorix mints a session. Disabled (zero
	// value) = the /auth/sso endpoints are not served.
	SSO SSOConfig `yaml:"sso"`
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

	// SecretValuePolicy is an optional quality gate on secret VALUES (reject weak/
	// placeholder values at create/rotate). Disabled (zero value) by default.
	SecretValuePolicy SecretValuePolicyConfig `yaml:"secret_value_policy"`

	// SecretNamePolicy is an optional naming convention on secret NAMES (regex /
	// max-length, enforced at create). Disabled (zero value) by default.
	SecretNamePolicy SecretNamePolicyConfig `yaml:"secret_name_policy"`

	// PasswordPolicy is optional. When the block is absent (zero value), the
	// server keeps its conservative built-in defaults (see core.DefaultPasswordPolicy);
	// when present, the install's values fully replace them.
	PasswordPolicy PasswordPolicyConfig `yaml:"password_policy"`

	// Connect configures Keyorix Connect (ADR-043): read-through federation to
	// external secret stores. Disabled (zero value) = the /connect endpoints are not
	// served.
	Connect ConnectConfig `yaml:"connect"`

	// License configures offline commercial-license validation (ADR-065). Absent (zero
	// value) = no license installed → the community baseline (no commercial features).
	// Enforcement is fail-safe: a missing/expired/invalid license never denies access or
	// stops the server; it degrades to the baseline with an admin warning + audit event.
	License LicenseConfig `yaml:"license"`

	// LicenseExpiry configures the opt-in background reminder that notifies install-wide
	// admins when the offline license is approaching or past expiry (ADR-065 Phase 2c).
	LicenseExpiry LicenseExpiryConfig `yaml:"license_expiry"`
}

// LicenseConfig points at an installed offline license token and tunes its evaluation
// (ADR-065). All fields are optional; an empty Path means no license is installed.
type LicenseConfig struct {
	// Path is the file holding the license token (as written by `keyorix license install`).
	Path string `yaml:"path"`
	// DeploymentID, when set, is checked against a license bound to a deployment; a
	// mismatch degrades to the baseline (it never shuts the server down).
	DeploymentID string `yaml:"deployment_id"`
	// GraceHours is the post-expiry tolerance window during which features are retained
	// (with a loud warning) so a lapse doesn't instantly drop entitlement. Default 336 (14d).
	GraceHours int `yaml:"grace_hours"`
}

// LicenseGrace returns the configured post-expiry grace window, defaulting to 14 days.
func (c *Config) LicenseGrace() time.Duration {
	if c.License.GraceHours <= 0 {
		return 14 * 24 * time.Hour
	}
	return time.Duration(c.License.GraceHours) * time.Hour
}

// ConnectConfig configures read-through federation to external secret stores
// (ADR-043). Opt-in: with no connectors (or Enabled false) the /connect API is off.
type ConnectConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Connectors []ConnectorConfig `yaml:"connectors"`
}

// ConnectorConfig describes one external-store connector. Name is the API path key
// (unique); Type selects the backend ("aws-secrets-manager"); Region is the backend
// region where applicable. Credentials come from the backend's ambient identity
// chain, never from here.
type ConnectorConfig struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Region string `yaml:"region"`
	// Address is the backend base URL: the Vault server for type "vault"
	// (e.g. https://vault:8200), or the Key Vault URL for type "azure-key-vault"
	// (e.g. https://myvault.vault.azure.net/).
	Address string `yaml:"address"`
	// TokenEnv names the environment variable holding the backend token for type
	// "vault" (default "VAULT_TOKEN"). The token is read from the environment, never
	// from this file.
	TokenEnv string `yaml:"token_env"`
	// AllowedRefs, when non-empty, restricts which secret references this connector
	// may read: a requested ref must have one of these prefixes (a defense-in-depth
	// guardrail in Keyorix's layer, on top of the backend identity's IAM policy). An
	// empty list places no restriction here — the backend IAM scope is then the only
	// bound, so prefer setting both.
	AllowedRefs []string `yaml:"allowed_refs"`
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
	// MaxRequestBodyBytes caps each request body to mitigate memory-exhaustion DoS from
	// an oversized payload. 0 uses a generous default (10 MiB — well above any normal
	// JSON request); a negative value disables the cap (for endpoints that legitimately
	// accept very large bodies).
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes,omitempty"`
	// TrustedProxies is the set of reverse-proxy/load-balancer source addresses (CIDRs
	// or bare IPs) whose X-Forwarded-For / X-Real-IP header is honored when deriving the
	// client IP. When empty, those headers are IGNORED and the real TCP peer is used —
	// so a client cannot spoof its source IP (which would otherwise defeat the per-IP
	// login/MFA rate limiter) unless it actually connects from a trusted proxy. Set this
	// to your ingress/LB CIDR(s) when running behind a proxy. (HTTP only.)
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
	// Web dashboard specific settings (HTTP only)
	WebAssetsPath  string   `yaml:"web_assets_path,omitempty"`
	AllowedOrigins []string `yaml:"allowed_origins,omitempty"`
	Domain         string   `yaml:"domain,omitempty"`
}

// defaultMaxRequestBodyBytes is the request-body cap when none is configured.
const defaultMaxRequestBodyBytes = 10 << 20 // 10 MiB

// EffectiveMaxRequestBodyBytes returns the request-body cap to enforce: the configured
// value, or a 10 MiB default when unset (0). A negative value is returned as-is and
// disables the cap at the middleware.
func (s ServerInstanceConfig) EffectiveMaxRequestBodyBytes() int64 {
	if s.MaxRequestBodyBytes == 0 {
		return defaultMaxRequestBodyBytes
	}
	return s.MaxRequestBodyBytes
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
// "env" reads it from the EnvVar's value (hex or base64); "exec" runs ExecCommand
// and reads the KEK from its stdout; "shamir" reconstructs it from K-of-N Shamir
// shares (ShamirShareFiles / ShamirShareEnv); "tpm" seals it to the host TPM 2.0
// (TPMDevice, sealed blob at WrappedKeyPath); "aws-kms" / "gcp-kms" / "azure-kms"
// envelope-wrap the KEK with a cloud KMS/HSM key (ADR-041) and store the wrapped
// blob at WrappedKeyPath. file/env/exec suit a KEK injected by a sealed/SOPS secret,
// a CSI driver, or any external secret store; shamir splits it across custodians;
// tpm binds it to host hardware; the KMS providers keep the wrapping key in the cloud HSM.
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
	// KMSEncryptionContext binds the wrapped KEK to this install (aws-kms /gcp-kms):
	// it's passed as the AWS EncryptionContext / GCP AdditionalAuthenticatedData on
	// wrap+unwrap, so a different install sharing the same CMK cannot unwrap this
	// install's KEK. Set a value unique to the install, e.g. {keyorix-install: <id>}.
	// Empty = no binding (the prior behaviour). Not supported by azure-kms (RSA wrap
	// has no AAD). Existing wrapped blobs decrypt via a no-context fallback, so this
	// can be enabled on a running install (it binds on the next KEK re-wrap).
	KMSEncryptionContext map[string]string `yaml:"kms_encryption_context"`
	// ExecCommand is the argv for type "exec": the resolver command (argv[0] is the
	// binary, the rest are arguments) whose stdout supplies the KEK as raw 32 bytes
	// or a hex/base64 encoding thereof. Run directly without a shell. Lets a
	// deployment fetch the KEK from any external secret store (e.g.
	// ["op","read","op://vault/kek/value"], ["sops","-d","kek.enc"]).
	ExecCommand []string `yaml:"exec_command"`
	// ShamirShareFiles / ShamirShareEnv list the K-of-N Shamir shares for type
	// "shamir": the KEK is reconstructed by combining the shares read from these file
	// paths and/or env-var values (each a hex/base64 share from
	// `keyorix encryption shamir-split`). Provide at least the threshold many; no
	// single share reveals the KEK.
	ShamirShareFiles []string `yaml:"shamir_share_files"`
	ShamirShareEnv   []string `yaml:"shamir_share_env"`
	// TPMDevice is the TPM 2.0 device for type "tpm" (default /dev/tpmrm0). The KEK
	// is sealed to this TPM and the sealed blob stored at WrappedKeyPath.
	TPMDevice string `yaml:"tpm_device"`
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
	// LoginLockout configures per-account login lockout (brute-force protection):
	// after MaxAttempts failed password logins within Window, the account is locked
	// for an exponentially-backing-off cooldown. Distinct from (and complementary to)
	// the per-IP rate limiter, which a distributed/botnet guess against one account can
	// evade. It is ENABLED BY DEFAULT — a secrets-manager login must resist online
	// guessing out of the box. Set login_lockout.disabled to opt out.
	LoginLockout LoginLockoutConfig `yaml:"login_lockout"`
	// RequireTransportTLS, when true, refuses to start an enabled HTTP/gRPC listener
	// that has no TLS configured — failing closed so bearer tokens and secret values are
	// never served in cleartext. Default false (a TLS-terminating proxy in front is a
	// common, supported deployment), but when off the server logs a prominent warning if
	// it serves cleartext, so the exposure is never silent.
	RequireTransportTLS bool `yaml:"require_transport_tls"`
}

// parseDurationDefault parses a Go duration string, returning def when empty or
// unparseable / non-positive.
func parseDurationDefault(raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	return def
}

// LoginLockoutConfig configures per-account login lockout. Lockout is enabled by
// default; Disabled is the explicit opt-out. Enabled is retained for backward
// compatibility and is now redundant with the default-on behavior.
type LoginLockoutConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Disabled     bool   `yaml:"disabled"`      // explicit opt-out (lockout is on by default)
	MaxAttempts  int    `yaml:"max_attempts"`  // failures within the window before locking (default 5)
	Window       string `yaml:"window"`        // Go duration; consecutive-failure window (default 15m)
	BaseCooldown string `yaml:"base_cooldown"` // lock duration for the first lockout (default 1m)
	MaxCooldown  string `yaml:"max_cooldown"`  // cap for the exponential backoff (default 1h)
}

func (c LoginLockoutConfig) GetMaxAttempts() int {
	if c.MaxAttempts > 0 {
		return c.MaxAttempts
	}
	return 5
}

func (c LoginLockoutConfig) GetWindow() time.Duration {
	return parseDurationDefault(c.Window, 15*time.Minute)
}

func (c LoginLockoutConfig) GetBaseCooldown() time.Duration {
	return parseDurationDefault(c.BaseCooldown, time.Minute)
}

func (c LoginLockoutConfig) GetMaxCooldown() time.Duration {
	return parseDurationDefault(c.MaxCooldown, time.Hour)
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
	// CheckpointNotary anchors each written audit checkpoint to an external RFC 3161
	// timestamp authority for a forge-proof proof-of-existence (ADR-029). Opt-in.
	CheckpointNotary CheckpointNotaryConfig `yaml:"checkpoint_notary"`
}

// CheckpointNotaryConfig configures external-notary anchoring of audit checkpoints.
// type is currently always "rfc3161" (the default when enabled). URL is the TSA's
// timestamp-query endpoint; Timeout is a Go duration (default 15s).
type CheckpointNotaryConfig struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"` // "rfc3161" (default)
	URL     string `yaml:"url"`  // TSA query endpoint, e.g. https://freetsa.org/tsr
	Timeout string `yaml:"timeout"`
	// CACertPath is a PEM bundle of the TSA's trusted root/CA cert(s). REQUIRED to
	// verify a stored anchor's issuer — without it anchoring still records tokens,
	// but verification fails closed (an untrusted/self-signed issuer must not be
	// trusted, since the checkpoint-row writer is the actor the anchor defends
	// against).
	CACertPath string `yaml:"ca_cert_path"`
}

// GetTimeout returns the TSA round-trip timeout (default 15s when unset/unparseable).
func (c CheckpointNotaryConfig) GetTimeout() time.Duration {
	return parseDurationDefault(c.Timeout, 15*time.Second)
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
	// SpoolDir enables a durable on-disk backlog: events that can't be delivered
	// (full queue / retries exhausted) are persisted here and replayed until the SIEM
	// accepts them, so a sustained outage doesn't silently lose the off-box copy.
	// Empty = best-effort only.
	SpoolDir string `yaml:"spool_dir"`
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
	Enabled     bool                      `yaml:"enabled"`
	Schedule    string                    `yaml:"schedule"`
	OutputDir   string                    `yaml:"output_dir"`
	Webhook     EvidenceWebhookConfig     `yaml:"webhook"`
	ObjectStore EvidenceObjectStoreConfig `yaml:"object_store"`
}

// EvidenceObjectStoreConfig configures the off-box S3-compatible object-storage
// target: each run uploads the pack (and detached signature) to a bucket. Works with
// AWS S3 and S3-compatible stores (MinIO, Cloudflare R2, Backblaze B2, GCS interop)
// via a custom endpoint. Credentials resolve via the standard AWS credential chain
// (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars, shared config, or
// instance/workload identity) — never from Keyorix config.
type EvidenceObjectStoreConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Bucket       string `yaml:"bucket"`         // required when enabled
	Prefix       string `yaml:"prefix"`         // optional key prefix, e.g. "keyorix/evidence/"
	Region       string `yaml:"region"`         // bucket region
	Endpoint     string `yaml:"endpoint"`       // optional custom endpoint for S3-compatible stores
	UsePathStyle bool   `yaml:"use_path_style"` // path-style addressing (MinIO and some gateways)
	// LockMode opts into S3 Object Lock (WORM) on each uploaded object: "" (off),
	// "governance", or "compliance". The bucket must have Object Lock enabled.
	LockMode string `yaml:"lock_mode"`
	// LockRetainDays is the retention window in days; required (> 0) when LockMode set.
	LockRetainDays int `yaml:"lock_retain_days"`
	// LegalHold places an indefinite S3 Object Lock legal hold on each uploaded
	// object (no expiry; cleared only out-of-band). Independent of LockMode; the
	// bucket must have Object Lock enabled.
	LegalHold bool `yaml:"legal_hold"`
}

// EvidenceWebhookConfig configures the off-box webhook target: each run POSTs the
// evidence pack JSON to Endpoint, optionally bearer-authenticated.
type EvidenceWebhookConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Endpoint           string `yaml:"endpoint"`
	Token              string `yaml:"token"` // use KEYORIX_EVIDENCE_WEBHOOK_TOKEN env var instead
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	// AllowPrivateNetworkTarget opts the endpoint out of the SSRF guard — a
	// SEPARATE decision from InsecureSkipVerify; see evidencesink.WebhookConfig.
	AllowPrivateNetworkTarget bool `yaml:"allow_private_network_target"`
}

// GetToken returns the resolved webhook token, preferring the environment variable.
func (c *EvidenceWebhookConfig) GetToken() string {
	return resolveSecret("KEYORIX_EVIDENCE_WEBHOOK_TOKEN", c.Token)
}

// HasTarget reports whether at least one delivery target is configured.
func (c EvidenceDeliveryConfig) HasTarget() bool {
	return c.OutputDir != "" || c.Webhook.Enabled || c.ObjectStore.Enabled
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
	Slack   NotificationChatConfig    `yaml:"slack"`
	Teams   NotificationChatConfig    `yaml:"teams"`
}

// NotificationChatConfig configures a Slack or Teams channel: an incoming-webhook
// URL (which carries the platform's secret token, so prefer the env var).
type NotificationChatConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// GetWebhookURL returns the resolved Slack incoming-webhook URL.
func (c *NotificationsConfig) GetSlackWebhookURL() string {
	return resolveSecret("KEYORIX_NOTIFY_SLACK_WEBHOOK", c.Slack.WebhookURL)
}

// GetTeamsWebhookURL returns the resolved Teams incoming-webhook URL.
func (c *NotificationsConfig) GetTeamsWebhookURL() string {
	return resolveSecret("KEYORIX_NOTIFY_TEAMS_WEBHOOK", c.Teams.WebhookURL)
}

// ComplianceDigestConfig configures the scheduled compliance digest (ISO 27001 /
// SOC 2 continuous monitoring): a periodic posture + control-matrix summary
// broadcast to the configured notification channels. Opt-in (default off); requires
// at least one notification channel to have somewhere to deliver.
type ComplianceDigestConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// GetInterval returns the digest interval, parsing Schedule as a Go duration (e.g.
// "24h", "168h"); defaults to 24h when unset or unparseable.
func (c ComplianceDigestConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
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
	// AllowPrivateNetworkTarget opts the endpoint out of the SSRF guard — a
	// SEPARATE decision from InsecureSkipVerify; see notifychan.WebhookConfig.
	AllowPrivateNetworkTarget bool `yaml:"allow_private_network_target"`
	// SigningSecret HMAC-signs each payload (X-Keyorix-Signature) so the receiver can
	// verify authenticity. Use KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET instead of the file.
	SigningSecret string `yaml:"signing_secret"`
}

// GetToken returns the resolved webhook token, preferring the environment variable.
func (c *NotificationWebhookConfig) GetToken() string {
	return resolveSecret("KEYORIX_NOTIFY_WEBHOOK_TOKEN", c.Token)
}

// GetSigningSecret returns the resolved webhook signing secret, preferring the env var.
func (c *NotificationWebhookConfig) GetSigningSecret() string {
	return resolveSecret("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", c.SigningSecret)
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

// SSOConfig configures human OIDC single-sign-on. Opt-in (default off). Each
// provider is an OIDC IdP; users are matched to a Keyorix account by the IdP
// subject (against the SCIM externalId) and, failing that, by email.
type SSOConfig struct {
	Enabled   bool                `yaml:"enabled"`
	Providers []SSOProviderConfig `yaml:"providers"`
}

// SSOProviderConfig is one configured OIDC provider. Endpoints are discovered from
// the issuer's /.well-known/openid-configuration at startup, so only the issuer +
// client credentials + redirect URL are required.
type SSOProviderConfig struct {
	Name string `yaml:"name"` // operator label + URL slug (e.g. "okta")
	// Type is "oidc" (default) or "saml"; it selects which block below is used.
	Type string `yaml:"type"`
	// SAML config (when type=saml). OIDC fields below are ignored for SAML providers.
	SAML *SAMLProviderConfig `yaml:"saml"`

	Issuer       string   `yaml:"issuer"`        // OIDC issuer URL
	ClientID     string   `yaml:"client_id"`     // the OAuth client id registered at the IdP
	ClientSecret string   `yaml:"client_secret"` // prefer KEYORIX_SSO_<NAME>_CLIENT_SECRET
	RedirectURL  string   `yaml:"redirect_url"`  // must equal <public-host>/auth/sso/<name>/callback
	Scopes       []string `yaml:"scopes"`        // default [openid, profile, email]

	// AutoProvision JIT-creates a Keyorix account on a first SSO login whose verified
	// identity matches no existing user — so an IdP that isn't wired for SCIM push can
	// still onboard users on demand. Opt-in (default off): when false, an unknown
	// identity is refused, exactly as before.
	AutoProvision bool `yaml:"auto_provision"`
	// DefaultRole is the install-wide baseline role granted to a JIT-provisioned user
	// (default "system_viewer"). A misconfigured/unknown role grants nothing —
	// least-privilege on misconfiguration.
	DefaultRole string `yaml:"default_role"`

	// GroupSync reconciles the user's NATIVE group memberships from the IdP's groups
	// claim on each login (the IdP becomes the source of truth — membership is added
	// for asserted groups and removed for non-asserted ones). Opt-in (default off).
	// Only existing native groups (provisioned by SCIM or an admin) are touched; an
	// asserted group with no native counterpart is ignored. If the groups claim is
	// absent from the id_token, the sync is a no-op.
	GroupSync bool `yaml:"group_sync"`
	// GroupsClaim is the id_token claim carrying the group names (default "groups";
	// some IdPs use "roles").
	GroupsClaim string `yaml:"groups_claim"`
	// GroupRoleMap maps an IdP group-claim value to a Keyorix (system) role name. When
	// set, each login reconciles the user's grants of the MAPPED roles to their
	// asserted groups (the IdP drives those assignments); roles outside the map are
	// untouched. Uses groups_claim as the source. e.g. {keyorix-admins: system_admin}.
	GroupRoleMap map[string]string `yaml:"group_role_map"`
}

// GetClientSecret returns the resolved client secret, preferring the per-provider
// env var KEYORIX_SSO_<NAME>_CLIENT_SECRET (name upper-cased).
func (p *SSOProviderConfig) GetClientSecret() string {
	return resolveSecret("KEYORIX_SSO_"+strings.ToUpper(p.Name)+"_CLIENT_SECRET", p.ClientSecret)
}

// SAMLProviderConfig is one configured SAML 2.0 IdP (when the provider's type=saml).
// The IdP metadata supplies the entityID, SSO URL, and signing certificate; provide it
// inline (idp_metadata_xml) or as a file path (idp_metadata_file).
type SAMLProviderConfig struct {
	IDPMetadataXML  string `yaml:"idp_metadata_xml"`
	IDPMetadataFile string `yaml:"idp_metadata_file"`
	SPEntityID      string `yaml:"sp_entity_id"` // our SP entity ID (conventionally the metadata URL)
	ACSURL          string `yaml:"acs_url"`      // <public-host>/auth/saml/<name>/acs
	// AllowIDPInitiated permits responses with no InResponseTo (loses CSRF/replay
	// protection). Off by default — enable only for IdPs that require it.
	AllowIDPInitiated bool `yaml:"allow_idp_initiated"`
	// Attribute names to read from the assertion (empty → common Azure AD/ADFS defaults).
	EmailAttribute  string `yaml:"email_attribute"`
	NameAttribute   string `yaml:"name_attribute"`
	GroupsAttribute string `yaml:"groups_attribute"`
}

// RotationRemindersConfig configures the rotation-reminder scheduler: a background
// job that notifies project admins of secrets overdue/approaching their rotation
// deadline under an active rotation policy. Opt-in (default off).
type RotationRemindersConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

// ExpiryRemindersConfig configures the opt-in secret-expiry reminder scheduler.
type ExpiryRemindersConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	LeadDays int    `yaml:"lead_days"` // notify this many days before expiry (0 = default 14)
}

// CertificateExpiryConfig configures the opt-in certificate-expiry monitoring scan
// (ADR-055). It parses certificate-typed secrets and notifies project admins of certs
// expired or expiring within LeadDays (using the certificate's real notAfter).
type CertificateExpiryConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	LeadDays int    `yaml:"lead_days"` // notify this many days before notAfter (0 = default 30)
}

// GetInterval returns the certificate-expiry scan interval (Go duration, e.g. "24h");
// defaults to 24h when unset or unparseable.
func (c CertificateExpiryConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// LicenseExpiryConfig configures the opt-in background reminder that notifies install-wide
// admins when the offline commercial license (ADR-065) is within LeadDays of expiry or has
// expired. Disabled (zero value) = no reminder; the fail-safe gate and status endpoint are
// unaffected.
type LicenseExpiryConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	LeadDays int    `yaml:"lead_days"` // notify this many days before expiry (0 = default 30)
}

// GetInterval returns the license-expiry reminder interval (Go duration, e.g. "24h");
// defaults to 24h when unset or unparseable.
func (c LicenseExpiryConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// GetInterval returns the expiry-reminder run interval (Go duration, e.g. "24h");
// defaults to 24h when unset or unparseable.
func (c ExpiryRemindersConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// AutoRotationConfig configures the opt-in automated-rotation scheduler (ADR-046) and
// the backend rotation executors it can drive (ADR-047).
type AutoRotationConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
	// Backends are the upstream rotation executors (ADR-047) — e.g. a PostgreSQL admin
	// connection that can ALTER ROLE. Each backend's admin DSN is read from its named
	// environment variable, never from this file.
	Backends []RotationBackendConfig `yaml:"backends"`
}

// RotationBackendConfig describes one upstream rotation executor (ADR-047). Name is the
// registry key; Type selects the backend ("postgresql"); DSNEnv names the environment
// variable holding the admin connection string. AllowedRefs optionally restricts which
// references (e.g. role names) the backend may rotate, by prefix.
type RotationBackendConfig struct {
	Name        string   `yaml:"name"`
	Type        string   `yaml:"type"`
	DSNEnv      string   `yaml:"dsn_env"`
	Region      string   `yaml:"region"` // for cloud backends (e.g. aws-iam); creds from the ambient chain
	AllowedRefs []string `yaml:"allowed_refs"`
}

// GetDSN returns the backend admin DSN from its configured environment variable
// (empty when DSNEnv is unset or the variable is empty — the credential never lives in
// the config file).
func (c RotationBackendConfig) GetDSN() string {
	if c.DSNEnv == "" {
		return ""
	}
	return os.Getenv(c.DSNEnv)
}

// GetInterval returns the auto-rotation run interval (Go duration, e.g. "1h");
// defaults to 1h when unset or unparseable.
func (c AutoRotationConfig) GetInterval() time.Duration {
	if c.Schedule != "" {
		if d, err := time.ParseDuration(c.Schedule); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
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
// job that signs the audit hash-chain head (ADR-029) so tampering, tail-truncation,
// and genesis re-seed are detectable. This is the audit trail's forgery-resistance
// layer — the per-row hash chain alone is unkeyed and a database-write attacker can
// recompute it, so without signed checkpoints the trail is only tamper-EVIDENT, not
// forgery-resistant. It is therefore enabled BY DEFAULT whenever a signing key is
// available (encryption configured). Set Disabled to opt out (a loud warning is
// logged). Enabled is retained for backward compatibility and is now redundant with
// the default-on behavior.
type AuditCheckpointsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Disabled bool   `yaml:"disabled"`
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
	// ML configures the optional Isolation Forest detection pass (ADR-050). It is
	// independent of Enabled (which gates alert *push*): ML.Enabled gates whether the
	// detection scan additionally scores accesses for multivariate outliers.
	ML AnomalyMLConfig `yaml:"ml"`
	// BusinessHours configures the timezone and band the off_hours rule uses. Unset =
	// the legacy UTC 22:00–06:00 default.
	BusinessHours AnomalyBusinessHoursConfig `yaml:"business_hours"`
}

// AnomalyBusinessHoursConfig defines when secret access counts as "off hours" for the
// off_hours detection rule. The hours are evaluated in Timezone, and the off-hours band
// is [OffHoursStart, OffHoursEnd) wrapping midnight (e.g. 22→6). All fields are optional
// and default to the legacy behaviour: UTC, 22:00–06:00. Setting Timezone alone is the
// common case — it stops flagging local business-hours access as off-hours on non-UTC
// deployments (and vice versa).
type AnomalyBusinessHoursConfig struct {
	Timezone      string `yaml:"timezone"`        // IANA name (e.g. "America/New_York"); "" = UTC
	OffHoursStart int    `yaml:"off_hours_start"` // off-hours band start hour [0,23]; default 22
	OffHoursEnd   int    `yaml:"off_hours_end"`   // off-hours band end hour [0,23]; default 6
}

// AnomalyMLConfig configures the Isolation Forest anomaly-detection pass (ADR-050).
// Opt-in (default off). When enabled, each detection scan trains a per-secret forest
// on the secret's 30-day access baseline and flags recent accesses whose joint
// feature vector (hour, IP novelty, user novelty) is a multivariate outlier — the
// single-signal statistical rules miss these. Metadata only; no secret values.
type AnomalyMLConfig struct {
	Enabled    bool    `yaml:"enabled"`
	Threshold  float64 `yaml:"threshold"`   // anomaly-score cutoff (0.5,1.0); default 0.60
	NumTrees   int     `yaml:"num_trees"`   // ensemble size; default 100
	SampleSize int     `yaml:"sample_size"` // per-tree subsample (psi); default 256
	Seed       int64   `yaml:"seed"`        // RNG seed for reproducible scoring; default 1
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

// ResolvedPath returns the config file path Load(path) would read, without
// actually reading it: an explicit non-empty path wins, otherwise
// KEYORIX_CONFIG_PATH, otherwise "keyorix.yaml" in the application root.
// Callers that need to know exactly which file was (or will be) loaded — e.g.
// startup validation checking that file's permissions — should resolve
// through this helper rather than re-deriving the fallback chain themselves.
func ResolvedPath(path string) string {
	if path == "" {
		path = resolveSecret("KEYORIX_CONFIG_PATH", "")
	}
	if path == "" {
		path = filepath.Join(appRootDir, "keyorix.yaml")
	}
	return path
}

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
	path = ResolvedPath(path)

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

	if err := validateAllowedOrigins(c.Server.HTTP.AllowedOrigins); err != nil {
		return err
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
		// gRPC has no ACME integration: auto_cert would build a TLS config with no
		// certificate, so every handshake fails (a silent outage). Reject it explicitly
		// rather than start a server that cannot serve.
		if c.Server.GRPC.TLS.AutoCert {
			return fmt.Errorf("gRPC TLS auto_cert is not supported; provide cert_file and key_file")
		}
		if c.Server.GRPC.TLS.CertFile == "" || c.Server.GRPC.TLS.KeyFile == "" {
			return fmt.Errorf("gRPC TLS is enabled but cert_file or key_file is missing")
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

// validateAllowedOrigins rejects a misconfigured CORS allowlist (server.http.
// allowed_origins) at startup rather than letting it sit silently until it's
// proven wrong in the field. A bare "*" — which matches every origin — must not
// be configurable here: the caller must list explicit origins. Every entry must
// also be a well-formed origin: an http(s) scheme, a host, and nothing else (no
// path, query, fragment, userinfo, or trailing slash) — the exact shape
// Access-Control-Allow-Origin expects an Origin header to have.
func validateAllowedOrigins(origins []string) error {
	for _, o := range origins {
		if o == "*" {
			return fmt.Errorf("server.http.allowed_origins must not contain \"*\" — list explicit origins (e.g. https://app.example.com); a wildcard origin defeats the CORS allowlist")
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return fmt.Errorf("server.http.allowed_origins entry %q is not a valid origin (expected scheme://host[:port], e.g. https://app.example.com)", o)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("server.http.allowed_origins entry %q must use http or https", o)
		}
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

	if err := securefiles.SecureWriteFileSync(appRootDir, path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %q: %w", path, err)
	}

	return nil
}

// SecretValuePolicyConfig configures the opt-in secret-value quality gate
// (core.SecretValuePolicy). Disabled unless Enabled is true.
type SecretValuePolicyConfig struct {
	Enabled       bool     `yaml:"enabled"`
	MinLength     int      `yaml:"min_length"`     // reject values shorter than this (0 = no minimum)
	RejectCommon  bool     `yaml:"reject_common"`  // reject a built-in denylist of weak/placeholder values
	ExtraDenylist []string `yaml:"extra_denylist"` // additional rejected values (case-insensitive)
}

// SecretNamePolicyConfig configures the opt-in secret naming convention
// (core.SecretNamePolicy). Disabled unless Enabled is true.
type SecretNamePolicyConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Pattern   string `yaml:"pattern"`    // RE2 regex the name must match (anchor with ^…$); empty = no regex check
	MaxLength int    `yaml:"max_length"` // reject names longer than this (0 = no maximum)
}
