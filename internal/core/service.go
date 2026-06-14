package core

import (
	"context"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// KeyorixCore represents the core business logic layer.
// It orchestrates all business operations while remaining transport-agnostic.
// Methods are organised into domain files:
//   - secrets.go       — Secret CRUD + rotation
//   - versions.go      — Secret version management + value retrieval
//   - permissions.go   — Permission enforcement and checking
//   - users.go         — User and group management
//   - rbac.go          — Role and permission assignment
//   - auth.go          — Session lifecycle + system initialisation
//   - dashboard.go     — Dashboard stats and activity feed
//   - catalog.go       — Project / environment passthrough
type KeyorixCore struct {
	storage    storage.Storage
	encryption *encryption.SecretEncryption
	// authEncryptor reversibly encrypts auth secrets that cannot be hashed (the
	// TOTP MFA shared secret). nil or disabled = passthrough (store plaintext),
	// consistent with the rest of the product when encryption is off. Wired from
	// the initialised encryption.Service at server startup via SetAuthEncryptor.
	authEncryptor *encryption.Service
	// dynamicEngineFactory resolves a dynamic-secrets credential engine by backend
	// type (ADR-035). nil = the real dynamic.New; overridable in tests with a fake.
	dynamicEngineFactory func(string) (dynamic.CredentialEngine, error)
	// dynamicSweepEnabled mirrors config dynamic_secrets.sweep_enabled. Backends
	// without DB-level expiry (MySQL/MongoDB) rely entirely on the sweeper to
	// enforce a lease's TTL, so IssueLease refuses to mint from them when it is off
	// (the credential would otherwise never expire). Set via SetDynamicSweepEnabled.
	dynamicSweepEnabled bool
	// webauthnRP is the WebAuthn relying party (ADR-036); nil = WebAuthn disabled.
	// Set from config at startup via SetWebAuthn.
	webauthnRP     *webauthn.WebAuthn
	now            func() time.Time // For testability
	passwordPolicy PasswordPolicy
	auditForwarder AuditForwarder
	// breakGlassPolicy configures self-service emergency access; zero value =
	// disabled. Set from config at startup via SetBreakGlassPolicy.
	breakGlassPolicy BreakGlassPolicy
	// dualControlRequiredApprovals is the N-of-M approval threshold for access
	// requests (A.5.3); 0/1 = single approval (disabled). Set via SetDualControlPolicy.
	dualControlRequiredApprovals int
	// retentionPolicy holds the configured per-record-type data-retention windows
	// (ISO A.5.33) so the compliance posture can report them; zero value = no
	// retention configured. Set from config at startup via SetRetentionPolicy.
	retentionPolicy RetentionPolicy
	// recertCadenceDays is the access-recertification review interval (ISO A.5.18),
	// in days; 0 = the default cadence. Used by the posture to flag overdue projects.
	// Set from config at startup via SetRecertificationCadence.
	recertCadenceDays int
	// oidcVerifier verifies federated machine-identity JWTs (ADR-031); nil = OIDC
	// auth disabled. Set from config via SetOIDCVerifier.
	oidcVerifier *OIDCVerifier
	// membershipValidationMode is the ADR-022 install-level onboarding mode;
	// "" = allowlist default. Set via SetMembershipValidationMode.
	membershipValidationMode string
	// setupTokenTTL is the lifetime of a credential-delivery setup token (ADR-028);
	// 0 = DefaultSetupTokenTTL. Set from config via SetSetupTokenTTL.
	setupTokenTTL time.Duration
	// sessionAccessTTL is the access-token lifetime; refresh extends by this much.
	// 0 = defaultSessionAccessTTL (24h). Set from config via SetSessionTTLs.
	sessionAccessTTL time.Duration
	// sessionAbsoluteTTL caps total session lifetime from login — refresh never
	// extends past it. 0 = no ceiling (refreshable indefinitely). Via SetSessionTTLs.
	sessionAbsoluteTTL time.Duration
	// credentialDelivery transports setup links (ADR-028). nil = out-of-band: the
	// link is returned to the caller. Set from config via SetCredentialDelivery.
	credentialDelivery delivery.CredentialDelivery
	// setupBaseURL is the absolute base (e.g. https://keyorix.acme.internal) used to
	// build setup links. Required to mint a link; a relative link is a misconfig.
	setupBaseURL string
	// auditCkptKey signs/verifies audit-chain checkpoints (ADR-029): a DEK-derived
	// HMAC key the database/DBA does not hold. nil = signed checkpoints unavailable
	// (encryption disabled), in which case WriteAuditCheckpoint is a no-op and
	// VerifyAuditChain runs without on-box checkpoint enforcement. Set at startup
	// via SetAuditCheckpointKey. auditCkptKeyVersion records which DEK version it
	// was derived from, so a checkpoint signed under a superseded key is not
	// enforced after a DEK rotation.
	auditCkptKey        []byte
	auditCkptKeyVersion string
}

// AuditForwarder ships persisted audit events to an external sink (e.g. a SIEM).
// Implementations must be non-blocking and best-effort: Forward is called on the
// audit write path and must never block or fail the audited operation. Defined
// here (not in the siem package) so core has no dependency on the forwarder impl.
type AuditForwarder interface {
	Forward(event *models.AuditEvent)
}

// SetAuditForwarder wires an audit forwarder. The server calls this at startup
// when the install configures an audit.siem block. nil disables forwarding.
func (c *KeyorixCore) SetAuditForwarder(f AuditForwarder) {
	c.auditForwarder = f
}

// emitAudit persists an audit event and forwards it to the configured sink.
// All core audit writers funnel through here so SIEM forwarding is uniform.
func (c *KeyorixCore) emitAudit(ctx context.Context, event *models.AuditEvent) {
	_ = c.storage.LogAuditEvent(ctx, event)
	if c.auditForwarder != nil {
		c.auditForwarder.Forward(event)
	}
}

// NewKeyorixCore creates a new instance of the core business logic.
func NewKeyorixCore(storage storage.Storage) *KeyorixCore {
	return &KeyorixCore{
		storage:        storage,
		encryption:     nil,
		now:            time.Now,
		passwordPolicy: DefaultPasswordPolicy(),
	}
}

// NewKeyorixCoreWithEncryption creates a new instance with encryption support.
func NewKeyorixCoreWithEncryption(storage storage.Storage, enc *encryption.SecretEncryption) *KeyorixCore {
	return &KeyorixCore{
		storage:        storage,
		encryption:     enc,
		now:            time.Now,
		passwordPolicy: DefaultPasswordPolicy(),
	}
}

// SetAuthEncryptor wires the encryption service used to protect reversibly-
// encrypted auth secrets (the TOTP MFA secret). The server calls this at startup
// when encryption is enabled. nil/disabled = passthrough.
func (c *KeyorixCore) SetAuthEncryptor(s *encryption.Service) {
	c.authEncryptor = s
}

// encryptAuthSecret reversibly encrypts plain; passthrough when encryption is off.
func (c *KeyorixCore) encryptAuthSecret(plain string) (ct, meta []byte, err error) {
	if c.authEncryptor == nil || !c.authEncryptor.IsEnabled() {
		return []byte(plain), nil, nil
	}
	return c.authEncryptor.EncryptSecret([]byte(plain))
}

// decryptAuthSecret reverses encryptAuthSecret; passthrough when encryption is off.
func (c *KeyorixCore) decryptAuthSecret(ct, _ []byte) (string, error) {
	if c.authEncryptor == nil || !c.authEncryptor.IsEnabled() {
		return string(ct), nil
	}
	plain, err := c.authEncryptor.DecryptSecret(ct)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// SetDynamicEngineFactory overrides the dynamic-secrets engine factory (tests
// inject a fake engine).
func (c *KeyorixCore) SetDynamicEngineFactory(f func(string) (dynamic.CredentialEngine, error)) {
	c.dynamicEngineFactory = f
}

// SetDynamicSweepEnabled records whether the auto-revoke sweeper is running
// (config dynamic_secrets.sweep_enabled). Wired at startup so IssueLease can refuse
// to mint a credential from a backend whose TTL only the sweeper would enforce.
func (c *KeyorixCore) SetDynamicSweepEnabled(enabled bool) {
	c.dynamicSweepEnabled = enabled
}

// dynamicEngine resolves an engine for a backend type via the factory (or the
// real dynamic.New when none is set).
func (c *KeyorixCore) dynamicEngine(backendType string) (dynamic.CredentialEngine, error) {
	if c.dynamicEngineFactory != nil {
		return c.dynamicEngineFactory(backendType)
	}
	return dynamic.New(backendType)
}

// SetWebAuthn wires the WebAuthn relying party (ADR-036). The server calls this
// at startup when the install configures a webauthn block. nil disables passkeys.
func (c *KeyorixCore) SetWebAuthn(rp *webauthn.WebAuthn) {
	c.webauthnRP = rp
}

// WebAuthnEnabled reports whether passkey support is configured on this server.
func (c *KeyorixCore) WebAuthnEnabled() bool { return c.webauthnRP != nil }

// SetPasswordPolicy overrides the password policy (which defaults to
// DefaultPasswordPolicy). The server calls this at startup when the install
// configures a password_policy block.
func (c *KeyorixCore) SetPasswordPolicy(p PasswordPolicy) {
	c.passwordPolicy = p
}

// SetSetupTokenTTL overrides the setup-token lifetime (ADR-028). The server calls
// this at startup from credential_delivery.setup_token_ttl. A non-positive value
// falls back to DefaultSetupTokenTTL.
func (c *KeyorixCore) SetSetupTokenTTL(ttl time.Duration) {
	c.setupTokenTTL = ttl
}

// SetSessionTTLs configures the short-lived-token lifetimes. access is the
// access-token window (refresh extends by this); absolute is the hard ceiling on
// total session lifetime (0 = no ceiling). The server calls this at startup from
// the session config block. A non-positive access falls back to the 24h default.
func (c *KeyorixCore) SetSessionTTLs(access, absolute time.Duration) {
	c.sessionAccessTTL = access
	c.sessionAbsoluteTTL = absolute
}

// Storage returns the underlying storage interface (used by ancillary services such as AnomalyDetector).
func (c *KeyorixCore) Storage() storage.Storage {
	return c.storage
}

// ListActiveSecrets returns all secrets for anomaly detection. Returns empty slice on error.
func (c *KeyorixCore) ListActiveSecrets(ctx context.Context) []models.SecretNode {
	secrets, _, err := c.ListSecrets(ctx, nil)
	if err != nil || secrets == nil {
		return nil
	}
	result := make([]models.SecretNode, 0, len(secrets))
	for _, s := range secrets {
		if s != nil {
			result = append(result, *s)
		}
	}
	return result
}

// HealthCheck checks the health of the core service and its dependencies.
func (c *KeyorixCore) HealthCheck(ctx context.Context) error {
	if c.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	return c.storage.HealthCheck(ctx)
}

// ResolveUsernames maps UserID → username for a slice of audit events.
// Nil UserIDs (system events) map to key 0 → "system".
func (c *KeyorixCore) ResolveUsernames(ctx context.Context, events []*models.AuditEvent) map[uint]string {
	seen := map[uint]bool{}
	for _, e := range events {
		if e.UserID != nil {
			seen[*e.UserID] = true
		}
		// Resolve impersonation actors too, so audit rows can show a human-readable
		// name on every impersonated event rather than an opaque ID.
		if e.ImpersonatedBy != nil {
			seen[*e.ImpersonatedBy] = true
		}
		if e.ActingAs != nil {
			seen[*e.ActingAs] = true
		}
	}
	byID := map[uint]string{0: "system"}
	for uid := range seen {
		if user, err := c.storage.GetUser(ctx, uid); err == nil && user != nil {
			byID[uid] = user.Username
		} else {
			byID[uid] = "unknown"
		}
	}
	return byID
}
