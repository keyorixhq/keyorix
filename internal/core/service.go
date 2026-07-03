package core

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/notary"
	"github.com/keyorixhq/keyorix/internal/rotation"
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
	// bootstrapToken gates POST /system/init (BootstrapSystem). The first-boot admin
	// claim is otherwise unauthenticated, so a fresh, network-reachable instance could
	// be seized by whoever calls /system/init first. The server sets this at startup
	// (from KEYORIX_BOOTSTRAP_TOKEN, or a random value logged for the operator while the
	// system is uninitialised); init refuses unless the caller presents a matching token.
	bootstrapToken    string
	secretValuePolicy SecretValuePolicy  // optional quality gate on secret values (off by default)
	secretNamePolicy  SecretNamePolicy   // optional naming convention for secrets (off by default)
	secretNameRe      *regexp.Regexp     // compiled secretNamePolicy.Pattern (nil = no regex check)
	loginLockout      LoginLockoutPolicy // per-account login lockout (disabled by default)
	// loginFailureMu serializes the per-account failed-login read-increment-write in
	// recordFailedLogin so concurrent failures can't lose an increment. Combined with
	// the row lock LockUserForUpdate takes on Postgres, the lockout counter stays
	// correct across replicas. Zero value is ready to use. See login_lockout.go.
	loginFailureMu sync.Mutex
	// globalAdminGuardMu serializes RemoveUserRole's last-global-admin check and the
	// removal it guards (guardLastGlobalAdmin) into one atomic unit, so two admins
	// concurrently removing each other's role assignment cannot both observe
	// "another admin still exists" before either write lands (#340). Combined with
	// the row lock ListGlobalAdminAssignmentsForUpdate takes on Postgres, the guard
	// stays correct across HA replicas too. Zero value is ready to use. See
	// rbac_management.go.
	globalAdminGuardMu sync.Mutex
	// setupResendMu serializes the count-then-issue window of the setup-link resend
	// throttle (checkResendThrottle + IssueSetupToken) so two concurrent resends for
	// the same (purpose, email) cannot both clear the per-day cap / min-interval
	// before either token row exists. Held only across the throttle check and the
	// token write — link delivery (SMTP) runs after release, so a slow send never
	// serializes every other resend. Zero value is ready to use. See setup_delivery.go.
	setupResendMu sync.Mutex
	// webauthnCredentialMu serializes persistUpdatedCredential's per-credential
	// read-validate-write of the advanced WebAuthn signature counter, so two
	// concurrent logins for the same (cloned) authenticator cannot race and let a
	// stale, lower counter clobber an already-persisted higher one. Combined with the
	// row lock LockWebAuthnCredentialForUpdate takes on Postgres, the counter stays
	// monotonic across replicas too. Zero value is ready to use. See webauthn.go.
	webauthnCredentialMu sync.Mutex
	// bootstrapMu serializes BootstrapSystem's "is this a fresh install" (total==0)
	// check through the admin CreateUser call, so two concurrent callers who both
	// already hold the valid bootstrap token (#339) — e.g. different usernames —
	// cannot both observe an empty user table and each create a "first admin". Zero
	// value is ready to use. See auth_bootstrap.go.
	bootstrapMu sync.Mutex
	// accountStateMu serializes the account_state/is_active read-modify-write shared
	// by setAccountState (SuspendUser/ReactivateUser/RequirePasswordReset) and
	// UpdateSCIMUser (#344): without it, an admin's incident-response SuspendUser and a
	// routine SCIM/IdP resync for the same user can each GetUser before the other's
	// Save commits, and whichever full-row Save lands last silently clobbers the
	// other's change — e.g. a suspend committed, then a SCIM sync's stale in-memory
	// "active" copy overwrites it back to active with no error to either caller.
	// Combined with the row lock LockUserForUpdate takes on Postgres, this holds
	// across replicas too. Zero value is ready to use. See account_state.go / scim.go.
	accountStateMu sync.Mutex
	auditForwarder AuditForwarder
	// auditStream is the in-process pub/sub broker that wakes live audit tails
	// (gRPC StreamAuditLogs) the instant an event is written, replacing fixed-interval
	// DB polling. Always non-nil (set in the constructors).
	auditStream *auditBroker
	// notificationSink fans each in-app notification out to an external channel
	// (email/webhook). nil = in-app only. Set from config via SetNotificationSink.
	notificationSink NotificationSink
	// connectManager proxies read-through federation to external secret stores
	// (ADR-043). nil = Keyorix Connect disabled. Set via SetConnectManager.
	connectManager *connect.Manager
	// rotationManager holds the backend rotation executors (ADR-047) that apply a new
	// credential to an upstream system during rotation. nil = no backends configured.
	rotationManager *rotation.Manager
	// evidenceForwarder ships the scheduled compliance-evidence pack to an off-box
	// target (webhook). nil = local-file only. Set via SetEvidenceForwarder.
	evidenceForwarder EvidenceForwarder
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
	// ssoProviders are the configured human-SSO OIDC providers (keyed by name);
	// ssoJWKS verifies their id_tokens. Empty = SSO disabled. Set via SetSSOProviders.
	ssoProviders map[string]*SSOProvider
	ssoJWKS      JWKSResolver
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
	// tokenCacheInvalidator evicts a bearer token from the HTTP auth cache by its hash.
	// Wired at startup (SetTokenCacheInvalidator) to the middleware cache; nil in tests/
	// remote mode (the cache lives in the HTTP server). Lets core paths that revoke a
	// token (e.g. revoking PATs on a password change) take effect immediately rather than
	// after the positive-cache TTL. core cannot import the middleware directly (cycle).
	tokenCacheInvalidator func(hash string)
	// auditMaxCertified is an in-memory monotonic high-water mark of the greatest
	// chained-events count this process has ever certified or verified. It backstops
	// the persistent signed high-water (SystemMetadata) against an online attacker who
	// deletes the high-water row mid-run: the chain can never be observed to regress
	// below a length we already saw this lifetime. Guarded by auditWatermarkMu.
	auditMaxCertified int64
	auditWatermarkMu  sync.Mutex
	// checkpointNotary, when set, anchors each freshly-written audit checkpoint to
	// an external authority (RFC 3161 TSA) for a forge-proof proof-of-existence
	// (ADR-029). nil = no external anchoring. Set at startup via SetCheckpointNotary.
	checkpointNotary notary.Notary
	// checkpointAnchorRoots is the trusted TSA root pool used to VERIFY stored
	// checkpoint anchors (the issuer trust anchor). nil = anchors cannot be verified
	// (fail closed). Set at startup via SetCheckpointAnchorRoots.
	checkpointAnchorRoots *x509.CertPool
	// evidenceSignKey / evidenceSignKeyVersion sign and verify exported compliance-
	// evidence packs (HMAC, DEK-derived, domain-separated from the checkpoint key).
	// nil = signing unavailable (encryption disabled). Set via SetEvidenceSignKey.
	evidenceSignKey        []byte
	evidenceSignKeyVersion string
	// licenseGate evaluates the installed offline commercial license (ADR-065). nil =
	// no license configured → the community baseline. Evaluation is fail-safe (it never
	// denies access or stops the server) and fresh on every call. Set via SetLicenseGate.
	licenseGate *license.Gate
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

// SetLicenseGate wires the offline-license feature gate built at startup from the
// installed token. nil = no license (community baseline). Safe to leave unset.
func (c *KeyorixCore) SetLicenseGate(g *license.Gate) {
	c.licenseGate = g
}

// LicenseStatus returns the freshly-evaluated license entitlement. It never errors; an
// unset gate or a degraded license reports the community baseline with a reason. The gate
// is nil-safe, so this is valid even when no license is configured.
func (c *KeyorixCore) LicenseStatus() license.Status {
	return c.licenseGate.Status()
}

// HasLicensedFeature reports whether commercial feature f is currently granted. This is the
// single gate a future commercial-only capability checks; it is false under any degraded,
// expired, missing, or unconfigured license.
func (c *KeyorixCore) HasLicensedFeature(f string) bool {
	return c.licenseGate.HasFeature(f)
}

// AuditLicenseState records the current license state as an audit event. The server calls
// it once at startup so the evaluated entitlement (and any degrade reason) is on the record.
func (c *KeyorixCore) AuditLicenseState(ctx context.Context) {
	st := c.LicenseStatus()
	desc := "License evaluated at startup: " + string(st.State)
	if st.Reason != "" {
		desc += " — " + st.Reason
	}
	ok := true
	c.emitAudit(ctx, &models.AuditEvent{
		EventType:   "license.evaluated",
		Description: desc,
		Success:     &ok,
		ActorType:   "system",
		EventTime:   time.Now(),
	})
}

// Audit field length caps (#381). Neither models.AuditEvent.Description nor .Diff
// carries a DB-level size limit, and secret/project/role names feeding into a
// Description have no length cap unless an operator opts into secret_name_policy
// (off by default) — so an attacker-chosen name could otherwise blow up every
// audit row that mentions it, and (since the audit-chain writer is a single
// process-wide serialized writer) degrade audit throughput for every OTHER write
// in the system. These ceilings comfortably fit any Description/Diff this
// codebase's own call sites actually generate (short templated sentences and
// small structured before/after JSON), so legitimate audit content is never
// affected.
const (
	auditDescriptionMaxLen = 4096 // ~4 KiB
	auditDiffMaxLen        = 8192 // ~8 KiB
)

// auditTruncatedMarker is appended to a field truncated by truncateAuditField.
const auditTruncatedMarker = "...[truncated]"

// truncateAuditField caps s at maxLen bytes, appending auditTruncatedMarker when
// truncation occurs. Audit writes must never fail (or reject) the underlying
// business operation just because a caller-supplied description/diff got too
// long, so this truncates rather than erroring. The cut point is walked back to
// a valid UTF-8 boundary so truncation never produces an invalid string.
func truncateAuditField(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	cut := maxLen
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	return s[:cut] + auditTruncatedMarker
}

// emitAudit persists an audit event and forwards it to the configured sink.
// All core audit writers funnel through here so SIEM forwarding is uniform —
// which also makes it the single choke point to cap Description/Diff length
// (#381), independent of which helper (writeAuditEvent*, writeImpersonationEvent,
// AuditLicenseState, ...) produced the event.
func (c *KeyorixCore) emitAudit(ctx context.Context, event *models.AuditEvent) {
	event.Description = truncateAuditField(event.Description, auditDescriptionMaxLen)
	event.Diff = truncateAuditField(event.Diff, auditDiffMaxLen)
	if err := c.storage.LogAuditEvent(ctx, event); err != nil {
		// A failed chain-write is an audit gap that VerifyAuditChain cannot detect — a
		// never-written event leaves no hole. Surface it loudly instead of swallowing,
		// and do NOT forward a phantom event (ID 0, no chain position) to the SIEM: the
		// off-box mirror must reflect the durable chain, not events that never landed.
		log.Printf("SECURITY: failed to persist audit event %q (success=%v): %v", event.EventType, event.Success, err)
		return
	}
	if c.auditForwarder != nil {
		c.auditForwarder.Forward(event)
	}
	// Wake any live audit tails (gRPC StreamAuditLogs). Non-blocking; subscribers
	// then read the new rows from storage with their cursor (DB stays authoritative).
	if c.auditStream != nil {
		c.auditStream.signal()
	}
}

// NotificationEvent is one user-facing notification handed to an external sink for
// out-of-band delivery (email/webhook) alongside the persisted in-app row.
type NotificationEvent struct {
	UserID    uint   `json:"user_id"`
	Email     string `json:"email,omitempty"` // recipient's address, resolved best-effort
	Type      string `json:"type"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	ProjectID *uint  `json:"project_id,omitempty"`
	Link      string `json:"link,omitempty"`
}

// NotificationSink delivers a NotificationEvent to an external channel (email,
// webhook, …). Like AuditForwarder, implementations MUST be non-blocking and
// best-effort: Deliver runs on the notification path and must never block or fail
// the triggering operation. Defined here (not in the channel package) so core has
// no dependency on the channel implementations.
type NotificationSink interface {
	Deliver(ev NotificationEvent)
}

// SetNotificationSink wires an external notification sink. The server calls this at
// startup when the install configures a notifications channel. nil = in-app only.
func (c *KeyorixCore) SetNotificationSink(s NotificationSink) {
	c.notificationSink = s
}

// NewKeyorixCore creates a new instance of the core business logic.
func NewKeyorixCore(storage storage.Storage) *KeyorixCore {
	return &KeyorixCore{
		storage:        storage,
		encryption:     nil,
		now:            time.Now,
		passwordPolicy: DefaultPasswordPolicy(),
		auditStream:    newAuditBroker(),
	}
}

// NewKeyorixCoreWithEncryption creates a new instance with encryption support.
func NewKeyorixCoreWithEncryption(storage storage.Storage, enc *encryption.SecretEncryption) *KeyorixCore {
	return &KeyorixCore{
		storage:        storage,
		encryption:     enc,
		now:            time.Now,
		passwordPolicy: DefaultPasswordPolicy(),
		auditStream:    newAuditBroker(),
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

// SetBootstrapToken sets the token that POST /system/init must present to seed the
// first admin. An empty token disables API bootstrap entirely (fail closed). The
// server wires this at startup; see BootstrapSystem.
func (c *KeyorixCore) SetBootstrapToken(token string) {
	c.bootstrapToken = token
}

// SetSecretValuePolicy enables/configures the secret-value quality gate (off by
// default). The server calls this at startup when secret_value_policy.enabled is set.
func (c *KeyorixCore) SetSecretValuePolicy(p SecretValuePolicy) {
	c.secretValuePolicy = p
}

// SetSecretNamePolicy enables/configures the secret naming convention (off by
// default). The server calls this at startup when secret_name_policy.enabled is set.
// Returns an error (and leaves the policy disabled) if Pattern is not a valid regex.
func (c *KeyorixCore) SetSecretNamePolicy(p SecretNamePolicy) error {
	re, err := compileNamePattern(p.Pattern)
	if err != nil {
		return err
	}
	c.secretNamePolicy = p
	c.secretNameRe = re
	return nil
}

// SetLoginLockoutPolicy enables/configures per-account login lockout. The server
// calls this at startup when security.login_lockout is enabled; left unset, lockout
// is disabled (Enabled=false).
func (c *KeyorixCore) SetLoginLockoutPolicy(p LoginLockoutPolicy) {
	c.loginLockout = p
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
