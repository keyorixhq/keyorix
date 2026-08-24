package core

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
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
	"github.com/keyorixhq/keyorix/internal/trust"
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
	storage storage.Storage
	// httpClient is used for outbound webhook/Slack POSTs (alert escalation).
	// nil = a fresh &http.Client{Timeout: 10s} per call. Overridable in tests to
	// inject a custom transport so no TCP port binding is needed.
	httpClient *http.Client
	// webhookURLValidator enforces SSRF rules on notification channel URLs (scheme
	// + private-IP rejection). nil = use the real validateWebhookURL (which does a
	// live DNS lookup); overridable in tests to avoid network calls.
	webhookURLValidator func(string) error
	// secretValueEncryptor encrypts secret VALUES at rest (ADR-004 envelope
	// AES-256-GCM, AAD-bound per #94). nil = encryption disabled (plaintext at
	// rest, dev/test only — the loud startup banner covers it). Wired from the
	// initialised encryption.Service at server startup via SetSecretValueEncryptor.
	// See secret_value_crypto.go for the fail-closed encrypt/decrypt helpers this
	// backs. Replaces the former, never-wired encryption.SecretEncryption path.
	secretValueEncryptor *encryption.Service
	// authEncryptor reversibly encrypts auth secrets that cannot be hashed (the
	// TOTP MFA shared secret). nil or disabled = passthrough (store plaintext),
	// consistent with the rest of the product when encryption is off. Wired from
	// the initialised encryption.Service at server startup via SetAuthEncryptor.
	authEncryptor *encryption.Service
	// dynamicEngineFactory resolves a dynamic-secrets credential engine by backend
	// type (ADR-035). nil = the real dynamic.New; overridable in tests with a fake.
	dynamicEngineFactory func(string) (dynamic.CredentialEngine, error)
	// trustRegistry resolves the embedded update/license signing-key trust registry
	// (ADR-062/064). nil = the real trust.DefaultRegistry; overridable in tests to
	// inject a lookup failure (#145) without mutating trust package internals.
	trustRegistry func() (*trust.KeyRegistry, error)
	// dynamicSweepEnabled mirrors config dynamic_secrets.sweep_enabled. Backends
	// without DB-level expiry (MySQL/MongoDB) rely entirely on the sweeper to
	// enforce a lease's TTL, so IssueLease refuses to mint from them when it is off
	// (the credential would otherwise never expire). Set via SetDynamicSweepEnabled.
	dynamicSweepEnabled bool
	// dynamicMaxLeaseTTL mirrors config dynamic_secrets.max_lease_ttl (#97): a hard,
	// install-wide ceiling dynamicTTL enforces alongside (never instead of) each
	// config's own MaxTTLSeconds, which has no ceiling of its own. Zero = the
	// package default (90 days) applies. Set via SetDynamicMaxLeaseTTL.
	dynamicMaxLeaseTTL time.Duration
	// dynamicAllowPrivateTargets mirrors config
	// dynamic_secrets.allow_private_network_targets. When false (the default), the
	// SSRF guard in CreateDynamicSecretConfig rejects admin DSNs whose host resolves
	// to a private or link-local address. Set via SetDynamicAllowPrivateTargets.
	dynamicAllowPrivateTargets bool
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
	bootstrapToken string
	// BootstrapSystem's check-then-create sequence is serialized via
	// storage.WithBootstrapLock (a process mutex, plus a PostgreSQL advisory lock
	// across HA replicas — see auth_bootstrap.go and #core-auth-03), not a
	// KeyorixCore-level mutex: a per-process mutex here would only serialize
	// callers within ONE replica, same gap #339 originally closed for concurrent
	// same-process callers only.
	secretValuePolicy SecretValuePolicy  // optional quality gate on secret values (off by default)
	secretNamePolicy  SecretNamePolicy   // optional naming convention for secrets (off by default)
	secretNameRe      *regexp.Regexp     // compiled secretNamePolicy.Pattern (nil = no regex check)
	loginLockout      LoginLockoutPolicy // per-account login lockout (disabled by default)
	// recordFailedLogin (and the pre-session-mint recheck in
	// checkLockAndClearLoginFailures) so concurrent failures can't lose an increment.
	// Combined with the row lock LockUserForUpdate takes on Postgres, the lockout
	// counter stays correct across replicas. Sharded by userID (see
	// loginFailureLock) so a flood against one account cannot serialize every OTHER
	// account's failed-login accounting behind a single process-wide lock — a
	// noisy-neighbour/availability concern distinct from the correctness the
	// per-shard lock + row lock still provide. Zero value is ready to use (each
	// shard is its own zero-value sync.Mutex). See login_lockout.go.
	loginFailureMu [loginFailureMuShards]sync.Mutex
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
	// secretDependencyMu serializes AddSecretDependency's cycle-check read through
	// the edge it writes (#260), so two concurrent callers racing to add A→B and
	// B→A in the same project cannot both pass the pre-write cycle check before
	// either commits, persisting a cycle that later hard-errors rotation planning
	// for that project. Combined with the row lock
	// ListSecretDependenciesForProjectForUpdate takes on Postgres, this holds
	// across replicas too. Zero value is ready to use. See secret_dependencies.go.
	secretDependencyMu sync.Mutex
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
	// sodGrantMu serializes every role-grant path that runs a preventive
	// separation-of-duties check (requireNoSoDViolation /
	// requireGroupGrantNoSoDViolation) before writing the grant (#G04):
	// AssignUserRole, assignUserRoleSystemGrant, AssignRoleToGroup,
	// AssignUserRoleWithExpiry, AssignGroupRoleWithExpiry, and
	// AddUserToGroup's validateGroupJoinRoles path (assignUserRoleWithExpirySkipSoD,
	// break-glass's deliberate SoD-skip path, does not need it — it never reads
	// SoD state to race against). Without it, two concurrent
	// grants that are each individually SoD-clean can both read the principal's
	// pre-grant permission set before either write commits, both pass the
	// check, and together create the exact toxic-permission-combination the
	// gate exists to block. In-process only (LocalStorage/single replica) —
	// a RemoteStorage/multi-replica deployment would need a DB-level lock on
	// the principal's role-grant rows to close the same window across
	// processes, out of scope for this pattern-level fix. Zero value is ready
	// to use. See sod.go / rbac_management.go / groups.go.
	sodGrantMu sync.Mutex
	// accessReviewDecisionMu serializes DecideAccessReviewItem's read-decide-
	// act-persist sequence (#G04): the pending-decision check, the actual
	// attest/revoke side effect, and the decision-stamping write must all be
	// treated as one step. persistItemDecision's conditional UPDATE already
	// stops a SECOND writer from persisting its Decision stamp, but without
	// this mutex both concurrent callers can still read Decision==pending and
	// both execute their attest/revoke action before either write commits —
	// so the losing caller's real-world action (e.g. an actual revoke) still
	// happened even though only the winner's stamp survives, leaving the
	// persisted evidence silently wrong about what was decided. In-process
	// only, same caveat as sodGrantMu. Zero value is ready to use. See
	// access_review_campaign.go.
	accessReviewDecisionMu sync.Mutex
	// dualControlApprovalMu serializes ApproveAccessRequestWithExpiry's
	// read-approvals-decide-grant sequence (#G04): two approvers signing off
	// at the exact threshold boundary can otherwise both read the same
	// below-threshold approval count before either's approval row commits,
	// both compute "received == required", and both finalize the grant —
	// defeating the K-distinct-approvers dual-control guarantee with fewer
	// than K approvals actually recorded first. In-process only, same caveat
	// as sodGrantMu. Zero value is ready to use. See invitations.go.
	dualControlApprovalMu sync.Mutex
	// projectAdminGuardMu serializes guardLastProjectAdmin's read (#G03) with the
	// role removal/change that follows it, in SetProjectMemberRole and
	// RemoveProjectMember: without it, two concurrent calls demoting/removing two
	// DIFFERENT project admins can each read "another admin survives" (the other
	// hasn't been removed yet) and both proceed, jointly stripping the project of
	// every roles.assign holder. A single global mutex, not per-project: this
	// operation is rare (membership changes, not steady-state traffic) so
	// correctness is worth more than cross-project throughput here. Zero value is
	// ready to use. See project_members.go.
	projectAdminGuardMu sync.Mutex
	// rateLimitUnsupportedWarnOnce guards the #452 operator warning logged the
	// first time IsLoginRateLimited/IsPasswordResetRateLimited observe that the
	// active storage backend can never satisfy CountRecentLoginAttempts (as
	// opposed to an ordinary transient storage error) — once per process, not
	// once per request. Zero value is ready to use. See rate_limit.go.
	rateLimitUnsupportedWarnOnce sync.Once
	// loginLockoutUnsupportedWarnOnce guards the #454 operator warning logged the
	// first time recordFailedLogin/checkLockAndClearLoginFailures/clearLoginFailures
	// observe that the active storage backend can never satisfy
	// UpdateLoginLockoutState (as opposed to an ordinary transient storage error) —
	// once per process, not once per login attempt. Zero value is ready to use. See
	// login_lockout.go.
	loginLockoutUnsupportedWarnOnce sync.Once
	auditForwarder                  AuditForwarder
	// auditStream is the in-process pub/sub broker that wakes live audit tails
	// (gRPC StreamAuditLogs) the instant an event is written, replacing fixed-interval
	// DB polling. Always non-nil (set in the constructors).
	auditStream *auditBroker
	// notificationSink broadcasts a deployment-wide, aggregate notification (the
	// compliance digest, an auto-rotation-failure summary) to every enabled external
	// channel, including Slack/Teams/webhook. nil = no channel configured. Set from
	// config via SetNotificationSink. Deliberately NOT used for per-user/per-project
	// events (see recipientNotificationSink) — see #391.
	notificationSink NotificationSink
	// recipientNotificationSink fans a per-user/per-project notification (secret
	// shared, share revoked, ownership transferred, access requested, anomaly alert,
	// break-glass activation, …) out to external channels that can actually address a
	// single recipient — currently just email. nil = in-app only.
	//
	// #391: chat (Slack/Teams) and generic webhook channels are, by design, ONE fixed
	// deployment-wide destination an operator configures (there is no per-user chat-
	// identity mapping in this codebase to DM a specific Slack user). Handing a
	// per-user event straight to those channels — as the old single notificationSink
	// did — broadcasts it to every member of that channel regardless of project
	// membership or secret access, defeating every recipient-scoping computation this
	// package does for the in-app row. So per-user events are routed ONLY to
	// recipient-addressable channels (email, which already drops any event with no
	// resolved address) and never to chat/webhook. Set from config via
	// SetRecipientNotificationSink.
	recipientNotificationSink NotificationSink
	// connectManager proxies read-through federation to external secret stores
	// (ADR-043). nil = Keyorix Connect disabled. Set via SetConnectManager.
	connectManager *connect.Manager
	// connectOwnership maps each configured connector's name to its resolved
	// tenant-scoping data (ADR-082 §A/§E) — built in the same boot pass as
	// connectManager, from the same config, by server/main.go, then set via
	// SetConnectOwnership. Deliberately NOT part of *connect.Manager/the Connector
	// interface (internal/connect stays a pure backend-read abstraction with no
	// ownership concept) — see ADR-082's Decision (D) for the option analysis. A
	// connector name absent from this map is denied ownership, never silently
	// skipped or treated as owned — see connectOwnershipSatisfied.
	connectOwnership map[string]ConnectOwnership
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
	// classificationRestrictedRequiresApproval mirrors config classification.
	// restricted_requires_approval; false (the default) = "restricted" stays purely
	// informational metadata, matching every deployment's behaviour today. When
	// true, a direct value read of a "restricted"-classified secret requires an
	// approved, secret-scoped access request (see classification_gate.go). Set from
	// config at startup via SetClassificationRestrictedRequiresApproval.
	classificationRestrictedRequiresApproval bool
	// classificationRestrictedRequiresPermission mirrors config classification.
	// restricted_requires_permission; false (the default) leaves "restricted" readable
	// by anyone whose RBAC roles grant secrets.read at the project scope. When true,
	// the user must ALSO hold the "secrets.read.restricted" permission (or an admin
	// bypass role). Set at startup via SetClassificationRestrictedRequiresPermission.
	classificationRestrictedRequiresPermission bool
	// classificationRestrictedRequiresMFAStepUp mirrors config classification.
	// restricted_requires_mfa_stepup; when true, reading a "restricted" secret
	// also requires the user to have completed MFA within the step-up window. Set
	// at startup via SetClassificationRestrictedRequiresMFAStepUp.
	classificationRestrictedRequiresMFAStepUp bool
	// classificationRestrictedMFAStepUpWindow is how long a completed MFA
	// verification remains valid for the step-up gate. 0 = default (15 min).
	classificationRestrictedMFAStepUpWindow time.Duration
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
	// membershipDomainAllowlist restricts invited emails to these domains
	// (ADR-022). Empty = no restriction. Set via SetMembershipDomainAllowlist.
	membershipDomainAllowlist []string
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
	// auditCkptKey signs/verifies audit-chain checkpoints (ADR-029): a KEK-derived
	// HMAC key the database/DBA does not hold (#502 — mirroring #268's fix for the
	// evidence-signing key: deriving from the KEK rather than the DEK means a
	// routine DEK rotation does not affect it, so a checkpoint signed before a DEK
	// rotation stays verifiable after one). nil = signed checkpoints unavailable
	// (encryption disabled), in which case WriteAuditCheckpoint is a no-op and
	// VerifyAuditChain runs without on-box checkpoint enforcement. Set at startup
	// via SetAuditCheckpointKey. auditCkptKeyVersion records the KEK-derived key's
	// own fingerprint, so a checkpoint signed under a superseded key (a genuine
	// KEK-provider migration, far rarer than a DEK rotation) is not enforced.
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
	// impersonationCeilingCache caches requireEqualOrGreaterAdminAuthority results
	// by "actorID:targetID" to reduce per-request DB load on the auth hot path for
	// impersonation sessions (IMP-001). Zero value is ready to use (sync.Map).
	impersonationCeilingCache sync.Map
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

// AuditForwarder returns the wired audit forwarder (nil if none configured).
// #G56: the server needs this at shutdown to flush/close the concrete
// forwarder (e.g. *siem.Forwarder) — SetAuditForwarder's caller previously had
// no way to reach it again afterward, since the constructed value lived only
// as a local variable inside server initialization.
func (c *KeyorixCore) AuditForwarder() AuditForwarder {
	return c.auditForwarder
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
//
// Deliver reports whether the event was actually handed off to the channel's
// delivery pipeline (true) or was a no-op (false) — e.g. a broadcast event with no
// per-user recipient and no configured destination for the channel to route it to.
// This is a synchronous, best-effort signal about whether an attempt was even
// queued; it does NOT confirm the remote destination accepted it (that outcome
// stays opaque to the caller by design and is tracked only in the per-channel
// Prometheus counters — see notify_metrics.go). Callers that broadcast to a
// deployment-wide audience (SendComplianceDigest, notifyRotationFailures) use the
// return value so their audit trail doesn't claim success when nothing was ever
// attempted (#221).
type NotificationSink interface {
	Deliver(ev NotificationEvent) bool
}

// SetNotificationSink wires the broadcast (deployment-wide, aggregate) notification
// sink used by SendComplianceDigest and notifyRotationFailures — typically every
// enabled channel (email/Slack/Teams/webhook). The server calls this at startup when
// the install configures a notifications channel. nil = no channel configured.
func (c *KeyorixCore) SetNotificationSink(s NotificationSink) {
	c.notificationSink = s
}

// SetRecipientNotificationSink wires the sink used for per-user/per-project
// notifications (see recipientNotificationSink). The server calls this at startup
// with ONLY the recipient-addressable channels it configured (currently email) —
// never chat/webhook, which have no per-user identity mapping (#391). nil = in-app
// only.
func (c *KeyorixCore) SetRecipientNotificationSink(s NotificationSink) {
	c.recipientNotificationSink = s
}

// NewKeyorixCore creates a new instance of the core business logic. Secret-value
// encryption is off until SetSecretValueEncryptor wires an initialised service (the
// server does this at startup when storage.encryption.enabled).
func NewKeyorixCore(storage storage.Storage) *KeyorixCore {
	return &KeyorixCore{
		storage:        storage,
		now:            time.Now,
		passwordPolicy: DefaultPasswordPolicy(),
		auditStream:    newAuditBroker(),
	}
}

// SetWebhookURLValidator replaces the SSRF guard applied to notification channel
// URLs on create and update. The default (nil) uses validateWebhookURL which
// enforces https-only and rejects private/loopback destinations via a live DNS
// lookup. Tests call this with a no-op to avoid real network calls.
func (c *KeyorixCore) SetWebhookURLValidator(fn func(string) error) {
	c.webhookURLValidator = fn
}

// SetAuthEncryptor wires the encryption service used to protect reversibly-
// encrypted auth secrets (the TOTP MFA secret). The server calls this at startup
// when encryption is enabled. nil/disabled = passthrough.
func (c *KeyorixCore) SetAuthEncryptor(s *encryption.Service) {
	c.authEncryptor = s
}

// SetSecretValueEncryptor wires the encryption service used to encrypt secret VALUES
// at rest (ADR-004 envelope encryption). The server calls this at startup when
// storage.encryption.enabled. Once wired, every new secret version is stored as
// AAD-bound ciphertext and reads fail closed on an unavailable key (see
// secret_value_crypto.go). nil = encryption disabled (plaintext at rest — dev/test).
func (c *KeyorixCore) SetSecretValueEncryptor(s *encryption.Service) {
	c.secretValueEncryptor = s
}

// SecretValueEncryptionActive reports whether secret values are being encrypted at
// rest — i.e. an initialised, enabled encryptor is wired. The server uses this to
// fail closed at startup when encryption is configured but did not actually engage.
func (c *KeyorixCore) SecretValueEncryptionActive() bool {
	return c.secretValueEncryptor != nil && c.secretValueEncryptor.IsEnabled() && c.secretValueEncryptor.IsInitialized()
}

// AuthEncryptionActive reports whether at-rest encryption for auth secrets (MFA
// TOTP seeds, dynamic-secret configs) is enabled -- the same condition
// BeginMFAEnrollment fails closed on. Exported for UpsertMFASecretProxy
// (server/http/handlers/mfa_management_proxy.go), which needs to refuse an
// MFA-secret write under the same condition without duplicating the
// authEncryptor field access.
func (c *KeyorixCore) AuthEncryptionActive() bool {
	return c.authEncryptor != nil && c.authEncryptor.IsEnabled()
}

// encryptAuthSecret reversibly encrypts plain, bound to aad (#94: MFASecretAAD /
// DynamicSecretConfigAAD / DynamicSecretLeaseAAD — never nil for a live caller, so a
// DB-write attacker cannot transplant one row's ciphertext onto another's identity and
// have it decrypt). Passthrough when encryption is off.
func (c *KeyorixCore) encryptAuthSecret(plain string, aad []byte) (ct, meta []byte, err error) {
	if c.authEncryptor == nil || !c.authEncryptor.IsEnabled() {
		return []byte(plain), nil, nil
	}
	return c.authEncryptor.EncryptSecretWithAAD([]byte(plain), aad)
}

// decryptAuthSecret reverses encryptAuthSecret. aad must be reconstructed from the
// row's own identity, identically to how it was encrypted. Falls back to a legacy
// nil-AAD decrypt for rows encrypted before #94 (Service.DecryptSecretWithAAD's own
// AADVersion branch — the same AAD-bound pattern secret_value_crypto.go applies to
// secret values); the sweep upgrades those rows to AAD-bound in place. Passthrough
// when encryption is off.
func (c *KeyorixCore) decryptAuthSecret(ct, _ []byte, aad []byte) (string, error) {
	if c.authEncryptor == nil || !c.authEncryptor.IsEnabled() {
		return string(ct), nil
	}
	plain, err := c.authEncryptor.DecryptSecretWithAAD(ct, aad)
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

// SetDynamicAllowPrivateTargets controls whether the admin-DSN SSRF guard is
// bypassed. When false (the default), CreateDynamicSecretConfig rejects DSNs
// whose host resolves to a private or link-local address. Set to true only when
// the dynamic-secret backend legitimately lives on a private segment.
func (c *KeyorixCore) SetDynamicAllowPrivateTargets(allow bool) {
	c.dynamicAllowPrivateTargets = allow
}

// SetDynamicMaxLeaseTTL sets the install-wide dynamic-secret lease TTL ceiling
// (config dynamic_secrets.max_lease_ttl, #97). A non-positive value is ignored — the
// package default (90 days) applies instead of disabling the ceiling.
func (c *KeyorixCore) SetDynamicMaxLeaseTTL(ttl time.Duration) {
	if ttl > 0 {
		c.dynamicMaxLeaseTTL = ttl
	}
}

// dynamicEngine resolves an engine for a backend type via the factory (or the
// real dynamic.New when none is set). c.dynamicAllowPrivateTargets is threaded
// through to dynamic.New so an engine that dials the admin DSN itself
// (postgres, mysql) applies the SAME private/link-local dial-time guard (or
// the same explicit operator opt-out) enforceDynamicSecretSSRFGuard already
// applies at config create/issue/renew time (G48).
func (c *KeyorixCore) dynamicEngine(backendType string) (dynamic.CredentialEngine, error) {
	if c.dynamicEngineFactory != nil {
		return c.dynamicEngineFactory(backendType)
	}
	return dynamic.New(backendType, c.dynamicAllowPrivateTargets)
}

// SetTrustRegistryFunc overrides how the update/license signing-key trust registry
// is resolved (tests inject a failing lookup to exercise #145's degrade path).
func (c *KeyorixCore) SetTrustRegistryFunc(f func() (*trust.KeyRegistry, error)) {
	c.trustRegistry = f
}

// defaultTrustRegistry resolves the trust registry via the override (or the real
// trust.DefaultRegistry when none is set).
func (c *KeyorixCore) defaultTrustRegistry() (*trust.KeyRegistry, error) {
	if c.trustRegistry != nil {
		return c.trustRegistry()
	}
	return trust.DefaultRegistry()
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
func (c *KeyorixCore) ResolveUsernames(ctx context.Context, events []*models.AuditEvent) map[uint]string { // nosemgrep: keyorix-unbounded-bulk-slice-param -- events is an already-paginated audit-log query result, not a raw client-supplied array; the per-item DB round trip below is over the deduped user-id set, not events itself
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
