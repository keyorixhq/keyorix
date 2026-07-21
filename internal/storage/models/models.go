package models

import (
	"time"

	"gorm.io/gorm"
)

type Project struct {
	ID uint `gorm:"primaryKey"`
	// Name uniqueness is enforced by a case-insensitive PARTIAL unique index
	// (LOWER(name) WHERE deleted_at IS NULL), created in migrateDatabase (#385) — not
	// the plain `uniqueIndex` tag — so "Production"/"production" can't land as two
	// distinct rows (closing a shadow-project confusion vector against the
	// case-insensitive CLI project-name resolution), while a soft-deleted project's
	// name is still freed for reuse.
	Name        string `gorm:"not null"`
	Description string
	// RequireMFA, when true, denies interactive (session-authenticated) callers
	// without a second factor access to this project's scoped resources, even when
	// the deployment-wide security.require_mfa policy is off (ADR-037). Non-
	// interactive credentials (PAT / machine / OIDC) are exempt, like the global policy.
	RequireMFA bool `gorm:"default:false"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  gorm.DeletedAt `gorm:"index"` // soft delete
}

type Environment struct {
	ID        uint   `gorm:"primaryKey"`
	ProjectID uint   `gorm:"not null;uniqueIndex:idx_env_project_name"`
	Name      string `gorm:"not null;uniqueIndex:idx_env_project_name"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"` // soft delete
}

// ProjectInvitation tracks an admin's intent to grant an email address a role in
// a project (ADR-024). State machine: pending → accepted / revoked / expired.
// The email/setup-link consumption (accept) is implemented in
// internal/core/setup_consume.go (completeInvitationAccept); this record tracks
// the pending invite so it can be listed, revoked, and aged out.
type ProjectInvitation struct {
	ID                     uint   `gorm:"primaryKey"`
	ProjectID              uint   `gorm:"index"`
	Email                  string `gorm:"index"`
	Role                   string // intended project role (project-scoped invite)
	State                  string // pending | accepted | revoked | expired
	InvitedBy              uint
	ValidationModeAtInvite string // snapshot of the install validation mode at invite time
	// Global invite (ADR-024): a non-project-scoped invitation (ProjectID 0) that, on
	// accept, grants a system role plus the per-project assignments below. Both empty
	// for a project-scoped invite.
	SystemRole      string // optional system role granted on accept
	AssignmentsJSON string `gorm:"type:text"` // optional JSON []{project_id, role} for multi-project grants
	ExpiresAt       *time.Time
	CreatedAt       time.Time
	AcceptedAt      *time.Time
	RevokedAt       *time.Time
}

// AccessRequest is a user's request for a role in a project (ADR-024), OR — when
// SecretID is set — a request for approval to read one specific secret's value
// (classification-gated reads, see internal/core/classification_gate.go). State
// machine: pending → approved / rejected / withdrawn / expired in both cases. For
// a project/role request, approval assigns the granted role (which may differ
// from the suggested one) at the project scope. For a secret-scoped request,
// approval grants no role at all — it only flips State to approved, which the
// classification gate looks for; GrantedRole/SuggestedRole are unused (left
// empty) on that path. No auto-approval either way.
type AccessRequest struct {
	ID            uint   `gorm:"primaryKey"`
	ProjectID     uint   `gorm:"index"`
	UserID        uint   `gorm:"index"`
	SuggestedRole string // role the requester asks for (empty for a secret-scoped request)
	GrantedRole   string // role actually granted on approval (empty for a secret-scoped request)
	// SecretID, when non-nil, narrows this request to "approval to read this one
	// secret" rather than a project/role grant (see RequestSecretAccess /
	// ApproveSecretAccessRequest). nil = the original project/role request this
	// model was designed for (ADR-024).
	SecretID      *uint `gorm:"index"`
	State         string // pending | approved | rejected | withdrawn | expired
	Reason        string // requester's note, or the rejecter's reason
	ResolvedBy    uint
	ExpiresAt     *time.Time
	CreatedAt     time.Time
	ResolvedAt    *time.Time
	// ApprovalsReceived / RequiredApprovals are transient (not persisted): the
	// dual-control progress (M of K) the API surfaces for a pending request.
	ApprovalsReceived int `gorm:"-"`
	RequiredApprovals int `gorm:"-"`
}

// AccessRequestApproval records one approver's sign-off on an access request, for
// N-of-M dual control (ISO 27001 A.5.3 / SOX): a request grants the role only once
// RequiredApprovals distinct approvers (none of them the requester) have approved.
type AccessRequestApproval struct {
	ID uint `gorm:"primaryKey"`
	// (RequestID, ApproverID) is unique: one sign-off per distinct approver. The
	// constraint is the race backstop for the M-of-K dual-control count — without it,
	// concurrent approvals from the same approver could insert multiple rows and the
	// row-count threshold would treat one person as several, defeating dual control.
	// The composite index also covers RequestID lookups (leftmost column).
	RequestID  uint `gorm:"not null;uniqueIndex:ux_access_request_approver"`
	ApproverID uint `gorm:"not null;uniqueIndex:ux_access_request_approver"`
	CreatedAt  time.Time
}

// RejectionReasonTemplate is a reusable pre-defined reason for rejecting access
// requests. Admins create named templates so common rejection reasons can be
// selected from a list rather than typed each time.
type RejectionReasonTemplate struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"not null;uniqueIndex" json:"name"`    // short label
	Reason    string    `gorm:"not null" json:"reason"`              // full text
	CreatedBy uint      `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SoDPolicy is a separation-of-duties rule (ISO 27001 A.5.3 / SOX): two permissions
// that one principal must not hold together (a "toxic combination"). A user whose
// effective permissions include BOTH PermissionA and PermissionB violates it. The
// policy existing = active; delete it to retire the rule.
type SoDPolicy struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	PermissionA string    `json:"permission_a"` // e.g. "roles.assign"
	PermissionB string    `json:"permission_b"` // e.g. "secrets.delete"
	CreatedBy   uint      `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// TableName pins the table name (GORM would otherwise derive "so_d_policies").
func (SoDPolicy) TableName() string { return "sod_policies" }

// LegalHold is a deployment-wide litigation/investigation hold (ISO 27001 A.5.34 /
// eDiscovery / DORA record-keeping). While one is active (Released = false), the
// background purge/retention jobs must not hard-delete any records, so data under
// hold is preserved. Placing/lifting is audited; the row history is the evidence
// of when holds were in effect.
type LegalHold struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	Reason        string     `json:"reason"`
	PlacedBy      uint       `json:"placed_by"`
	PlacedAt      time.Time  `json:"placed_at"`
	Released      bool       `gorm:"index" json:"released"` // false = active
	ReleasedBy    uint       `json:"released_by,omitempty"`
	ReleasedAt    *time.Time `json:"released_at,omitempty"`
	ReleaseReason string     `json:"release_reason,omitempty"` // why the hold was lifted (#380)
}

// SSOLoginState is the short-lived CSRF/nonce state for an in-flight OIDC
// authorization-code login (RFC 6749 §10.12 / the OIDC nonce). It is created when
// the user is redirected to the IdP and consumed single-use on callback, binding the
// returned id_token's nonce to this browser and proving the callback's state was the
// one we issued. Expires within minutes.
type SSOLoginState struct {
	ID        uint      `gorm:"primaryKey"`
	State     string    `gorm:"uniqueIndex;not null"` // random CSRF token; the lookup key
	Nonce     string    `gorm:"not null"`             // bound into the requested id_token
	Provider  string    `gorm:"not null"`
	ReturnTo  string    // optional in-app path to land on after login
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}

// SchedulerLockLease is a TTL-bounded distributed-mutex row backing
// TryAcquireSchedulerLock/ReleaseSchedulerLock (#530). Unlike LocalStorage's
// own WithSchedulerLock (a Postgres session advisory lock held for the exact
// duration of one in-process call), this primitive exists so a
// storage.type: remote (ADR-049) spoke can acquire the SAME single-replica
// guarantee over two separate HTTP round trips (acquire, then release once its
// locally-run scheduler job finishes) without ever pinning a live DB
// connection across requests: Holder proves ownership so a stale/expired
// holder can never release (or be mistaken for holding) a lease a newer
// holder has since won, and ExpiresAt bounds how long a crashed or
// network-partitioned holder can wedge the key — a fresh acquire attempt past
// ExpiresAt reclaims the row unconditionally. One row per lock Key — Key is
// the primary key, so the DB itself rejects a second concurrent row for the
// same lock (the belt-and-suspenders case TryAcquireSchedulerLock's own
// isUniqueViolation check handles).
type SchedulerLockLease struct {
	Key       int64     `gorm:"primaryKey;autoIncrement:false"`
	Holder    string    `gorm:"not null"` // opaque per-acquisition token, not a stable identity
	ExpiresAt time.Time `gorm:"index"`
}

// RiskException records a governed acceptance of a known control gap or policy
// exception (ISO 27001 A.5.8 risk treatment / A.5.36 compliance-with-policies): a
// named risk, accepted by an owner with a written justification, for a bounded time.
// While active (not revoked and not past ExpiresAt) it is the auditable evidence that
// a gap is *accepted with a sunset*, not silently ignored — so an auditor sees a
// governed exception rather than a raw violation. Exceptions are always time-bound.
type RiskException struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	Title         string     `json:"title"`
	Category      string     `json:"category"`            // sod | mfa | rotation | dormant_access | classification | other
	Reference     string     `json:"reference,omitempty"` // what it applies to (a user, an SoD pair, a secret)
	Justification string     `json:"justification"`
	CreatedBy     uint       `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `gorm:"index" json:"expires_at"` // required — exceptions sunset
	Revoked       bool       `gorm:"index" json:"revoked"`    // true = withdrawn before expiry
	RevokedBy     uint       `json:"revoked_by,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	// Approved/ApprovedBy/ApprovedAt implement dual control (#170): an exception
	// only suppresses its matched violation once a DIFFERENT system.write holder
	// than the creator approves it, so the same actor can't unilaterally create
	// and self-approve a suppression of their own risk.
	Approved   bool       `gorm:"default:false" json:"approved"`
	ApprovedBy uint       `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
}

// BreakGlassActivation records a self-service emergency-access elevation: a user
// immediately self-granted a time-bound emergency role (no approval), with a
// written justification, for incident response (NIS2/DORA). The grant itself is a
// JIT time-bound role assignment that auto-expires; this record is the queryable,
// auditable evidence for post-hoc review. State: active → expired | revoked.
//
// A partial unique index on (project_id, user_id) WHERE state='active' (created by
// the storage migration, not expressible via a plain gorm tag) enforces at most one
// active activation per project+user even under a race — see
// storage.ErrBreakGlassAlreadyActive.
type BreakGlassActivation struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	ProjectID     uint       `gorm:"index" json:"project_id"`
	UserID        uint       `gorm:"index" json:"user_id"` // who activated it
	RoleID        uint       `json:"role_id"`
	RoleName      string     `json:"role_name"`
	Justification string     `json:"justification"`
	State         string     `json:"state"` // active | expired | revoked
	ExpiresAt     *time.Time `gorm:"index" json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedBy     uint       `json:"revoked_by,omitempty"` // set on early revoke
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// AccessReviewCampaign is a periodic access-recertification cycle for a project
// (ISO 27001 A.5.18 — review at planned intervals). Opening a campaign snapshots
// the project's current access-review entries into AccessReviewItem rows; reviewers
// then decide each (attest/revoke); closing it freezes the record as evidence the
// review was performed. State machine: open → closed.
type AccessReviewCampaign struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	ProjectID uint       `gorm:"index" json:"project_id"`
	Name      string     `json:"name"`  // human label, e.g. "Q4 2026 access recertification"
	State     string     `json:"state"` // open | closed
	CreatedBy uint       `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ClosedBy  uint       `json:"closed_by,omitempty"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`
	// Degraded/DegradedReasons carry forward AccessReviewReport.Degraded/
	// DegradedReasons (access_review.go) from the snapshot this campaign was
	// opened from (#483). Without this, a transient storage error mid-snapshot
	// (e.g. ListSharesBySecret failing for one secret) produces a campaign
	// evidence row indistinguishable from a fully-covered review — the ephemeral
	// report signal would otherwise be discarded the instant the campaign is
	// created, undermining the very control (ISO 27001 A.5.18 recertification
	// coverage) the #453 degrade signal exists to protect.
	Degraded bool `gorm:"default:false" json:"degraded"`
	// DegradedReasons is JSON-serialized (gorm serializer) so it round-trips as a
	// native []string, mirroring AccessReviewReport.DegradedReasons.
	DegradedReasons []string `gorm:"serializer:json" json:"degraded_reasons,omitempty"`
	// ForcedIncomplete marks a close performed with `force` while items were still
	// pending (#237): the campaign was frozen as evidence, but it is NOT a genuine
	// completed recertification — some access was never reviewed. Mirrors the
	// Degraded pattern above: without a durable signal, this close is otherwise
	// indistinguishable from a fully-decided one, so the recertification cadence
	// (recertification.go) would silently treat a rushed, incomplete force-close as
	// satisfying a full review cycle and push the next-due date out just as far.
	ForcedIncomplete bool `gorm:"default:false" json:"forced_incomplete"`
}

// AccessReviewItem is one access grant captured in a campaign at open time, plus
// the reviewer's recertification decision. The grant fields mirror an
// AccessReviewEntry (a frozen snapshot — the live grant may change or be revoked
// after capture). Decision: pending → attested | revoked.
type AccessReviewItem struct {
	ID         uint `gorm:"primaryKey" json:"id"`
	CampaignID uint `gorm:"index" json:"campaign_id"`
	// Snapshot of the AccessReviewEntry at open time.
	PrincipalType string `json:"principal_type"`
	PrincipalID   uint   `json:"principal_id"`
	PrincipalName string `json:"principal_name"`
	Email         string `json:"email,omitempty"`
	Source        string `json:"source"` // role | owner | direct_share | group_share
	RoleID        uint   `json:"role_id,omitempty"`
	RoleName      string `json:"role_name,omitempty"`
	AccessLevel   string `json:"access_level"`
	EnvironmentID uint   `json:"environment_id"`
	SecretID      uint   `json:"secret_id,omitempty"`
	SecretName    string `json:"secret_name,omitempty"`
	// LastUsedAt captures the principal's last secret-access time at open (dormant-
	// access signal frozen into the evidence record); nil = no recorded activity.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// Recertification decision.
	Decision  string     `json:"decision"`         // pending | attested | revoked
	Reason    string     `json:"reason,omitempty"` // optional reviewer note
	DecidedBy uint       `json:"decided_by,omitempty"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
}

type User struct {
	ID uint `gorm:"primaryKey"`
	// Username uniqueness is enforced by a PARTIAL unique index (username WHERE
	// deleted_at IS NULL), created in migrateDatabase — not the plain `uniqueIndex`
	// tag — so a soft-deleted (e.g. SCIM-deprovisioned) user's username is freed for
	// reuse on re-provisioning while the old row stays restorable for audit.
	Username string `gorm:"not null"`
	// Email uniqueness (among live, non-empty rows) is enforced by a PARTIAL
	// unique index (email WHERE deleted_at IS NULL AND email != ''), created in
	// migrateDatabase — mirrors the Username precedent. Without this, two
	// concurrent CreateUser calls with the same address could both succeed,
	// leaving duplicate-email accounts with ambiguous SSO/SCIM/password-reset
	// targeting.
	Email        string
	DisplayName  string
	PasswordHash string     `json:"-"`
	IsActive     bool       `gorm:"default:true"`
	LastLoginAt  *time.Time // stamped on each successful auth.login; nil = never logged in
	// PasswordChangedAt is when the current password was set. Drives max-age
	// expiry (ADR-025). nil on legacy rows = treat as set at account creation.
	PasswordChangedAt *time.Time
	// AccountState is the ADR-025 lifecycle state: active | pending_first_login |
	// password_reset_required | suspended. Empty (legacy rows) is treated as active.
	AccountState string `gorm:"default:'active'"`
	// MFAEnabled is true once the user has activated TOTP MFA; login then requires
	// a one-time code (see MFASecret / MFAChallenge).
	MFAEnabled bool `gorm:"default:false"`
	// WebAuthnEnabled is true once the user has registered at least one passkey /
	// security key (ADR-036); like MFAEnabled it makes login a two-step flow, with
	// a WebAuthn assertion as the second factor (see WebAuthnCredential).
	WebAuthnEnabled bool `gorm:"default:false"`
	// ExternalID is the IdP's stable identifier for a SCIM-provisioned user (SCIM
	// externalId, RFC 7644). Empty for locally-created users. Uniqueness (among
	// live, non-empty rows) is enforced by a PARTIAL unique index, created in
	// migrateDatabase — two different users sharing a non-empty external_id would
	// make SSO/SCIM identity resolution (GetUserByExternalID) ambiguous. Blank
	// rows (every local account) coexist freely.
	ExternalID string `gorm:"index"`
	// Per-account login lockout (brute-force protection). FailedLoginAttempts counts
	// consecutive failed password logins within the configured window;
	// LoginLockedUntil (when set and in the future) refuses login regardless of the
	// password; LoginLockoutCount drives the exponential backoff across repeated
	// lockouts. All reset on a successful login or an admin unlock.
	FailedLoginAttempts int `gorm:"default:0"`
	LastFailedLoginAt   *time.Time
	LoginLockedUntil    *time.Time
	LoginLockoutCount   int `gorm:"default:0"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletedAt           gorm.DeletedAt `gorm:"index"` // soft delete — set by DELETE /users/{id}, cleared by restore
}

// MFASecret holds a user's TOTP shared secret, encrypted at rest. One row per
// user (UserID unique). Activated flips true on the first valid code at
// enrolment; a row with Activated=false is a pending enrolment not yet confirmed.
type MFASecret struct {
	ID     uint `gorm:"primaryKey"`
	UserID uint `gorm:"uniqueIndex"`
	// SecretEnc is the encrypted TOTP secret. Unlike a general secret VALUE (whose
	// at-rest encryption is an explicit, informed operator trade-off when disabled —
	// see encryption.SecretEncryption.StoreSecret) or a dynamic-secret admin DSN
	// (same plaintext-passthrough via core.encryptAuthSecret), MFA does NOT fall
	// back to plaintext when encryption is off: the sole write path,
	// core.BeginMFAEnrollment, refuses outright ("... requires at-rest encryption
	// to be enabled") rather than ever calling encryptAuthSecret with a
	// disabled/nil encryptor for this row. So although encryptAuthSecret's
	// plaintext-passthrough branch exists in the shared helper (and is genuinely
	// used by its other two callers), it is unreachable for MFASecret in
	// practice — a row here is either genuinely encrypted or, for a pre-#94
	// legacy row, holds an already-encrypted-under-the-old-scheme value.
	SecretEnc  []byte `json:"-"`
	SecretMeta []byte `json:"-"` // encryption metadata (key version etc.)
	Activated  bool   `gorm:"default:false"`
	// LastUsedStep is the TOTP time-step (unix/period) of the most recently accepted
	// login code. A code at or below it is a replay within its validity window and is
	// rejected (anti-replay). nil on legacy rows = no code accepted yet.
	LastUsedStep *int64 `json:"-"`
	CreatedAt    time.Time
}

// MFARecoveryCode is a single-use backup code (SHA-256 hashed). UsedAt is stamped
// when consumed so a code cannot be replayed.
type MFARecoveryCode struct {
	ID       uint   `gorm:"primaryKey"`
	UserID   uint   `gorm:"index"`
	CodeHash string `gorm:"index"`
	UsedAt   *time.Time
}

// MFAChallenge is a short-lived, single-use pre-auth token issued when an
// MFA-enabled user passes the password step; the verify step consumes it. The
// raw token is never stored — only its SHA-256 hash.
type MFAChallenge struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    uint   `gorm:"index"`
	TokenHash string `gorm:"uniqueIndex" json:"-"`
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// LoginAttempt records one failed authentication attempt from a client IP, for
// cluster-wide brute-force rate limiting (ADR-040). Counting rows within the
// window across all replicas replaces the old per-process in-memory limiter, so
// the limit holds in HA. Rows past the window are pruned by a maintenance sweep
// and are never read after that. The composite index serves the windowed count.
type LoginAttempt struct {
	ID uint   `gorm:"primaryKey"`
	IP string `gorm:"index:idx_login_attempt_ip_time,priority:1"`
	// AttemptedAt carries two indexes: the composite (ip, attempted_at) serves the
	// per-IP windowed count, and a standalone index serves the prune's
	// `WHERE attempted_at < ?` (the composite's leading ip column can't), keeping the
	// hourly cleanup an index range delete rather than a full-table scan.
	AttemptedAt time.Time `gorm:"index:idx_login_attempt_ip_time,priority:2;index:idx_login_attempt_time"`
}

// WebAuthnCredential is a registered passkey / FIDO2 authenticator (ADR-036).
// CredentialBlob is the JSON-serialized go-webauthn Credential (public key,
// attestation, sign count, transports) — the library's canonical record, updated
// on each login to track the signature counter for clone detection. CredentialID
// is the raw credential ID (indexed) used to look the row up at assertion time.
type WebAuthnCredential struct {
	ID             uint   `gorm:"primaryKey"`
	UserID         uint   `gorm:"index"`
	CredentialID   []byte `gorm:"uniqueIndex"`
	Name           string // user-supplied label, e.g. "YubiKey 5C" or "MacBook Touch ID"
	CredentialBlob []byte // JSON of webauthn.Credential
	CreatedAt      time.Time
	LastUsedAt     *time.Time

	// Disabled is set when an authentication attempt against this credential showed
	// a signature-counter regression (go-webauthn's CloneWarning — #212), the
	// standard FIDO2 signal that its private key material may exist on more than one
	// device. A disabled credential is excluded from every future ceremony (it can no
	// longer authenticate, and won't be offered for exclusion on re-registration
	// either); the owner must delete it and register a fresh passkey. Never
	// auto-re-enabled — the stored counter can never again exceed a value a
	// possibly-compromised clone already asserted.
	Disabled bool `gorm:"default:false"`
}

// WebAuthnSession persists the in-flight ceremony state (the go-webauthn
// SessionData: challenge, allowed credentials, UV requirement) between the begin
// and finish steps of a registration or login. Single-use and short-lived, keyed
// by the SHA-256 hash of an opaque token (the raw token is never stored) — the
// same hash-at-rest pattern as MFAChallenge. Purpose is "register" or "login".
type WebAuthnSession struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    uint   `gorm:"index"`
	TokenHash string `gorm:"uniqueIndex" json:"-"`
	Purpose   string
	Data      []byte // JSON of webauthn.SessionData
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// PasswordHistory records prior password hashes per user so the policy can
// forbid reuse of the last N passwords (ADR-025 history_count). Only bcrypt
// hashes are stored — never plaintext.
type PasswordHistory struct {
	ID           uint   `gorm:"primaryKey"`
	UserID       uint   `gorm:"index"`
	PasswordHash string `json:"-"`
	CreatedAt    time.Time
}

type Role struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"unique;not null"`
	Description string
}

type Permission struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"unique;not null"`
	Description string
	Resource    string `gorm:"not null"`
	Action      string `gorm:"not null"`
}

type RolePermission struct {
	RoleID       uint `gorm:"primaryKey"`
	PermissionID uint `gorm:"primaryKey"`
}

// UserRole binds a user to a role at a scope. ProjectID/EnvironmentID use a
// 0 = global sentinel (not NULL) so they can sit in the composite primary key
// without nullable-PK headaches across SQLite and Postgres:
//
//	(0, 0)   role applies globally (every project/environment)
//	(P, 0)   role applies to all environments in project P
//	(P, E)   role applies only to environment E of project P
type UserRole struct {
	UserID        uint `gorm:"primaryKey"`
	RoleID        uint `gorm:"primaryKey"`
	ProjectID     uint `gorm:"primaryKey;not null;default:0"`
	EnvironmentID uint `gorm:"primaryKey;not null;default:0"`
	// ExpiresAt makes a grant time-bound (just-in-time access): nil = permanent;
	// otherwise the grant stops authorizing the moment it passes and is swept by
	// the JIT expiry scheduler. Authorization queries filter on it directly so an
	// expired grant is denied immediately, before the sweep removes the row.
	ExpiresAt *time.Time `gorm:"index"`
}

// ConnectRefGrant scopes which secret references a role may read through a Keyorix
// Connect connector (ADR-045) — a per-connector, per-role reference allowlist that
// refines the global connect.read permission. A grant authorizes any ref whose value
// begins with RefPrefix on the named connector for holders of RoleID (RefPrefix "" =
// all refs on that connector).
//
// Enforcement is deny-by-default ONLY for connectors that have at least one grant:
// when NO grant exists for a connector, that connector is governed solely by
// connect.read plus the operator's allowed_refs (backward compatible); once any grant
// exists for a connector, a read is permitted only if one of the caller's roles holds
// a matching grant.
type ConnectRefGrant struct {
	ID        uint   `gorm:"primaryKey"`
	RoleID    uint   `gorm:"not null;index;uniqueIndex:uq_connect_ref_grant,priority:1"`
	Connector string `gorm:"not null;index;uniqueIndex:uq_connect_ref_grant,priority:2"`
	RefPrefix string `gorm:"not null;uniqueIndex:uq_connect_ref_grant,priority:3"`
	// ExpiresAt makes a grant time-bound (just-in-time access): nil = permanent;
	// otherwise the grant stops authorizing the moment it passes. Enforcement checks
	// this directly so an expired grant is denied immediately, mirroring
	// UserRole.ExpiresAt / ShareRecord.ExpiresAt.
	ExpiresAt *time.Time `gorm:"index"`
	CreatedAt time.Time
}

type Group struct {
	ID uint `gorm:"primaryKey"`
	// Name uniqueness is enforced by a PARTIAL unique index (name WHERE deleted_at
	// IS NULL), created in migrateDatabase — not the plain `unique` tag — so a
	// soft-deleted group's name is freed for reuse while it stays restorable.
	Name        string `gorm:"not null"`
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"` // soft delete (restorable)
}

type UserGroup struct {
	UserID uint `gorm:"primaryKey"`
	GroupID uint `gorm:"primaryKey"`
	// ProjectID scopes this membership to a specific project. 0 = global (member
	// in every project), non-zero = member only within that project. The
	// authorisation query unions project_id=0 rows with project_id=<requested>
	// rows, so global memberships still confer roles everywhere.
	ProjectID uint `gorm:"primaryKey;not null;default:0"`
}

// GroupRole binds a group to a role at a scope. See UserRole for the
// 0 = global sentinel semantics of ProjectID/EnvironmentID.
type GroupRole struct {
	GroupID       uint `gorm:"primaryKey"`
	RoleID        uint `gorm:"primaryKey"`
	ProjectID     uint `gorm:"primaryKey;not null;default:0"`
	EnvironmentID uint `gorm:"primaryKey;not null;default:0"`
	// ExpiresAt makes a group grant time-bound; see UserRole.ExpiresAt.
	ExpiresAt *time.Time `gorm:"index"`
}

type SecretNode struct {
	ID            uint `gorm:"primaryKey"`
	ParentID      *uint
	ProjectID     uint
	EnvironmentID uint
	Name          string `gorm:"not null"`
	IsSecret      bool   `gorm:"default:false"`
	Type          string
	// Description is an optional free-text note about the secret — what it is, which
	// upstream it belongs to, who to contact. Metadata only; never the value.
	Description string
	MaxReads    *int
	// ReadCount is the secret's LIFETIME read count against MaxReads — deliberately
	// secret-level, not per-version (#133). A per-version counter resets to zero on
	// every new version, so a burn-after-N-reads secret became re-readable simply
	// by rotating or rolling back (which creates a fresh version); this counter
	// carries forward across both.
	ReadCount  int
	Expiration *time.Time
	Metadata   JSON
	// Classification is the data sensitivity label (ISO 27001 A.5.12/A.5.13):
	// "" = unclassified, else one of public|internal|confidential|restricted. Drives
	// the classification posture and lets a review find high-sensitivity secrets.
	// LABEL ONLY, NOT A CONTROL — see the KNOWN LIMITATION note on the package doc of
	// internal/core/classification.go; a "restricted" secret is not currently treated
	// any differently at read time than a "public" one.
	Classification string `gorm:"index"`
	Status         string `gorm:"default:'active'"`
	CreatedBy      string
	OwnerID        uint `gorm:"index"`
	IsShared       bool `gorm:"default:false"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastRotatedAt  *time.Time
	// AutoRotate opts this secret into automated rotation (ADR-046): when set, and the
	// secret is covered by an active rotation policy it is overdue under, the rotation
	// executor regenerates its value on schedule. Off by default — only secrets whose
	// value Keyorix owns (generated, no external consumer to coordinate) should enable
	// it, since auto-rotation changes the stored value without touching any upstream.
	AutoRotate bool `gorm:"not null;default:false"`
	// RotationLength / RotationCharset shape the value the auto-rotation executor
	// generates (ADR-046). RotationLength 0 = the default length; RotationCharset "" =
	// the default alphanumeric set. See the rotation executor for the named charsets.
	RotationLength  int    `gorm:"not null;default:0"`
	RotationCharset string `gorm:"not null;default:''"`
	// RotationBackend / RotationRef wire a secret to a backend rotation executor
	// (ADR-047): when RotationBackend names a configured executor, auto-rotation applies
	// the new value to the upstream system (RotationRef = the upstream identifier, e.g. a
	// DB role) before storing it. Empty RotationBackend = regenerate in Keyorix only.
	RotationBackend string `gorm:"not null;default:''"`
	RotationRef     string `gorm:"not null;default:''"`
	// CertNotAfter caches the parsed leaf-certificate expiry for certificate-typed
	// secrets (ADR-056). Populated as a side-effect of certificate inspection /
	// expiry scans (which already decrypt + parse the value), so the compliance
	// posture can report certificate hygiene without decrypting on the read path.
	// Nil = not yet evaluated (or not a certificate). Metadata only — never the value.
	CertNotAfter *time.Time `gorm:"index"`
	// DeletedAt enables soft delete (ADR-033). DELETE stamps it; restore clears
	// it; the purge scheduler hard-deletes rows past the retention window. GORM
	// auto-scopes `deleted_at IS NULL` on model-based queries — raw/Table/Joins
	// queries on secret_nodes must filter it explicitly.
	DeletedAt gorm.DeletedAt `gorm:"index"`
	// RetentionOverrideDays overrides the global retention window for this secret.
	// 0 means "use global setting". Must be >= 7 if non-zero.
	RetentionOverrideDays int `gorm:"default:0" json:"retention_override_days,omitempty"`
	// ValueStored is a transient, in-process-only signal (#499): never persisted
	// (`gorm:"-"`) and never serialized (`json:"-"`). storage.Storage.CreateSecret
	// sets it true on the node it returns ONLY when the backend already durably
	// stored the secret's initial value as part of that same call (RemoteStorage,
	// when core forwarded a plaintextValue and the upstream server created
	// version 1 atomically). core.CreateSecret checks this to decide whether its
	// own follow-up CreateSecretVersion call is still needed (LocalStorage,
	// where it always is) or would create a conflicting duplicate (RemoteStorage,
	// where the value is already stored). Never carries the value itself.
	ValueStored bool `gorm:"-" json:"-"`
}

// SecretDependency is a directed edge in a project's secret dependency graph:
// the secret DependentSecretID "depends on" DependsOnSecretID — i.e. rotating the
// dependency may require updating or re-issuing the dependent (e.g. an application
// token derived from a database password, or a config value that embeds another
// secret). Metadata only; never the secret values. The graph drives impact analysis
// ("what breaks if I rotate this?") and rotation ordering (ADR-052). Both endpoints
// are secrets in the same project AND environment (authorization is environment-
// granular, so an edge is confined to one environment); self-edges, duplicates,
// cross-environment edges, and cycles are rejected at create so the graph stays a DAG.
type SecretDependency struct {
	ID        uint `gorm:"primaryKey" json:"id"`
	ProjectID uint `gorm:"index;not null" json:"project_id"` // denormalised from the endpoints (same for both)
	// DependentSecretID depends on DependsOnSecretID. The pair is unique.
	DependentSecretID uint      `gorm:"not null;uniqueIndex:idx_secret_dep_edge" json:"dependent_secret_id"`
	DependsOnSecretID uint      `gorm:"not null;uniqueIndex:idx_secret_dep_edge" json:"depends_on_secret_id"`
	Note              string    `json:"note,omitempty"`
	CreatedBy         uint      `json:"created_by,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// SecretTemplate is a reusable metadata preset for secret creation.
// Applying a template pre-fills classification, tags, and description on new secrets.
type SecretTemplate struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `gorm:"not null;uniqueIndex" json:"name"`
	// Description is a human-readable note about what this template is for.
	Description string `json:"description,omitempty"`
	// DefaultClassification pre-fills the secret's classification level.
	DefaultClassification string `json:"default_classification,omitempty"`
	// DefaultTags is a comma-separated list of tag names to apply.
	DefaultTags string `json:"default_tags,omitempty"`
	// DescriptionPattern is a freetext hint for the description field.
	DescriptionPattern string `json:"description_pattern,omitempty"`
	// RotationHintDays suggests a rotation interval in days (informational only).
	RotationHintDays int       `json:"rotation_hint_days,omitempty"`
	CreatedBy        uint      `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// SecretACL grants a specific user fine-grained access to one secret (RBAC Phase 3).
// When a SecretACL entry exists for (UserID, SecretID), the listed Permissions are
// granted regardless of project-level RBAC — the user need not hold a project role.
// ACL management requires secrets.manage at project scope.
type SecretACL struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	SecretID    uint   `gorm:"uniqueIndex:idx_secret_acl_user;not null" json:"secret_id"`
	UserID      uint   `gorm:"uniqueIndex:idx_secret_acl_user;not null" json:"user_id"`
	Permissions string `gorm:"type:text;not null" json:"permissions"` // JSON []string, e.g. ["secrets.read"]
	GrantedBy   uint   `gorm:"not null" json:"granted_by"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SecretAccessSchedule enforces temporal read-access controls on a secret.
// A secret with a schedule is readable ONLY during the allowed window.
// Days uses ISO weekday numbers: 1=Mon, 2=Tue, ..., 7=Sun. "*" = all days.
type SecretAccessSchedule struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	SecretNodeID uint      `gorm:"uniqueIndex;not null" json:"secret_node_id"`
	// AllowedDays is a comma-separated ISO weekday list, e.g. "1,2,3,4,5" or "*"
	AllowedDays string    `json:"allowed_days"`
	StartHour   int       `json:"start_hour"` // 0–23 inclusive
	EndHour     int       `json:"end_hour"`   // 1–24; EndHour > StartHour
	Timezone    string    `json:"timezone"`   // IANA, e.g. "UTC" or "America/New_York"
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type SecretVersion struct {
	ID                 uint `gorm:"primaryKey"`
	SecretNodeID       uint
	VersionNumber      int
	EncryptedValue     []byte `json:"-"`
	EncryptionMetadata JSON   `json:"-"`
	ReadCount          int
	CreatedAt          time.Time
}

// DynamicSecretConfig (ADR-035) defines an on-demand database-credential source:
// Keyorix connects to the target with the (encrypted) admin DSN and runs the
// creation template to mint a short-lived role per lease. One per (project, env,
// name) — enforced by a unique index on (project_id, environment_id, name)
// created in migrateDatabase (#462), not a `uniqueIndex` struct tag here: this
// table is never fully re-AutoMigrated once it exists (same pgx hazard as
// elsewhere in migrateDatabase), so a struct tag alone would never reach an
// existing database.
type DynamicSecretConfig struct {
	ID            uint   `gorm:"primaryKey"`
	Name          string `gorm:"not null"`
	ProjectID     uint   `gorm:"index"`
	EnvironmentID uint
	BackendType   string // "postgres"
	AdminDSNEnc   []byte `json:"-"` // encrypted admin connection string (never returned in API responses)
	AdminDSNMeta  []byte `json:"-"`
	// CreationTemplate is operator-authored SQL run after the role is created,
	// with {{name}} substituted by the generated (sanitized) role name. e.g.
	// "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};"
	CreationTemplate  string
	DefaultTTLSeconds int
	// MaxTTLSeconds caps the lifetime of any lease from this config (issue + all
	// renewals), regardless of the TTL a caller requests. 0 = no ceiling.
	MaxTTLSeconds int
	// MaxActiveLeases caps how many leases from this config may be active at once, so a
	// caller can't mint unbounded real DB roles/users (resource exhaustion on the target).
	// 0 = no ceiling.
	MaxActiveLeases int
	// Classification is the data-sensitivity label of the credentials this config
	// mints (ISO 27001 A.5.12/A.5.13): "" = unclassified, else one of
	// public|internal|confidential|restricted. Folds into the classification posture
	// so dynamic credentials are covered alongside static secrets.
	// LABEL ONLY, NOT A CONTROL — see internal/core/classification.go.
	Classification string `gorm:"index"`
	// Disabled refuses new IssueLease calls against this config (#369). Set
	// automatically when the owning project is soft-deleted (DeleteProject's
	// cascade), so a principal who still holds a role scoped to the "deleted"
	// project cannot keep minting fresh database credentials against it. Not
	// cleared automatically by RestoreProject — re-enabling a dynamic-secret
	// config (which can mint live database credentials) is a higher-consequence
	// action than restoring a static secret, so it requires an explicit,
	// deliberate re-enable rather than silently resurrecting with the project.
	Disabled  bool `gorm:"default:false"`
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DynamicSecretLease is one issued credential: a short-lived role on the target
// database. The issued credential is stored encrypted; status drives the
// auto-revoke sweep (active → revoked/expired/revoke_failed).
type DynamicSecretLease struct {
	ID             uint   `gorm:"primaryKey"`
	ConfigID       uint   `gorm:"index"`
	LeaseID        string `gorm:"uniqueIndex"` // opaque public identifier
	ProjectID      uint   // denormalized so the scope resolver/sweep avoid a join
	EnvironmentID  uint
	RoleName       string // the generated role/username on the target DB
	CredentialEnc  []byte `json:"-"` // encrypted issued credential (username/password JSON)
	CredentialMeta []byte `json:"-"`
	Status         string `gorm:"index:idx_lease_status_expiry"` // active | revoked | expired | revoke_failed
	RevokeReason   string
	RevokeError    string
	IssuedAt       time.Time
	ExpiresAt      time.Time `gorm:"index:idx_lease_status_expiry"`
	RevokedAt      *time.Time
}

type SecretAccessLog struct {
	ID              uint `gorm:"primaryKey"`
	SecretNodeID    uint
	SecretVersionID uint
	AccessedBy      string
	AccessTime      time.Time
	Action          string
	IPAddress       string
	UserAgent       string
}

type SecretMetadataHistory struct {
	ID           uint `gorm:"primaryKey"`
	SecretNodeID uint
	ChangedBy    string
	ChangeTime   time.Time
	OldMetadata  JSON
	NewMetadata  JSON
}

type Session struct {
	ID                    uint `gorm:"primaryKey"`
	UserID                uint
	SessionToken          string     `gorm:"unique" json:"-"` // SHA-256 hash of the session token (never plaintext)
	EncryptedSessionToken []byte     `json:"-"`
	SessionTokenMetadata  JSON       `json:"-"`
	UserAgent             string     // captured at login, for the My Account "active sessions" view
	IPAddress             string     // captured at login
	LastSeenAt            *time.Time // throttled — updated at most once per validTokenTTL on the auth slow path
	CreatedAt             time.Time
	ExpiresAt             *time.Time // short-lived access window; RefreshSession rotates the token and extends this

	// AbsoluteExpiresAt is the hard ceiling on total session lifetime. It is set
	// once at login and carried unchanged through every refresh, so refreshing the
	// access window can never extend a session past it — re-authentication is
	// required once it lapses. nil = no ceiling (refreshable indefinitely).
	AbsoluteExpiresAt *time.Time

	// Impersonation: when an admin impersonates another user, a separate session
	// is issued for the target user with ImpersonatedBy set to the admin's ID and
	// ImpersonationStartedAt stamped. The admin's own session is left intact so the
	// frontend can swap back without re-authentication. nil = ordinary session.
	ImpersonatedBy         *uint
	ImpersonationStartedAt *time.Time

	// FamilyID links every session descended from the same login through each
	// refresh-token rotation (#211): stamped once at mintSession and carried
	// unchanged onto every session RefreshSession rotates it into. Lets a detected
	// refresh-token-reuse event revoke the WHOLE lineage in one shot (standard
	// OAuth refresh-token-family revocation), not just the one row that was
	// replayed. Empty on legacy rows minted before this field existed.
	FamilyID string `gorm:"index"`

	// RotatedAt marks this row superseded by RefreshSession — a soft, not hard,
	// delete. Keeping the row instead of deleting it immediately lets a replay of
	// this now-stale token be told apart from an ordinary "never existed" /
	// already-swept-up-by-expiry lookup, which is the standard refresh-token-reuse
	// detection signal. nil = still the live session for its token. GetSession
	// excludes rotated rows (a rotated token must authenticate nothing); only the
	// refresh path's reuse-detection lookup (GetSessionAny) sees them. Rotated rows
	// are still swept up by CleanupExpiredSessions once their (unextended) ExpiresAt
	// passes, so they don't accumulate indefinitely.
	RotatedAt *time.Time
}

// PersonalAccessToken is a long-lived, user-owned bearer credential (ADR-027).
// Unlike APIToken (service-account / admin-scoped), a PAT is created and managed
// by the owning user from the My Account page and authenticates API requests AS
// that user — inheriting their full permission set. The raw token is shown once
// on creation; only its SHA-256 hash is stored, enabling an indexed O(1) lookup
// on the auth hot path. Raw tokens carry the `kx_pat_` prefix.
type PersonalAccessToken struct {
	ID          uint   `gorm:"primaryKey"`
	UserID      uint   `gorm:"index;not null"`
	Name        string `gorm:"not null"`                      // user-facing label
	TokenHash   string `gorm:"uniqueIndex;not null" json:"-"` // SHA-256 hex of the raw token (never the plaintext)
	TokenPrefix string `gorm:"index"`                         // leading chars of the raw token, for display ("kx_pat_ab12…")
	// Scopes is a JSON-encoded []string permission allowlist (ADR-042). Empty/null =
	// the token inherits the owner's full permission set (legacy v1 behaviour, the
	// default for existing rows). When non-empty, the token may exercise ONLY the
	// listed permissions — and even then never more than the owner actually holds at
	// request time (it is a filter that narrows, never an escalation).
	Scopes string `gorm:"type:text"`
	// ProjectScope, when non-zero, restricts the token to acting within that single
	// project's scope (and denies global/system-wide actions). 0 = any scope the
	// owner can reach. Mirrors the 0 = global sentinel used throughout RBAC.
	ProjectScope uint `gorm:"default:0"`
	// EnvironmentScope, when non-zero, further confines the token to a single
	// environment (ADR-042). 0 = any environment. Environment ids are globally
	// unique, so this also pins the project.
	EnvironmentScope uint `gorm:"default:0"`
	// AllowedCIDRs is a JSON-encoded []string of CIDR blocks the token may be used from
	// (e.g. ["10.0.0.0/8","192.0.2.4/32"]). Empty/null = no network restriction (the
	// default). When set, a request presenting this token from a source IP outside every
	// listed CIDR is denied — a stolen token is useless off the allowed network.
	AllowedCIDRs string `gorm:"type:text"`
	LastUsedAt   *time.Time
	ExpiresAt    *time.Time // nil = never expires
	Revoked      bool       `gorm:"default:false"`
	CreatedAt    time.Time
}

// SetupToken is the single-use, hashed-at-rest bearer string that lets a brand-new
// principal establish their first credential (ADR-028). It backs three producers —
// invitation acceptance (ADR-024), admin-direct account setup (ADR-025), and the
// reset-link path — selected by Purpose. The plaintext is shown exactly once (in a
// link or out-of-band display) and never persisted; only TokenHash (SHA-256 hex) is
// stored, and lookup is by hash, mirroring PersonalAccessToken.
type SetupToken struct {
	ID        uint   `gorm:"primaryKey"`
	TokenHash string `gorm:"uniqueIndex;not null" json:"-"` // SHA-256 hex of the raw token (never the plaintext)

	// Purpose scopes the token: invitation_accept | account_setup | password_reset_link.
	// A token minted for one purpose can never drive another, even if the raw string
	// leaked into the wrong endpoint.
	Purpose string `gorm:"index;not null"`

	// SubjectUserID is the account the token establishes a credential for. Nullable:
	// an invitation issued to an email has no user row until acceptance materializes one.
	SubjectUserID *uint `gorm:"index"`
	// SubjectEmail binds the token to the address it was minted for (acceptance checks it).
	SubjectEmail string `gorm:"index"`
	// InvitationID links back to the project_invitations row for purpose=invitation_accept.
	InvitationID *uint `gorm:"index"`

	// State: active | consumed | expired | superseded. Consuming is single-use
	// (active → consumed in the same txn that materializes the effect); reissuing for
	// the same (purpose, subject) supersedes the prior active token (active → superseded);
	// a lazy-expire check flips overdue active tokens to expired on read.
	State string `gorm:"index;not null;default:active"`

	ExpiresAt time.Time
	// CreatedBy is the admin/inviter who minted the token; 0 for self-service reset.
	CreatedBy  uint
	CreatedAt  time.Time
	ConsumedAt *time.Time // nil until consumed
}

type PasswordReset struct {
	ID             uint `gorm:"primaryKey"`
	UserID         uint
	Token          string `gorm:"unique" json:"-"` // password-reset token (legacy column)
	EncryptedToken []byte `json:"-"`
	TokenMetadata  JSON   `json:"-"`
	ExpiresAt      *time.Time
	CreatedAt      time.Time
}

type Tag struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"unique"`
}

type SecretTag struct {
	SecretNodeID uint `gorm:"primaryKey"`
	TagID        uint `gorm:"primaryKey"`
}

// NotificationSeverity is a coarse escalation ranking recorded on a standing
// reminder notification (#250). Reminder schedulers (expiry/rotation/license)
// compare a newly computed severity against the value recorded here on an
// existing unread notification of the same (user, type, project): the
// notification is escalated in place only when the new state is strictly
// more severe than what was originally recorded, so an unread standing
// reminder can't freeze forever at a stale, since-superseded severity while
// still suppressing re-notification when nothing has gotten worse.
type NotificationSeverity int

const (
	// NotificationSeverityNone is the default for notification types that don't
	// participate in escalation-aware dedup.
	NotificationSeverityNone NotificationSeverity = 0
	// NotificationSeverityWarning marks a "heads up" state, e.g. a secret
	// expiring soon, a rotation approaching its deadline, or a license
	// expiring soon.
	NotificationSeverityWarning NotificationSeverity = 1
	// NotificationSeverityCritical marks a materially worse state than
	// NotificationSeverityWarning, e.g. a secret that has actually expired, a
	// rotation that is now overdue, or a license that has actually expired.
	NotificationSeverityCritical NotificationSeverity = 2
)

// Notification is an in-app notification addressed to a single user (ADR-024).
// Surfaced via the header bell; delivery is in-app only (email/Slack is M3+).
type Notification struct {
	ID           uint `gorm:"primaryKey"`
	UserID       uint `gorm:"index"`
	SecretNodeID *uint
	ProjectID    *uint // optional project context for the event
	Type         string
	Title        string
	Message      string
	Link         string // optional in-app target, e.g. /projects/{id}
	// Severity records the escalation ranking at which this notification was
	// last created/updated (#250). Zero (NotificationSeverityNone) for
	// notification types that don't use escalation-aware dedup.
	Severity NotificationSeverity `gorm:"default:0"`
	IsRead   bool                 `gorm:"index"`
	CreatedAt    time.Time
}

type AuditEvent struct {
	ID           uint `gorm:"primaryKey"`
	EventType    string
	UserID       *uint
	SecretNodeID *uint
	ProjectID    *uint `gorm:"index"`
	IPAddress    string
	Description  string
	Success      *bool `gorm:"default:true"`
	EventTime    time.Time

	// Diff is a JSON object describing what changed on a mutation event (e.g.
	// secret.updated). It records before/after for non-sensitive metadata
	// (name, type, max_reads, expiration) and a {"changed":true} marker for the
	// secret value — never the plaintext value itself. Empty for non-diff events.
	Diff string `gorm:"type:text"`

	// Impersonation context (audit-design block). When an action is performed
	// inside an impersonation session, Impersonation is true, ImpersonatedBy is
	// the real admin who initiated impersonation, and ActingAs is the user whose
	// identity is being borrowed (== UserID for the action). All three are unset
	// on ordinary events, so a single `impersonation` boolean is the consistent
	// "is this impersonated?" signal across every row.
	ImpersonatedBy *uint
	ActingAs       *uint
	Impersonation  bool `gorm:"default:false"`

	// ActorType records whether the acting principal is a human user or a
	// non-human machine identity (ADR-023). It is "user" on every ordinary
	// event; the machine-token auth path (ADR-030) tags the request context so
	// every event under a machine session is stamped "machine_identity".
	// "system" marks events with no authenticated principal. Defaults to "user"
	// so legacy rows and back-compat writers read as human-actored.
	ActorType string `gorm:"default:user"`

	// Tamper-evidence hash chain (ADR-029). PrevHash is the EntryHash of the
	// immediately preceding chained event (a fixed genesis constant for the
	// first chained event); EntryHash is SHA256(canonical(fields) ‖ PrevHash).
	// Each entry binds its predecessor, so any modification/deletion/insertion
	// is detectable by re-walking the chain (see VerifyAuditChain). Both are
	// empty on legacy rows written before ADR-029 (an unchained prefix).
	PrevHash  string `gorm:"index"`
	EntryHash string `gorm:"index"`
}

// AuditCheckpoint is a signed notarisation of the audit hash-chain head
// (ADR-029). Signature is an HMAC over (ChainedEvents, HeadID, HeadHash,
// KeyVersion) keyed by a DEK-derived key the database/DBA does not hold, so a
// checkpoint cannot be forged from database access alone. Re-verifying the live
// chain against the latest signed checkpoint detects on-box tail-truncation or a
// genesis re-seed — which an unanchored re-walk of a self-consistent (shorter)
// chain cannot catch. Append-only: a new checkpoint is added each cycle, never
// updated.
type AuditCheckpoint struct {
	ID            uint   `gorm:"primaryKey" json:"id"`
	ChainedEvents int64  `json:"chained_events"`
	HeadID        uint   `json:"head_id"`
	HeadHash      string `json:"head_hash"`
	KeyVersion    string `json:"key_version"`
	Signature     string `gorm:"not null" json:"signature"` // hex HMAC-SHA256
	// External-notary anchor (ADR-029): an independent RFC 3161 timestamp over the
	// checkpoint's canonical bytes, proving it existed at AnchoredAt with a proof the
	// server cannot forge. Nil/empty when no notary is configured or the anchor call
	// failed (best-effort — an unanchored checkpoint is still a valid checkpoint).
	AnchorToken    []byte     `json:"anchor_token,omitempty"`    // opaque RFC 3161 TimeStampToken (DER)
	AnchoredAt     *time.Time `json:"anchored_at,omitempty"`     // the time the TSA asserts
	AnchorProvider string     `json:"anchor_provider,omitempty"` // e.g. "rfc3161:https://freetsa.org/tsr"
	CreatedAt      time.Time  `json:"created_at"`
}

type Setting struct {
	ID     uint `gorm:"primaryKey"`
	UserID *uint
	Key    string
	Value  string
}

type SystemMetadata struct {
	Key       string `gorm:"primaryKey"`
	Value     string
	UpdatedAt time.Time
}

// StatsSnapshot stores daily dashboard stat counts for trend calculation
type StatsSnapshot struct {
	ID                  uint `gorm:"primaryKey;autoIncrement"`
	UserID              uint `gorm:"index"`
	TotalSecrets        int64
	SharedSecrets       int
	SecretsSharedWithMe int
	SnapshotDate        time.Time `gorm:"index"`
	CreatedAt           time.Time
}

// DeploymentStatsSnapshot captures deployment-wide dashboard metrics once per
// UTC day so the next day's dashboard can show a trend vs the previous snapshot.
// Unlike StatsSnapshot (per-user secret counts), this is a singleton per day
// (no UserID field).
type DeploymentStatsSnapshot struct {
	ID             uint      `gorm:"primarykey"`
	ActiveUsers    int64     `json:"active_users"`
	AuditEvents30d int64     `json:"audit_events_30d"`
	SnapshotDate   time.Time `gorm:"index"` // UTC date (truncated to day)
	CreatedAt      time.Time
}

// HygieneTrendSnapshot captures one day's credential-hygiene counts for
// per-day trend queries (stale PATs, expired PATs, stale machine credentials).
// One row per UTC calendar day (SnapshotDate is truncated to midnight).
type HygieneTrendSnapshot struct {
	ID            uint      `gorm:"primarykey"`
	StalePATs     int       `json:"stale_pats"`     // non-revoked, active PATs unused > 30 days
	ExpiredPATs   int       `json:"expired_pats"`   // non-revoked PATs where ExpiresAt < now
	StaleMachines int       `json:"stale_machines"` // machine identities with no credential used in 30 days
	TotalPATs     int       `json:"total_pats"`
	TotalMachines int       `json:"total_machines"`
	SnapshotDate  time.Time `gorm:"uniqueIndex" json:"snapshot_date"` // UTC midnight
	CreatedAt     time.Time `json:"created_at"`
}

// CompliancePostureSnapshot captures daily deployment compliance posture counts
// for week-over-week trend computation.
type CompliancePostureSnapshot struct {
	ID               uint      `gorm:"primarykey"`
	TotalControls    int       `json:"total_controls"`    // total control areas evaluated
	PassedControls   int       `json:"passed_controls"`   // controls with no gaps
	FailedControls   int       `json:"failed_controls"`   // controls with gaps/failures
	DegradedControls int       `json:"degraded_controls"` // controls that couldn't be evaluated
	SnapshotDate     time.Time `json:"snapshot_date" gorm:"uniqueIndex"` // date only (UTC midnight)
	CreatedAt        time.Time `json:"created_at"`
}

type APIClient struct {
	ID                    uint `gorm:"primaryKey"`
	Name                  string
	Description           string
	ClientID              string `gorm:"unique"`
	ClientSecret          string `json:"-"` // SHA-256 hash of the client secret (never plaintext); the secret is shown once at creation
	EncryptedClientSecret []byte `json:"-"` // legacy/unused encrypt-at-rest column; creation now hashes into ClientSecret
	ClientSecretMetadata  JSON   `json:"-"`
	Scopes                string
	IsActive              bool
	CreatedAt             time.Time
}

type APIToken struct {
	ID             uint `gorm:"primaryKey"`
	ClientID       uint
	UserID         *uint
	Token          string `gorm:"unique" json:"-"` // SHA-256 hash of the token (never plaintext); the token is shown once at creation
	EncryptedToken []byte `json:"-"`               // legacy/unused encrypt-at-rest column; creation now hashes into Token
	TokenMetadata  JSON   `json:"-"`
	Scope          string
	Revoked        bool
	ExpiresAt      *time.Time
	CreatedAt      time.Time
}

type RateLimit struct {
	ID             uint `gorm:"primaryKey"`
	ClientID       uint
	Method         string
	LimitPerMinute int
	CreatedAt      time.Time
}

type APICallLog struct {
	ID         uint `gorm:"primaryKey"`
	ClientID   *uint
	UserID     *uint
	Method     string
	Path       string
	StatusCode int
	DurationMS int
	IPAddress  string
	UserAgent  string
	CreatedAt  time.Time
}

type ShareRecord struct {
	ID          uint   `gorm:"primaryKey"`
	SecretID    uint   `gorm:"index"`
	OwnerID     uint   `gorm:"index"`
	RecipientID uint   `gorm:"index"`
	IsGroup     bool   `gorm:"default:false"`
	Permission  string `gorm:"default:read"` // "read" or "write"
	// ExpiresAt makes a share time-bound (just-in-time secret access): nil = permanent;
	// otherwise the share stops authorizing the moment it passes and is swept by the
	// JIT expiry scheduler. The permission queries filter on it directly so an expired
	// share is denied immediately, before the sweep removes the row. Mirrors UserRole.ExpiresAt.
	ExpiresAt *time.Time `gorm:"index"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type GRPCService struct {
	Name        string `gorm:"primaryKey"`
	Version     string
	Description string
}

type IdentityProvider struct {
	ID        uint   `gorm:"primaryKey"`
	Name      string `gorm:"unique"`
	Type      string
	Config    string
	IsActive  bool
	CreatedAt time.Time
}

type ExternalIdentity struct {
	ID         uint `gorm:"primaryKey"`
	ProviderID uint
	UserID     uint
	ExternalID string
	Email      string
	Name       string
	Metadata   JSON
	LinkedAt   time.Time
}

type RotationPolicy struct {
	ID              uint   `gorm:"primaryKey"`
	Name            string `gorm:"not null"`
	Description     string
	Scope           string `gorm:"not null;default:'environment'"` // "project" or "environment"
	ProjectID       *uint  `gorm:"index"`
	EnvironmentID   *uint  `gorm:"index"`
	IntervalDays    int    `gorm:"not null"`
	AlertDaysBefore int    `gorm:"not null;default:7"`
	NotifyOnBreach  bool   `gorm:"not null;default:true"`
	IsActive        bool   `gorm:"not null;default:true"`
	CreatedBy       string `gorm:"not null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt `gorm:"index"`
}

// AnomalyAlert represents a detected anomaly in secret access patterns.
type AnomalyAlert struct {
	ID           uint `gorm:"primaryKey"`
	SecretNodeID uint `gorm:"index"`
	SecretName   string
	AlertType    string // off_hours, new_ip, frequency_spike, new_user, ml_outlier, principal_breadth
	Severity     string // low, medium, high
	Description  string
	AccessedBy   string
	IPAddress    string
	DetectedAt   time.Time `gorm:"index"`
	Acknowledged bool      `gorm:"default:false"`
	// AcknowledgedBy/AcknowledgedAt attribute WHO dismissed this alert and WHEN
	// (#217) — a privileged principal could otherwise suppress evidence of their
	// own malicious access with the acknowledged flag alone leaving no forensic
	// trail on the row itself (a separate audit event is also emitted, but the
	// row-level attribution lets the posture/digest surface it directly).
	AcknowledgedBy uint       `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	// Alerted is set once the anomaly has been pushed out (admin notification +
	// SIEM forward) so the alerter doesn't re-notify on every scan.
	Alerted   bool `gorm:"default:false;index"`
	CreatedAt time.Time
}

// AnomalyConfigRecord stores runtime-tunable anomaly detection parameters.
// Only one row exists (ID=1); use GetAnomalyConfig/SaveAnomalyConfig to manage it.
type AnomalyConfigRecord struct {
	ID uint `gorm:"primarykey"`
	// Lookback window for access-frequency baseline (default: 7 days)
	LookbackDays int `json:"lookback_days"`
	// Quarantine period before a new secret's first-read is flagged (default: 24h)
	QuarantineHours int `json:"quarantine_hours"`
	// Off-hours enforcement
	OffHoursEnabled  bool   `json:"off_hours_enabled"`
	OffHoursTimezone string `json:"off_hours_timezone"` // IANA tz
	OffHoursStart    int    `json:"off_hours_start"`    // 0–23
	OffHoursEnd      int    `json:"off_hours_end"`      // 0–23
	// ML Isolation Forest
	MLEnabled    bool    `json:"ml_enabled"`
	MLThreshold  float64 `json:"ml_threshold"`   // 0.5–1.0
	MLNumTrees   int     `json:"ml_num_trees"`
	MLSampleSize int     `json:"ml_sample_size"`
	UpdatedAt    time.Time `json:"updated_at"`
	UpdatedBy    string    `json:"updated_by"` // username of last editor
}

// MachineIdentity is a non-human project member (ADR-023): a CI runner, a
// Kubernetes workload, a service, or other automation. It carries its own
// lifecycle, separate from human users, so the Members view can segment the two.
// This is the identity record + lifecycle; its own token-based authentication
// (ADR-030) is MachineIdentityCredential below.
type MachineIdentity struct {
	ID           uint   `gorm:"primaryKey"`
	ProjectID    uint   `gorm:"index"`
	Name         string `gorm:"not null"`
	IdentityType string // ci | k8s | service | automation | other
	State        string // pending | active | suspended | revoked
	Description  string
	CreatedBy    uint
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastSeenAt   *time.Time
	RevokedAt    *time.Time
	// Classification is the data-sensitivity tier this machine identity handles
	// (ISO 27001 A.5.12): "" = unclassified, else public|internal|confidential|restricted.
	// LABEL ONLY, NOT A CONTROL — see internal/core/classification.go.
	Classification string `gorm:"index"`
}

// MachineIdentityCredential is an opaque bearer token a machine identity uses to
// authenticate (ADR-030), mirroring PersonalAccessToken. Only the SHA-256 hash
// is stored — the raw `kx_machine_…` token is shown once at issuance. A machine
// may hold several active credentials (rotation). A credential is usable only
// while un-revoked, unexpired, AND its machine identity is still `active`.
type MachineIdentityCredential struct {
	ID                uint   `gorm:"primaryKey"`
	MachineIdentityID uint   `gorm:"index;not null"`
	Name              string // operator-facing label
	TokenHash         string `gorm:"uniqueIndex;not null" json:"-"` // SHA-256 hex (never the plaintext)
	TokenPrefix       string `gorm:"index"`                         // leading chars for display ("kx_machine_ab12cd")
	LastUsedAt        *time.Time
	ExpiresAt         *time.Time // nil = never expires
	Revoked           bool       `gorm:"default:false"`
	CreatedAt         time.Time
	// Classification is the data-sensitivity tier of what this credential can reach
	// (ISO 27001 A.5.12): "" = unclassified, else public|internal|confidential|restricted.
	// LABEL ONLY, NOT A CONTROL — see internal/core/classification.go.
	Classification string `gorm:"index"`
}

// MachineIdentityRole grants a role to a machine identity at a project/
// environment scope (ADR-030), mirroring UserRole. 0 = global scope. Machine
// principals never receive an admin-role bypass, so a leaked machine token is
// bounded to the permissions of its granted roles.
type MachineIdentityRole struct {
	MachineIdentityID uint `gorm:"primaryKey"`
	RoleID            uint `gorm:"primaryKey"`
	ProjectID         uint `gorm:"primaryKey;not null;default:0"`
	EnvironmentID     uint `gorm:"primaryKey;not null;default:0"`
}

// MachineIdentityOIDCBinding maps an external token's (issuer, subject) to a
// machine identity (ADR-031), so a Kubernetes projected SA token or any OIDC JWT
// can authenticate as that machine. The (Issuer, Subject) pair is unique — one
// external principal maps to exactly one machine.
type MachineIdentityOIDCBinding struct {
	ID                uint   `gorm:"primaryKey"`
	MachineIdentityID uint   `gorm:"index;not null"`
	Issuer            string `gorm:"uniqueIndex:idx_oidc_iss_sub;not null"`
	Subject           string `gorm:"uniqueIndex:idx_oidc_iss_sub;not null"`
	CreatedBy         uint
	CreatedAt         time.Time
}

// TableName pins the table name. GORM does not treat "OIDC" as a known
// initialism, so its default pluralization would not match the explicit name
// used in the migration guard and the GetMachineByOIDCSubject join.
func (MachineIdentityOIDCBinding) TableName() string { return "machine_identity_oidc_bindings" }

// AlertEscalationPolicy defines when and how to escalate unacknowledged anomaly alerts.
// After EscalateAfterMinutes of no acknowledgement, alerts at or above MinSeverity
// are dispatched to the NotificationChannels listed in ChannelIDs.
type AlertEscalationPolicy struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `gorm:"not null;uniqueIndex" json:"name"`
	// MinSeverity: only escalate alerts at or above this severity ("low","medium","high","critical")
	MinSeverity string `json:"min_severity"`
	// EscalateAfterMinutes: escalate if alert unacknowledged for this many minutes
	EscalateAfterMinutes int `json:"escalate_after_minutes"`
	// ChannelIDs: comma-separated NotificationChannel IDs to deliver to
	ChannelIDs string    `json:"channel_ids"`
	Enabled    bool      `gorm:"default:true" json:"enabled"`
	CreatedBy  uint      `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// NotificationChannel is a runtime-managed outbound notification destination.
// Channel types: "webhook", "slack", "teams", "email".
type NotificationChannel struct {
	ID      uint   `gorm:"primarykey" json:"id"`
	Name    string `gorm:"uniqueIndex;not null" json:"name"`
	Type    string `gorm:"not null" json:"type"` // webhook|slack|teams|email
	Enabled bool   `gorm:"default:true" json:"enabled"`
	// URL is the webhook endpoint (for webhook/slack/teams types)
	URL string `json:"url,omitempty"`
	// Email is the recipient address (for email type)
	Email string `json:"email,omitempty"`
	// Events is a comma-separated list of event types this channel receives
	// e.g. "secret.rotated,anomaly.detected,secret.expiring"
	Events    string    `json:"events"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by"`
}

// ProjectMembership tracks the onboarding lifecycle of a user into a project
// (ADR-022), separate from the actual role grant (user_roles). It carries a
// 5-state machine: invited → identity_verified → provisioned → active, with
// revoked as a terminal state reachable from any non-terminal state. The role
// grant is applied only when the membership reaches active.
type ProjectMembership struct {
	ID        uint `gorm:"primaryKey"`
	ProjectID uint `gorm:"index"`
	UserID    uint `gorm:"index"`
	Role      string
	State     string // invited | identity_verified | provisioned | active | revoked
	// Uniqueness of a non-revoked membership per (project, user) is enforced by a
	// DB-level partial unique index (uniq_project_memberships_active, factory.go's
	// ensureProjectMembershipIndex, scoped to state <> 'revoked') so a revoked
	// membership can be followed by a fresh invite without a unique-index collision,
	// while two concurrent invites for the same (project, user) can't both commit a
	// row (#309). That index only dedupes this table, though — it says nothing about
	// the user_roles grant a membership is supposed to carry once active; see
	// KeyorixCore.revertFailedActivation for what happens when that grant fails
	// after this row already committed as active.
	InvitedBy   uint
	InvitedAt   time.Time
	ActivatedAt *time.Time
	RevokedAt   *time.Time
	UpdatedAt   time.Time
}

// SecretVersionComment is a free-text annotation on a specific secret version,
// providing a human-readable audit trail of why a version was created or changed.
type SecretVersionComment struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	VersionID uint      `gorm:"not null;index" json:"version_id"`
	SecretID  uint      `gorm:"not null;index" json:"secret_id"`
	UserID    uint      `gorm:"not null" json:"user_id"`
	Username  string    `gorm:"not null" json:"username"`
	Comment   string    `gorm:"not null" json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}
