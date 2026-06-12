package models

import (
	"time"

	"gorm.io/gorm"
)

type Project struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex;not null"`
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"` // soft delete
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
// The email/setup-link consumption (accept) is a follow-up; this record tracks
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

// AccessRequest is a user's request for a role in a project (ADR-024). State
// machine: pending → approved / rejected / withdrawn / expired. On approval the
// granted role (which may differ from the suggested one) is assigned at the
// project scope. No auto-approval.
type AccessRequest struct {
	ID            uint   `gorm:"primaryKey"`
	ProjectID     uint   `gorm:"index"`
	UserID        uint   `gorm:"index"`
	SuggestedRole string // role the requester asks for
	GrantedRole   string // role actually granted on approval
	State         string // pending | approved | rejected | withdrawn | expired
	Reason        string // requester's note, or the rejecter's reason
	ResolvedBy    uint
	ExpiresAt     *time.Time
	CreatedAt     time.Time
	ResolvedAt    *time.Time
}

type User struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"uniqueIndex;not null"`
	Email        string
	DisplayName  string
	PasswordHash string
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
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  gorm.DeletedAt `gorm:"index"` // soft delete — set by DELETE /users/{id}, cleared by restore
}

// MFASecret holds a user's TOTP shared secret, encrypted at rest. One row per
// user (UserID unique). Activated flips true on the first valid code at
// enrolment; a row with Activated=false is a pending enrolment not yet confirmed.
type MFASecret struct {
	ID         uint   `gorm:"primaryKey"`
	UserID     uint   `gorm:"uniqueIndex"`
	SecretEnc  []byte // encrypted TOTP secret (passthrough plaintext when encryption is disabled)
	SecretMeta []byte // encryption metadata (key version etc.)
	Activated  bool   `gorm:"default:false"`
	CreatedAt  time.Time
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
	TokenHash string `gorm:"uniqueIndex"`
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// PasswordHistory records prior password hashes per user so the policy can
// forbid reuse of the last N passwords (ADR-025 history_count). Only bcrypt
// hashes are stored — never plaintext.
type PasswordHistory struct {
	ID           uint `gorm:"primaryKey"`
	UserID       uint `gorm:"index"`
	PasswordHash string
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
}

type Group struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"unique;not null"`
	Description string
}

type UserGroup struct {
	UserID  uint `gorm:"primaryKey"`
	GroupID uint `gorm:"primaryKey"`
}

// GroupRole binds a group to a role at a scope. See UserRole for the
// 0 = global sentinel semantics of ProjectID/EnvironmentID.
type GroupRole struct {
	GroupID       uint `gorm:"primaryKey"`
	RoleID        uint `gorm:"primaryKey"`
	ProjectID     uint `gorm:"primaryKey;not null;default:0"`
	EnvironmentID uint `gorm:"primaryKey;not null;default:0"`
}

type SecretNode struct {
	ID            uint `gorm:"primaryKey"`
	ParentID      *uint
	ProjectID     uint
	EnvironmentID uint
	Name          string `gorm:"not null"`
	IsSecret      bool   `gorm:"default:false"`
	Type          string
	MaxReads      *int
	Expiration    *time.Time
	Metadata      JSON
	Status        string `gorm:"default:'active'"`
	CreatedBy     string
	OwnerID       uint `gorm:"index"`
	IsShared      bool `gorm:"default:false"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastRotatedAt *time.Time
	// DeletedAt enables soft delete (ADR-033). DELETE stamps it; restore clears
	// it; the purge scheduler hard-deletes rows past the retention window. GORM
	// auto-scopes `deleted_at IS NULL` on model-based queries — raw/Table/Joins
	// queries on secret_nodes must filter it explicitly.
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type SecretVersion struct {
	ID                 uint `gorm:"primaryKey"`
	SecretNodeID       uint
	VersionNumber      int
	EncryptedValue     []byte
	EncryptionMetadata JSON
	ReadCount          int
	CreatedAt          time.Time
}

// DynamicSecretConfig (ADR-035) defines an on-demand database-credential source:
// Keyorix connects to the target with the (encrypted) admin DSN and runs the
// creation template to mint a short-lived role per lease. One per (project, env,
// name).
type DynamicSecretConfig struct {
	ID            uint   `gorm:"primaryKey"`
	Name          string `gorm:"not null"`
	ProjectID     uint   `gorm:"index"`
	EnvironmentID uint
	BackendType   string // "postgres"
	AdminDSNEnc   []byte // encrypted admin connection string (never returned in API responses)
	AdminDSNMeta  []byte
	// CreationTemplate is operator-authored SQL run after the role is created,
	// with {{name}} substituted by the generated (sanitized) role name. e.g.
	// "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};"
	CreationTemplate string
	DefaultTTLSeconds int
	CreatedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
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
	CredentialEnc  []byte // encrypted issued credential (username/password JSON)
	CredentialMeta []byte
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
	SessionToken          string `gorm:"unique"` // Deprecated: use EncryptedSessionToken
	EncryptedSessionToken []byte
	SessionTokenMetadata  JSON
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
	Name        string `gorm:"not null"`             // user-facing label
	TokenHash   string `gorm:"uniqueIndex;not null"` // SHA-256 hex of the raw token (never the plaintext)
	TokenPrefix string `gorm:"index"`                // leading chars of the raw token, for display ("kx_pat_ab12…")
	LastUsedAt  *time.Time
	ExpiresAt   *time.Time // nil = never expires
	Revoked     bool       `gorm:"default:false"`
	CreatedAt   time.Time
}

// SetupToken is the single-use, hashed-at-rest bearer string that lets a brand-new
// principal establish their first credential (ADR-028). It backs three producers —
// invitation acceptance (ADR-024), admin-direct account setup (ADR-025), and the
// reset-link path — selected by Purpose. The plaintext is shown exactly once (in a
// link or out-of-band display) and never persisted; only TokenHash (SHA-256 hex) is
// stored, and lookup is by hash, mirroring PersonalAccessToken.
type SetupToken struct {
	ID        uint   `gorm:"primaryKey"`
	TokenHash string `gorm:"uniqueIndex;not null"` // SHA-256 hex of the raw token (never the plaintext)

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
	Token          string `gorm:"unique"` // Deprecated: use EncryptedToken
	EncryptedToken []byte
	TokenMetadata  JSON
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
	IsRead       bool   `gorm:"index"`
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
	// event; the (future) machine-token auth path tags the request context so
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

type APIClient struct {
	ID                    uint `gorm:"primaryKey"`
	Name                  string
	Description           string
	ClientID              string `gorm:"unique"`
	ClientSecret          string // Deprecated: use EncryptedClientSecret
	EncryptedClientSecret []byte
	ClientSecretMetadata  JSON
	Scopes                string
	IsActive              bool
	CreatedAt             time.Time
}

type APIToken struct {
	ID             uint `gorm:"primaryKey"`
	ClientID       uint
	UserID         *uint
	Token          string `gorm:"unique"` // Deprecated: use EncryptedToken
	EncryptedToken []byte
	TokenMetadata  JSON
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
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
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
	AlertType    string // off_hours, new_ip, frequency_spike, new_user
	Severity     string // low, medium, high
	Description  string
	AccessedBy   string
	IPAddress    string
	DetectedAt   time.Time `gorm:"index"`
	Acknowledged bool      `gorm:"default:false"`
	CreatedAt    time.Time
}

// MachineIdentity is a non-human project member (ADR-023): a CI runner, a
// Kubernetes workload, a service, or other automation. It carries its own
// lifecycle, separate from human users, so the Members view can segment the two.
// Authentication for a machine identity (its own token) is a follow-up; this is
// the identity record + lifecycle.
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
	TokenHash         string `gorm:"uniqueIndex;not null"` // SHA-256 hex (never the plaintext)
	TokenPrefix       string `gorm:"index"`                // leading chars for display ("kx_machine_ab12cd")
	LastUsedAt        *time.Time
	ExpiresAt         *time.Time // nil = never expires
	Revoked           bool       `gorm:"default:false"`
	CreatedAt         time.Time
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
	// Uniqueness of a non-revoked membership per (project, user) is enforced in
	// core (see InviteMember), not by a DB constraint — so a revoked membership
	// can be followed by a fresh invite without a unique-index collision.
	InvitedBy   uint
	InvitedAt   time.Time
	ActivatedAt *time.Time
	RevokedAt   *time.Time
	UpdatedAt   time.Time
}
