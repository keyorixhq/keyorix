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
	Role                   string // intended project role
	State                  string // pending | accepted | revoked | expired
	InvitedBy              uint
	ValidationModeAtInvite string // snapshot of the install validation mode at invite time
	ExpiresAt              *time.Time
	CreatedAt              time.Time
	AcceptedAt             *time.Time
	RevokedAt              *time.Time
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
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"` // soft delete — set by DELETE /users/{id}, cleared by restore
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
	ExpiresAt             *time.Time

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

type Notification struct {
	ID           uint `gorm:"primaryKey"`
	UserID       uint
	SecretNodeID *uint
	Type         string
	Message      string
	IsRead       bool
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
