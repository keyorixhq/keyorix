package models

import (
	"time"

	"gorm.io/gorm"
)

type Namespace struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"unique;not null"`
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Zone struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"unique;not null"`
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Environment struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"unique;not null"`
}

type User struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"uniqueIndex;not null"`
	Email        string
	DisplayName  string
	PasswordHash string
	IsActive     bool `gorm:"default:true"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"` // soft delete — set by DELETE /users/{id}, cleared by restore
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

type UserRole struct {
	UserID      uint `gorm:"primaryKey"`
	RoleID      uint `gorm:"primaryKey"`
	NamespaceID *uint
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

type GroupRole struct {
	GroupID     uint `gorm:"primaryKey"`
	RoleID      uint `gorm:"primaryKey"`
	NamespaceID *uint
}

type SecretNode struct {
	ID            uint `gorm:"primaryKey"`
	ParentID      *uint
	NamespaceID   uint
	ZoneID        uint
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
	CreatedAt             time.Time
	ExpiresAt             *time.Time
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
	Description  string
	EventTime    time.Time
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
