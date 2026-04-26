package models

import (
	"time"
)

// SecretWithSharingInfo represents a secret with additional sharing information
type SecretWithSharingInfo struct {
	*SecretNode

	// Resolved catalog names (populated by the list handler)
	NamespaceName   string `json:"namespace_name,omitempty"`
	ZoneName        string `json:"zone_name,omitempty"`
	EnvironmentName string `json:"environment_name,omitempty"`

	// Sharing information
	IsShared       bool   `json:"is_shared"`
	IsOwnedByUser  bool   `json:"is_owned_by_user"`
	OwnerUsername  string `json:"owner_username,omitempty"`
	UserPermission string `json:"user_permission,omitempty"` // "read", "write", or empty if owned
	ShareCount     int    `json:"share_count"`               // Number of users/groups this secret is shared with

	// Additional metadata for shared secrets
	SharedAt *time.Time `json:"shared_at,omitempty"` // When this secret was shared with the current user
	SharedBy string     `json:"shared_by,omitempty"` // Who shared this secret with the current user

	// UI indicators
	SharingIndicators *SharingIndicators `json:"sharing_indicators,omitempty"`
}

// SecretListFilter extends the basic SecretFilter with sharing-specific options
type SecretListFilter struct {
	// Basic filters
	NamespaceID   *uint
	ZoneID        *uint
	EnvironmentID *uint
	Type          *string
	Tags          []string
	CreatedBy     *string
	CreatedAfter  *time.Time
	CreatedBefore *time.Time

	// Sharing filters
	ShowOwnedOnly  bool   // Show only secrets owned by the user
	ShowSharedOnly bool   // Show only secrets shared with the user
	Permission     string // Filter by permission level ("read", "write")
	SharedBy       string // Filter by who shared the secret

	// Pagination
	Page     int
	PageSize int

	// Sorting
	SortBy    string // "name", "created_at", "shared_at", "owner"
	SortOrder string // "asc", "desc"
}

// SecretListResponse represents the response for listing secrets with sharing information
type SecretListResponse struct {
	Secrets    []*SecretWithSharingInfo `json:"secrets"`
	Total      int64                    `json:"total"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"page_size"`
	TotalPages int                      `json:"total_pages"`

	// Summary information
	OwnedCount  int `json:"owned_count"`
	SharedCount int `json:"shared_count"`
}

// SharingStatus represents the sharing status of a secret
type SharingStatus struct {
	IsShared   bool            `json:"is_shared"`
	ShareCount int             `json:"share_count"`
	Shares     []*ShareSummary `json:"shares,omitempty"`
}

// SharingStatusWithIndicators represents the sharing status with UI indicators
type SharingStatusWithIndicators struct {
	IsShared          bool               `json:"is_shared"`
	ShareCount        int                `json:"share_count"`
	IsOwner           bool               `json:"is_owner"`
	UserPermission    string             `json:"user_permission"`
	Shares            []*ShareSummary    `json:"shares,omitempty"`
	SharingIndicators *SharingIndicators `json:"sharing_indicators,omitempty"`
}

// ShareSummary represents a summary of a share record
type ShareSummary struct {
	ID            uint      `json:"id"`
	RecipientID   uint      `json:"recipient_id"`
	RecipientName string    `json:"recipient_name"`
	IsGroup       bool      `json:"is_group"`
	Permission    string    `json:"permission"`
	SharedAt      time.Time `json:"shared_at"`
	SharedBy      string    `json:"shared_by"`
}

// UserSecretPermission represents a user's permission for a specific secret
type UserSecretPermission struct {
	SecretID   uint   `json:"secret_id"`
	UserID     uint   `json:"user_id"`
	Permission string `json:"permission"` // "owner", "read", "write"
	Source     string `json:"source"`     // "owner", "direct_share", "group_share"
	ShareID    *uint  `json:"share_id,omitempty"`
	GroupID    *uint  `json:"group_id,omitempty"`
}

// SharingIndicators provides UI-specific indicators for shared secrets
type SharingIndicators struct {
	// Visual indicators
	Icon       string `json:"icon"`        // Icon name for UI (e.g., "shared", "owned", "group")
	Badge      string `json:"badge"`       // Badge text (e.g., "SHARED", "OWNER", "READ-ONLY")
	BadgeColor string `json:"badge_color"` // Badge color (e.g., "blue", "green", "orange")
	StatusText string `json:"status_text"` // Human-readable status text

	// Permission indicators
	CanRead   bool `json:"can_read"`
	CanWrite  bool `json:"can_write"`
	CanShare  bool `json:"can_share"`
	CanDelete bool `json:"can_delete"`

	// Sharing details for tooltips/details
	ShareDetails *ShareDetails `json:"share_details,omitempty"`
}

// ShareDetails provides detailed sharing information for UI
type ShareDetails struct {
	TotalShares    int                `json:"total_shares"`
	DirectShares   int                `json:"direct_shares"`
	GroupShares    int                `json:"group_shares"`
	RecentShares   []*RecentShareInfo `json:"recent_shares,omitempty"`
	PermissionText string             `json:"permission_text"`
	ShareSummary   string             `json:"share_summary"` // e.g., "Shared with 3 users and 2 groups"
}

// RecentShareInfo provides information about recent shares for UI
type RecentShareInfo struct {
	RecipientName string    `json:"recipient_name"`
	RecipientType string    `json:"recipient_type"` // "user" or "group"
	Permission    string    `json:"permission"`
	SharedAt      time.Time `json:"shared_at"`
	IsRecent      bool      `json:"is_recent"` // Shared within last 7 days
}
