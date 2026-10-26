package storage

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SecretFieldUpdate names the secret_nodes columns one operation owns, for
// UpdateSecretFields. A nil pointer means "do not write this column at all" —
// which is the whole point: it replaced a full-row GORM Save whose eight
// callers each silently reverted every column the others owned (#2695).
//
// The union of fields here is exactly what those callers legitimately change,
// and nothing more. Columns deliberately ABSENT, because no caller of this
// method owns them and a full-row write was how they got clobbered:
// `deleted_at` (DeleteSecret / RestoreSecret), `status` (TransitionSecretStatus),
// `read_count` (TryIncrementSecretNodeReadCount — a MaxReads budget),
// `auto_rotate` and the other rotation columns (UpdateSecretRotationConfig),
// `project_id` / `environment_id` / `is_secret`, and the certificate cache.
// Adding a field here is a decision about which operation may revert which
// other operation, not a mechanical convenience — say why in the commit.
//
// The four nullable columns use an explicit Set* flag rather than relying on a
// nil pointer, so "clear this column" is distinguishable from "leave it alone"
// and reads as the deliberate act it is at the call site.
type SecretFieldUpdate struct {
	Name           *string
	Description    *string
	Classification *string
	Type           *string
	OwnerID        *uint
	Metadata       *models.JSON
	UpdatedAt      *time.Time

	SetParentID bool
	ParentID    *uint // nil + SetParentID = move to root

	SetExpiration bool
	Expiration    *time.Time // nil + SetExpiration = clear the expiry

	SetMaxReads bool
	MaxReads    *int // nil + SetMaxReads = clear the read cap

	SetLastRotatedAt bool
	LastRotatedAt    *time.Time
}

// SecretFilter defines filtering options for secret queries
type SecretFilter struct {
	ProjectID     *uint
	EnvironmentID *uint
	Type          *string
	Tags          []string
	CreatedBy     *string
	// OwnerID, when set, restricts to secrets owned by that user (owner_id) — the
	// canonical ownership the permission model uses (CheckSecretPermission), as
	// opposed to the mutable created_by username string.
	OwnerID       *uint
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	// ExpiresBefore, when set, restricts to secrets with a non-null expiration
	// earlier than the given time (i.e. already expired or expiring before it).
	ExpiresBefore *time.Time
	// Classification, when set, restricts to secrets with that data-classification
	// label (A.5.12). Use the sentinel "unclassified" to match the empty label.
	Classification *string
	// ParentID, when set, restricts to secrets whose parent_id equals the given
	// value. Use to list the direct children of a folder node.
	ParentID *uint
	// Search, when set, restricts to secrets whose name contains the given
	// substring (case-insensitive). Uses LOWER/LIKE so it works on both SQLite
	// and PostgreSQL.
	Search *string
	// FolderOnly, when true, restricts to folder nodes (is_secret=false). Mutually
	// exclusive with listing only real secrets — callers set one or the other.
	FolderOnly bool
	Page       int
	PageSize   int
	// IncludeDeleted, when true, also returns soft-deleted secrets (ADR-033) —
	// for a restore UI. Default false: GORM auto-scopes deleted_at IS NULL.
	IncludeDeleted bool
	// DeletedOnly, when true, returns ONLY soft-deleted secrets (deleted_at IS NOT
	// NULL) — the recycle-bin / restore view. Implies reaching past GORM's
	// soft-delete scope. Takes precedence over IncludeDeleted.
	DeletedOnly bool
	// IsSecret, when set, restricts to nodes matching the given value:
	// true = actual secrets only, false = folder nodes only.
	// When nil, both secrets and folders are returned.
	IsSecret *bool
}

// SecretScheduleAndLatestVersion is GetSecretScheduleAndLatestVersion's result.
// Schedule is nil when the secret has no access schedule (no restriction, as
// GetSecretAccessSchedule's nil, nil). Exactly one of LatestVersion and
// LatestVersionErr is set; LatestVersionErr is the error GetLatestSecretVersion
// would have returned (wrapping ErrSecretVersionNotFound when there is none).
type SecretScheduleAndLatestVersion struct {
	Schedule         *models.SecretAccessSchedule
	LatestVersion    *models.SecretVersion
	LatestVersionErr error
}

// DriftSecretRow is one secret's drift-relevant projection: which environment it
// lives in, its name (the cross-environment key), its type, and whether it has
// an expiration / max-reads cap set. Used to build the per-key × per-environment
// presence matrix for cross-environment drift detection.
type DriftSecretRow struct {
	EnvironmentID uint
	Name          string
	Type          string
	HasExpiration bool
	HasMaxReads   bool
}

// SecretNameRow is one live secret's naming-conformance-relevant projection plus its
// project ID — the row shape ListLiveSecretNamesByProject returns for the
// deployment-wide naming-policy conformance scan (#416). Mirrors the fields
// SecretNameViolation already carries per-project, so the deployment-wide caller can
// build a DeploymentSecretNameViolation directly without a second lookup.
type SecretNameRow struct {
	ProjectID      uint
	ID             uint
	Name           string
	Type           string
	Classification string
	EnvironmentID  uint
}

// SecretUsageStat is one row of the most-accessed-secrets report.
type SecretUsageStat struct {
	SecretID      uint       `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	EnvironmentID uint       `json:"environment_id"`
	ReadCount     int64      `json:"read_count"`
	LastRead      *time.Time `json:"last_read"`
}
