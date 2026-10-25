package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SharingStore is the Storage slice for secret ACLs and share records.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type SharingStore interface {
	// Secret ACL (RBAC Phase 3) — per-secret fine-grained access grants.
	// A SecretACL row grants (UserID, SecretID, Permissions) independent of project RBAC.
	// Folder-level grants are inherited by descendant secrets via the ancestor walk in
	// HasSecretACL (uses GetSecretAncestors to climb the ParentID chain).
	CreateOrUpdateSecretACL(ctx context.Context, acl *models.SecretACL) error
	ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error)
	// ListSecretACLsByUser returns all ACL rows where user_id = userID, across all secrets.
	// Used by ListSecretsWithSharingInfo to surface secrets the user can access via explicit
	// per-secret/per-folder grants but does not own and has no ShareRecord for.
	ListSecretACLsByUser(ctx context.Context, userID uint) ([]*models.SecretACL, error)
	GetSecretACL(ctx context.Context, secretID, userID uint) (*models.SecretACL, error)
	DeleteSecretACL(ctx context.Context, id uint) error
	// DeleteSecretACLsByUserAndProject removes all ACL grants for userID on secrets
	// that belong to projectID. Called during project member removal so that a
	// revoked member's per-secret ACL grants do not survive offboarding (CWE-284).
	DeleteSecretACLsByUserAndProject(ctx context.Context, userID, projectID uint) error
	// GetSecretAncestors returns the ancestor SecretNode IDs for nodeID,
	// ordered from immediate parent to root (breadth-first up the ParentID
	// chain). Used by HasSecretACL to walk the folder ACL inheritance path.
	// Capped at 20 levels to guard against accidental circular ParentID
	// references in the data. LocalStorage climbs the chain via repeated
	// GetSecret calls.
	GetSecretAncestors(ctx context.Context, nodeID uint) ([]uint, error)

	// Secret Sharing Management
	CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error)
	// LockShareRecordForUpdate is GetShareRecord inside a WithTransaction, taking a
	// row-level write lock on backends that support one (Postgres: SELECT … FOR
	// UPDATE) so a decision made from the row and the write of it serialize against
	// every concurrent writer across replicas. On SQLite it is a plain read (write
	// transactions there are BEGIN IMMEDIATE). Use this — not GetShareRecord —
	// whenever a transaction classifies an update against the row it then writes
	// (core.UpdateSharePermission, SHARE-CAS-1). Outside a transaction it locks nothing.
	LockShareRecordForUpdate(ctx context.Context, shareID uint) (*models.ShareRecord, error)
	UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	DeleteShareRecord(ctx context.Context, shareID uint) error
	// now is the instant "currently active" is evaluated against (expires_at IS
	// NULL OR expires_at > now) -- an explicit parameter, not an internal
	// time.Now() read, so every caller of these seven methods sources it from
	// the SAME clock its own active-share check uses (KeyorixCore.shareEffectiveNow),
	// instead of this storage layer reading the real wall clock independently
	// (#1983 investigation finding: this was the one "split clock in series"
	// gap among the sharing methods -- see jit_access.go's shareEffectiveNow
	// callers for the production wiring). Mirrors DeleteExpiredShareRecords'
	// existing before time.Time parameter below, not a new mechanism.
	ListSharesBySecret(ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error)
	// ListSharesBySecretIDs is the batch form of ListSharesBySecret: currently-active
	// share records for every secret in secretIDs, in one query — used by the
	// rotation planner's risk-scoring batch (#409) instead of one ListSharesBySecret
	// call per candidate secret.
	ListSharesBySecretIDs(ctx context.Context, secretIDs []uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharesByUser(ctx context.Context, userID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharesByOwner(ctx context.Context, ownerID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharesByGroup(ctx context.Context, groupID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharedSecrets(ctx context.Context, userID uint, now time.Time) ([]*models.SecretNode, error)
	CheckSharePermission(ctx context.Context, secretID, userID uint, now time.Time) (string, error)
	// DeleteExpiredShareRecords removes time-bound shares whose ExpiresAt is non-NULL
	// and at or before the cutoff, returning the removed rows so the caller can audit
	// each expiry. Server-side only (run by the JIT expiry scheduler).
	DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error)
	// ReassignSecretShareOwner re-stamps ShareRecord.OwnerID to newOwnerID on EVERY row
	// of secretID — live, expired-unswept and soft-deleted (revoked) alike — and returns
	// how many rows it wrote (#3102). Only owner_id is written: permission, expires_at,
	// recipient and deleted_at are untouched, so no recipient's access changes and a
	// revoked share stays revoked. It exists for ONE caller, the ownership transfer
	// (core.transferOwnership), and MUST run in the same WithTransaction as the
	// secret's owner_id write: ShareRecord.OwnerID is the key of the owner-scoped share
	// lists while revoke/update are gated on owning the SECRET, so the two have to move
	// together. Every soft-deleted row is re-stamped too, so nothing that ever
	// resurrects a row can bring the previous owner back as the share's owner.
	ReassignSecretShareOwner(ctx context.Context, secretID, newOwnerID uint) (int64, error)
}
