package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// DynamicStore is the Storage slice for dynamic secret configs and leases.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type DynamicStore interface {
	// Dynamic secrets (ADR-035).
	CreateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error)
	GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error)
	ListDynamicSecretConfigs(ctx context.Context, projectID, environmentID uint) ([]*models.DynamicSecretConfig, error)
	// SetDynamicSecretConfigAdminDSN writes ONLY a config's encrypted admin DSN
	// (admin_dsn_enc, admin_dsn_meta) and updated_at, never the rest of the row
	// (#2651). CreateDynamicSecretConfig's second write used a full-row Save (the
	// since-deleted UpdateDynamicSecretConfig) and wrote disabled=false back over a
	// concurrent DeleteProject's #369 disable. Returns an error when no row matched.
	SetDynamicSecretConfigAdminDSN(ctx context.Context, id uint, enc, meta []byte) error
	// SetDynamicSecretConfigClassification persists ONLY the classification
	// column (plus updated_at), and only if the row's CURRENT classification is
	// still fromClassification (the value the caller read). matched=false (no
	// error) means another classifier moved it; the caller must fail closed.
	//
	// ClassifyDynamicSecretConfig used a full-row Save (the since-deleted
	// UpdateDynamicSecretConfig) and therefore wrote `disabled=false` back over a concurrent
	// SetDynamicSecretConfigEnabled(false) — the incident kill switch, which
	// also revokes the config's live leases — so IssueLease could mint real
	// database credentials again, with an audit trail reading "config_disabled"
	// then only "classified" and nothing recording the re-enable (#2698). The
	// same column is what DeleteProject's #369 cascade sets, so the same write
	// also re-enabled a config under a deleted project.
	SetDynamicSecretConfigClassification(ctx context.Context, id uint, fromClassification, toClassification string, updatedAt time.Time) (matched bool, err error)
	// TransitionDynamicSecretConfigDisabled persists cfg's full row via a single
	// conditional write — "UPDATE ... WHERE id = ? AND disabled = ?" — succeeding
	// only if the row's CURRENT persisted disabled value still equals fromDisabled
	// (the value SetDynamicSecretConfigEnabled observed via GetDynamicSecretConfig
	// immediately before mutating cfg.Disabled in memory), mirroring
	// UpdateProjectInvitation's `WHERE id = ? AND state = 'pending'` pattern (#412)
	// and TransitionMachineIdentityState's `WHERE id = ? AND state = ?` pattern
	// (#388/#518) exactly, just gated on DynamicSecretConfig.Disabled instead of a
	// string state column. Returns whether the write actually matched a row.
	//
	// This exists for the same reason TransitionMachineIdentityState does: the
	// now-deleted RemoteStorage's WithTransaction was a no-op passthrough, so a
	// plain GetDynamicSecretConfig-then-full-row-Save sequence — the
	// shape SetDynamicSecretConfigEnabled used before this fix — had no atomicity
	// at all against it: two racing callers (e.g. one admin enabling while another
	// is mid-disable, or an unrelated concurrent edit landing between the read and
	// the write) could silently clobber each other's change, or clobber an
	// unrelated field mutated by the other racer, with no error surfaced. Routing
	// the actual write through this one conditional round trip instead of a
	// separate proxied Update restores the same guarantee LocalStorage's
	// conditional UPDATE already provides, without making any enable/disable
	// decision here: the caller (core.SetDynamicSecretConfigEnabled) still decides
	// the target Disabled value before calling this; a false match result must be
	// treated as a lost race, not retried or silently overwritten.
	TransitionDynamicSecretConfigDisabled(ctx context.Context, cfg *models.DynamicSecretConfig, fromDisabled bool) (bool, error)
	// CountDynamicSecretConfigsByClassification returns install-wide config counts
	// keyed by classification label ("" = unclassified) for the compliance posture.
	CountDynamicSecretConfigsByClassification(ctx context.Context) (map[string]int, error)
	CreateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) (*models.DynamicSecretLease, error)
	GetDynamicSecretLease(ctx context.Context, leaseID string) (*models.DynamicSecretLease, error)
	ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error)
	// CountActiveLeases returns how many leases from configID still hold a live
	// credential upstream — "active" AND "revoke_failed" (#411: a revoke_failed
	// lease's earlier revoke attempt failed on the target, so the credential is
	// still live) — used to enforce the config's MaxActiveLeases ceiling.
	CountActiveLeases(ctx context.Context, configID uint) (int64, error)
	// ExtendDynamicSecretLeaseExpiry persists ONLY expires_at, and only for a
	// lease whose status is STILL "active": "UPDATE ... SET expires_at WHERE
	// lease_id = ? AND status = 'active'". matched=false (no error) means the
	// lease is no longer active (revoked, expired, or revoke_failed) and the
	// renewal must be refused.
	//
	// RenewLease used the full-row UpdateDynamicSecretLease (a bare Save) and
	// therefore wrote the stale Status/RevokeError/RevokedAt back (#2698): a
	// concurrent successful RevokeLease became `active` again with a LATER
	// expiry, so the row lied about a dead credential and kept holding a
	// MaxActiveLeases slot until the sweep; a revoke that had recorded
	// `revoke_failed` was erased outright, its error cleared. Renew is a no-op
	// on several backends, so nothing downstream would have noticed.
	ExtendDynamicSecretLeaseExpiry(ctx context.Context, leaseID string, newExpiry time.Time) (matched bool, err error)
	// RecordDynamicSecretLeaseRevocation persists ONLY status, revoke_reason,
	// revoke_error and revoked_at. Deliberately NOT conditional on the current
	// status: it records what already happened to the credential at the
	// backend, so it must land regardless of what else moved meanwhile — a
	// lease whose target drop failed must never be left reading `active`.
	// What it must not do is carry the caller's whole pre-read row with it.
	RecordDynamicSecretLeaseRevocation(ctx context.Context, leaseID, status, revokeReason, revokeError string, revokedAt *time.Time) (matched bool, err error)
	ListExpiredActiveLeases(ctx context.Context, before time.Time) ([]*models.DynamicSecretLease, error)
}
