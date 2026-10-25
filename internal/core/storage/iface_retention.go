package storage

import (
	"context"
	"time"
)

// RetentionStore is the Storage slice for retention purges of soft-deleted and expired rows.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type RetentionStore interface {
	// PurgeDeleted*Before hard-delete soft-deleted rows whose deleted_at is
	// older than `before`, returning the number purged (ADR-032). Irreversible.
	PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error)
	PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error)
	PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error)
	PurgeDeletedSecretsBefore(ctx context.Context, before time.Time) (int64, error)
	// Delete*Before hard-delete compliance records past their retention window
	// (ISO A.5.33 / GDPR), returning the number removed. Unlike the soft-delete
	// purge these age out live records by a time column, never touch active rows,
	// and cascade to dependent rows where noted. Irreversible.
	// DeleteAnomalyAlertsBefore removes an anomaly alert when EITHER: it is
	// ALREADY-ACKNOWLEDGED and detected_at < ackBefore (the normal, short window —
	// an old but never-acknowledged alert is still a live, unreviewed signal and is
	// never purged by this clause alone); OR it is unacknowledged and detected_at <
	// unackCeiling, a separate and much more generous absolute-age safety net (#489)
	// so an alert nobody ever acknowledges cannot accumulate forever (disk
	// exhaustion / unbounded ListAnomalyAlerts scans). A zero time.Time for either
	// parameter disables that clause entirely (matches it against nothing).
	DeleteAnomalyAlertsBefore(ctx context.Context, ackBefore, unackCeiling time.Time) (int64, error)
	// DeleteClosedAccessReviewsBefore removes closed campaigns (closed_at < before)
	// and their snapshot items, returning (campaigns, items) removed.
	DeleteClosedAccessReviewsBefore(ctx context.Context, before time.Time) (campaigns int64, items int64, err error)
	// DeleteExpiredBreakGlassBefore reconciles any TTL-lapsed 'active' row to
	// 'expired' (without deleting it in the same pass -- see local_purge.go's
	// doc comment), then removes non-active activations (created_at < before).
	DeleteExpiredBreakGlassBefore(ctx context.Context, before time.Time) (int64, error)
	// DeleteResolvedAccessRequestsBefore removes terminal-state requests (resolved_at
	// < before) and their approval records, returning (requests, approvals) removed.
	DeleteResolvedAccessRequestsBefore(ctx context.Context, before time.Time) (requests int64, approvals int64, err error)
}
