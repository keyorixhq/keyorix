// local_scheduler_lock_lease.go — the TTL-bounded distributed-mutex primitive
// backing RemoteStorage's WithSchedulerLock (#530): TryAcquireSchedulerLock and
// ReleaseSchedulerLock, both single-round-trip-atomic so they stay safe when
// called over HTTP by a storage.type: remote spoke (remote_scheduler_lock.go),
// where no transaction can span two separate requests.
//
// Deliberately independent of WithSchedulerLock/local_scheduler_lock.go's
// Postgres session advisory lock: that mechanism ties the lock's lifetime to a
// single pinned DB connection held for the exact duration of one in-process
// call, which cannot survive being split across an acquire request and a LATER
// release request (the connection would have to stay pinned, out of the pool,
// for however long the caller's fn takes — unbounded, and it would not
// auto-release on a crashed HTTP caller the way a dropped DB session does
// locally). A row-based lease with an explicit TTL sidesteps both problems: it
// needs no pinned connection between requests, it works identically on
// Postgres and SQLite (advisory locks are Postgres-only), and a crashed or
// network-partitioned holder self-heals once ExpiresAt passes rather than
// wedging the key forever — the same "never permanently blocks a legitimate
// re-acquire" safety property the local advisory lock gets for free from
// Postgres closing the session.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// TryAcquireSchedulerLock attempts, in one transaction (so the read-then-
// decide-then-write below is atomic against a concurrent attempt on the same
// key — including on Postgres, where the SELECT is taken under a row lock),
// to take or renew the named lock for holder.
//
//   - No row exists yet: insert one. A concurrent racer's insert can still slip
//     in between this transaction's own SELECT and INSERT; the primary key
//     (Key) turns that into a unique-constraint violation, caught below and
//     treated as "lost the race" rather than a hard error.
//   - A row exists, held by holder itself (not yet expired, or expired — either
//     way it's this holder's own lease): update ExpiresAt. This is the renewal/
//     heartbeat path RemoteStorage.WithSchedulerLock uses to extend the lease
//     while fn is still running, without needing a distinct "renew" method.
//   - A row exists, held by a DIFFERENT holder and not yet expired: acquired
//     stays false — the lock is genuinely contended.
//   - A row exists, held by a different holder but already expired: reclaim it
//     for the new holder (crash/partition self-heal).
func (ls *LocalStorage) TryAcquireSchedulerLock(ctx context.Context, key int64, holder string, ttl time.Duration) (bool, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	now := time.Now()
	expiresAt := now.Add(ttl)
	acquired := false
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var existing models.SchedulerLockLease
		err := q.Where("key = ?", key).Take(&existing).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if createErr := tx.Create(&models.SchedulerLockLease{Key: key, Holder: holder, ExpiresAt: expiresAt}).Error; createErr != nil {
				if isUniqueViolation(createErr) {
					return nil // lost the race to a concurrent first-time acquire; acquired stays false
				}
				return createErr
			}
			acquired = true
			return nil
		case err != nil:
			return err
		default:
			if existing.Holder != holder && existing.ExpiresAt.After(now) {
				return nil // held by someone else and not yet expired — genuinely contended
			}
			if updErr := tx.Model(&models.SchedulerLockLease{}).Where("key = ?", key).
				Updates(map[string]any{"holder": holder, "expires_at": expiresAt}).Error; updErr != nil {
				return updErr
			}
			acquired = true
			return nil
		}
	})
	if err != nil {
		return false, err
	}
	return acquired, nil
}

// ReleaseSchedulerLock deletes the lease row IFF it is still held by holder —
// see the Storage interface doc for why an ownership mismatch is a silent
// no-op rather than an error.
func (ls *LocalStorage) ReleaseSchedulerLock(ctx context.Context, key int64, holder string) error {
	return ls.db.WithContext(ctx).
		Where("key = ? AND holder = ?", key, holder).
		Delete(&models.SchedulerLockLease{}).Error
}
