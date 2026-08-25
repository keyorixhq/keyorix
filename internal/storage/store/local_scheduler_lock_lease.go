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
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// TryAcquireSchedulerLock attempts, in one transaction, to take or renew the
// named lock for holder.
//
//   - No row exists yet: the unconditional INSERT ... ON CONFLICT DO NOTHING
//     below either creates it outright (RowsAffected == 1, we won), or a
//     concurrent racer's insert won the conflict first (RowsAffected == 0) and
//     execution falls through to the read-and-decide path below, exactly as
//     if the row had already existed.
//   - A row exists, held by holder itself (not yet expired, or expired — either
//     way it's this holder's own lease): update ExpiresAt. This is the renewal/
//     heartbeat path RemoteStorage.WithSchedulerLock uses to extend the lease
//     while fn is still running, without needing a distinct "renew" method.
//   - A row exists, held by a DIFFERENT holder and not yet expired: acquired
//     stays false — the lock is genuinely contended.
//   - A row exists, held by a different holder but already expired: reclaim it
//     for the new holder (crash/partition self-heal).
//
// This deliberately PREVENTS the concurrent-first-insert conflict via
// ON CONFLICT DO NOTHING rather than catching a unique-constraint violation
// after the fact (the prior shape here): on Postgres, once an INSERT inside a
// transaction raises a unique-constraint violation, the ENTIRE transaction is
// aborted at the protocol level — no further statement can run, and GORM's
// subsequent COMMIT is silently downgraded to a ROLLBACK by the server. A Go
// `if isUniqueViolation(err) { return nil }` never gets a chance to matter: by
// the time it runs, the transaction is already unusable, and the caller sees
// a confusing "commit unexpectedly resulted in rollback" instead of the
// intended (false, nil) "someone else won". ON CONFLICT DO NOTHING never
// raises an error in the first place, so there is nothing to catch and no
// transaction to abort — the race becomes a non-event instead of an error to
// recover from. Confirmed fixed against real Postgres (this campaign's
// report); ON CONFLICT DO NOTHING is also GORM's standard driver-agnostic
// idiom (see CreateBreakGlassActivation, local_break_glass.go, for the same
// shape), so this is unchanged, not newly risky, on SQLite.
func (ls *LocalStorage) TryAcquireSchedulerLock(ctx context.Context, key int64, holder string, ttl time.Duration) (bool, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	now := time.Now()
	expiresAt := now.Add(ttl)
	acquired := false
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&models.SchedulerLockLease{Key: key, Holder: holder, ExpiresAt: expiresAt})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 1 {
			acquired = true
			return nil
		}

		// The row already existed — either from before this call, or a
		// concurrent racer's insert won the conflict above. Read it (under
		// FOR UPDATE on Postgres, so this decision serializes against a
		// concurrent renew/reclaim on the same key) and decide.
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var existing models.SchedulerLockLease
		if err := q.Where("key = ?", key).Take(&existing).Error; err != nil {
			return err
		}
		if existing.Holder != holder && existing.ExpiresAt.After(now) {
			return nil // held by someone else and not yet expired — genuinely contended
		}
		if updErr := tx.Model(&models.SchedulerLockLease{}).Where("key = ?", key).
			Updates(map[string]any{"holder": holder, "expires_at": expiresAt}).Error; updErr != nil {
			return updErr
		}
		acquired = true
		return nil
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
