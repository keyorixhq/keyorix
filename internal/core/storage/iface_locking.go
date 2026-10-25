package storage

import (
	"context"
	"time"
)

// LockingStore is the Storage slice for scheduler/bootstrap/named locks, transactions and the live-project row lock.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type LockingStore interface {
	// WithSchedulerLock runs fn only if this process can take the named scheduler
	// lock, so a background job runs on a single replica at a time (HA, ADR-039).
	// On PostgreSQL it uses a session advisory lock (pg_try_advisory_lock); on
	// SQLite (single instance) fn always runs. Returns ran=false (and nil error)
	// when another replica holds the lock — the caller should simply skip this tick.
	//
	// fn (here and in WithAuditCheckpointLock, WithBootstrapLock and
	// WithNamedLock) must run under the ctx it is passed, not one it closed
	// over: on PostgreSQL that ctx is cancelled with cause
	// store.ErrAdvisoryLockLost when the lock's connection dies while fn runs
	// (the lock is gone and another replica may take it), and the call then
	// returns that error joined with fn's own.
	WithSchedulerLock(ctx context.Context, key int64, fn func(ctx context.Context) error) (ran bool, err error)

	// TryAcquireSchedulerLock and ReleaseSchedulerLock (#530) are the two
	// building blocks WithSchedulerLock is composed from. They exist as their
	// own Storage methods (rather than being private to one implementation)
	// because RemoteStorage's now-deleted WithSchedulerLock had to acquire, run
	// fn locally against itself (which could in turn make its own further
	// proxied calls), and release as two separate HTTP round trips — a real
	// cross-process transaction could not span the acquire and release the way
	// LocalStorage's single in-process call does, so each half had to be
	// independently atomic and safely idempotent. LocalStorage still keeps the
	// same two-method split even with RemoteStorage gone.
	//
	// TryAcquireSchedulerLock atomically attempts to take (or renew, if holder
	// already owns it) the named lock for ttl, in ONE round trip: acquired=true
	// only when this holder now owns it (a fresh acquire, a reclaim of an
	// expired lease, or a renewal of its own still-held lease); acquired=false
	// when a DIFFERENT holder's lease has not yet expired. Calling it again with
	// the SAME holder before ExpiresAt is therefore a safe heartbeat/renewal,
	// not a new acquisition attempt.
	TryAcquireSchedulerLock(ctx context.Context, key int64, holder string, ttl time.Duration) (acquired bool, err error)

	// ReleaseSchedulerLock releases the named lock IFF it is still held by
	// holder — a conditional delete, never a bare unconditional one, so a
	// holder whose lease already expired (and was possibly reclaimed by a
	// different holder in the meantime) can never clobber that newer holder's
	// lease. A release for a lock this holder does not (or no longer) own is a
	// silent no-op, not an error — mirroring ConsumeSSOLoginState's
	// already-consumed-is-not-an-error stance for the same reason: the caller's
	// own crashed-holder safety net is ExpiresAt, not a hard release
	// requirement.
	ReleaseSchedulerLock(ctx context.Context, key int64, holder string) error

	// WithAuditCheckpointLock serializes the audit-checkpoint chain-walk + decide +
	// create-checkpoint sequence (ADR-029) across every trigger — the scheduler tick,
	// the HTTP POST /api/v1/audit/checkpoint endpoint, and the gRPC
	// WriteAuditCheckpoint RPC — even when they land on different replicas (ADR-039
	// HA). Unlike WithSchedulerLock, this BLOCKS until the lock is free rather than
	// skipping on contention: every caller must actually run its checkpoint decision
	// against a consistent, serialized view, not silently no-op (#300). On PostgreSQL
	// it holds a session advisory lock (pg_advisory_lock) for the duration of fn; on
	// SQLite (single instance, no cross-process concern) a process mutex is enough.
	WithAuditCheckpointLock(ctx context.Context, fn func(ctx context.Context) error) error

	// WithBootstrapLock serializes BootstrapSystem's whole "is this a fresh
	// install" check through admin/RBAC/project seeding (auth_bootstrap.go) across
	// every replica of an HA deployment (ADR-039), mirroring WithAuditCheckpointLock's
	// mutex+advisory-lock design: an in-process mutex alone only serializes callers
	// within ONE server, so two different replicas racing POST /system/init could
	// both observe "not yet initialised" before either's commit is visible to the
	// other and each independently seed a "first admin" (double-seed / partial-RBAC
	// corruption). This BLOCKS until the lock is free, same as
	// WithAuditCheckpointLock: a losing replica must actually re-check under the
	// lock and observe the winner's now-committed state, not silently skip. On
	// PostgreSQL it holds a session advisory lock (pg_advisory_lock) for the
	// duration of fn; on SQLite (single instance, no cross-process concern) a
	// process mutex is enough.
	WithBootstrapLock(ctx context.Context, fn func(ctx context.Context) error) error

	// WithNamedLock serializes fn against every OTHER caller using the identical
	// lockKey, across replicas of an HA deployment (ADR-039) -- the general-purpose
	// form of WithAuditCheckpointLock/WithBootstrapLock's dedicated-mutex pattern,
	// for check-then-act invariants that don't warrant their own bespoke method
	// (#1646: the separation-of-duties preventive gate, the last-project-admin
	// guard, and the last-global-admin guard were each previously serialized by
	// an in-process KeyorixCore-level sync.Mutex ONLY -- meaning two independent
	// replicas of a real multi-instance Postgres deployment were never
	// serialized against each other at all, reproduced live for the SoD case).
	// On PostgreSQL it holds a session advisory lock (pg_advisory_lock) keyed by
	// a hash of lockKey for the duration of fn; on SQLite (single instance, no
	// cross-process concern) a single shared process mutex is enough. This
	// BLOCKS until the lock is free, same as WithAuditCheckpointLock/
	// WithBootstrapLock: a losing caller must actually re-check under the lock
	// and observe the winner's now-committed state, not silently skip.
	//
	// fn receives the lock-marked context. A caller that itself calls
	// WithNamedLock again (directly or transitively) MUST pass this ctx through,
	// not whatever ctx it closed over -- otherwise the reentrancy marker is lost
	// and a nested call self-deadlocks (see store.namedLockHeldCtxKey).
	WithNamedLock(ctx context.Context, lockKey string, fn func(ctx context.Context) error) error

	// WithTransaction runs fn inside a single storage transaction: every mutation fn
	// performs through the provided Storage commits together, or rolls back together if
	// fn returns an error. LocalStorage opens a real DB transaction and hands fn a
	// transaction-scoped Storage. (The now-deleted RemoteStorage instead ran fn directly
	// against itself as a no-op passthrough, since each proxied HTTP call was already
	// atomic server-side and there was no client-side transaction to open — several
	// comments elsewhere in this file still explain invariants shaped by that
	// constraint.) Use it for multi-step mutations that must not half-apply (e.g. a
	// suspend + delete pair).
	WithTransaction(ctx context.Context, fn func(Storage) error) error

	// LockLiveProject re-reads project projectID and reports whether it is still
	// live (not soft-deleted). On Postgres it takes SELECT ... FOR SHARE on that
	// row, so it serializes against DeleteProject's cascade, which row-locks the
	// project FOR UPDATE before it sweeps any child (#2656).
	//
	// It is ONLY meaningful on a transaction-scoped Storage — the handle
	// WithTransaction hands fn — and only when called AFTER the child write it
	// guards, rolling the transaction back when it returns false. That ordering is
	// the whole mechanism, and it is not interchangeable with checking first: a
	// cascade that runs entirely between a pre-write check and the write never
	// sees the child, and the child commits under a deleted project. Called on a
	// non-transactional Storage it still answers the question correctly, but
	// guarantees nothing, because the row lock is released the instant that
	// single autocommit statement completes.
	//
	// #2702/#2710/#2711/#2712: core.CreateSecret, core.CreateFolder,
	// core.CreateEnvironment and LocalStorage.RestoreSecret each checked the
	// ENVIRONMENT's liveness (via the EnvironmentSecretGuardLockKey named lock)
	// but never the project's, and deleteProjectCascade takes no such named lock —
	// so a child committed under a project deleted in the window. The store-internal
	// lockLiveParent helper this exposes already backed RestoreEnvironment's
	// identical fix (#2656); the method exists so a core-layer caller already
	// inside WithTransaction can use it without the full-row write
	// internal/storage/store would otherwise have to grow a bespoke method for.
	LockLiveProject(ctx context.Context, projectID uint) (bool, error)
}
