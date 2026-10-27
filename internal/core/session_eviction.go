package core

// session_eviction.go -- ERRLOSS-REVOKE-1. Every session-revocation path lists the
// user's session-token hashes (the HTTP auth-cache keys) BEFORE its write, and evicts
// them from the cache AFTER commit, so a revoked/suspended/deprovisioned session stops
// authenticating on the very next request instead of after validTokenTTL (30 s). Each
// of them used to write `hashes, _ := ...ListSessionTokenHashesForUser(...)`: a read
// failure gave an empty list, nothing was evicted, and nothing was logged or audited
// while the code comments promised "immediately".
//
// The listing is now done by listSessionHashes (one retry), and a listing that still
// fails is carried to the post-commit step in sessionEvictions.ListErr, where
// evictSessions falls back to the strongest eviction that needs no hash list (every
// cache entry of the user, SetUserTokenCacheEvictor) and logs a "SECURITY:" line, and
// auditSessionListFailure writes EventSessionRevocationFailed. None of it ever fails
// the primary operation: the DB-side revocation is the durable control, this is only
// the immediacy ("a narrowing decision is never blocked", decisions.md).

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// sessionEvictions is what a revocation path captured before its write: the user's
// session-token hashes, or the error (ListErr) that stopped it from listing them even
// after the retry. A caller may fold other hashes it did get (PATs) into Hashes.
type sessionEvictions struct {
	Hashes  []string
	ListErr error
}

// sessionEvictMode picks the auth-cache primitive for a successful listing and decides
// whether a failed one is audited.
type sessionEvictMode int

const (
	// evictTombstone: the change narrows access (suspend, deactivate, delete, password
	// change, session purge). Writes a tombstone per hash (invalidateTokenCache).
	evictTombstone sessionEvictMode = iota
	// evictClearNarrowing: access is narrowed but the credential stays valid (role
	// removal), so only an already-cached entry is cleared (clearCachedTokens).
	evictClearNarrowing
	// evictClearWidening: access is restored (account becoming active). Clear only; a
	// listing failure is logged and swept but not audited as a revocation failure.
	evictClearWidening
)

// sessionHashLister is the one storage method the listing needs; both c.storage and a
// transaction handle satisfy it.
type sessionHashLister interface {
	ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error)
}

// listSessionHashes lists userID's session-token hashes, retrying once on error.
func listSessionHashes(ctx context.Context, s sessionHashLister, userID uint) sessionEvictions {
	hashes, err := s.ListSessionTokenHashesForUser(ctx, userID)
	if err != nil {
		hashes, err = s.ListSessionTokenHashesForUser(ctx, userID)
	}
	if err != nil {
		return sessionEvictions{ListErr: err}
	}
	return sessionEvictions{Hashes: hashes}
}

// listSessionHashesForEviction is listSessionHashes on c.storage, for callers outside a
// transaction.
func (c *KeyorixCore) listSessionHashesForEviction(ctx context.Context, userID uint) sessionEvictions {
	return listSessionHashes(ctx, c.storage, userID)
}

// listSessionHashesInTx is the listing for a caller inside a transaction. The read stays
// on tx, but runs in a nested savepoint (the one sanctioned in-transaction shape, see
// internal/besteffort): on PostgreSQL a failed statement aborts the enclosing
// transaction, which would turn a failed LISTING into a rolled-back suspension. Nothing
// is logged or audited here; the caller does that after commit via evictSessions.
func listSessionHashesInTx(ctx context.Context, tx storage.Storage, userID uint) sessionEvictions {
	var ev sessionEvictions
	for attempt := 0; attempt < 2; attempt++ {
		ev = sessionEvictions{}
		err := tx.WithTransaction(ctx, func(sp storage.Storage) error {
			hashes, lerr := sp.ListSessionTokenHashesForUser(ctx, userID)
			ev.Hashes = hashes
			return lerr
		})
		if err == nil {
			return ev
		}
		ev = sessionEvictions{ListErr: err}
	}
	return ev
}

// SetUserTokenCacheEvictor wires the HTTP auth cache's evict-everything-of-one-user
// function (middleware.InvalidateUserTokenCache). Called once at startup, alongside
// SetTokenCacheInvalidator.
func (c *KeyorixCore) SetUserTokenCacheEvictor(fn func(userID uint)) {
	c.userTokenCacheEvictor = fn
}

// evictSessions evicts ev from the auth cache; call it AFTER the revocation committed.
// With a good listing it applies mode's primitive to each hash. With a failed listing it
// logs a SECURITY line and evicts every cache entry of the user instead (sessions and
// PATs: over-evicting only costs a re-validation, a still-valid credential gets 200).
// The audit event is separate (auditSessionListFailure) because some callers hold a lock
// here and must write it after releasing it.
func (c *KeyorixCore) evictSessions(userID uint, ev sessionEvictions, mode sessionEvictMode, reason string) {
	// Hashes may be non-empty even when the listing failed (a caller folds the PAT
	// hashes it did get into the same slice), so always apply them.
	if mode == evictTombstone {
		c.invalidateTokenCache(ev.Hashes...)
	} else {
		c.clearCachedTokens(ev.Hashes...)
	}
	if ev.ListErr == nil {
		return
	}
	swept := c.evictUserTokenCache(userID)
	if swept {
		log.Printf("SECURITY: %s: could not list the sessions of user %d (%v) -- evicted every auth-cache entry of the user instead (best-effort, primary operation already succeeded)", reason, userID, ev.ListErr)
	} else {
		log.Printf("SECURITY: %s: could not list the sessions of user %d (%v) and no per-user auth-cache eviction is available -- a revoked session may keep authenticating for up to the auth-cache TTL (best-effort, primary operation already succeeded)", reason, userID, ev.ListErr)
	}
}

// evictUserTokenCache drops every auth-cache entry of the user and reports whether an
// evictor was wired and ran. A panic in the evictor is recovered: it runs after the
// primary operation committed.
func (c *KeyorixCore) evictUserTokenCache(userID uint) (ok bool) {
	if c.userTokenCacheEvictor == nil {
		return false
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: per-user auth-cache eviction panicked for user %d (best-effort, primary operation already succeeded): %v", userID, r)
			ok = false
		}
	}()
	c.userTokenCacheEvictor(userID)
	return true
}

// auditSessionListFailure writes EventSessionRevocationFailed when ev's listing failed,
// best-effort like deleteSessionsForUserAndEvict's own audit write (it never fails the
// caller). A widening change (evictClearWidening) is not audited: nothing was revoked.
func (c *KeyorixCore) auditSessionListFailure(ctx context.Context, userID uint, ev sessionEvictions, mode sessionEvictMode, reason string) {
	if ev.ListErr == nil || mode == evictClearWidening {
		return
	}
	c.writeAuditEventFailedFull(ctx, EventSessionRevocationFailed, &userID, nil, nil, "",
		fmt.Sprintf("%s: could not list the sessions of user %d to evict them from the auth cache (%v) -- the user's cache entries were evicted wholesale where possible; a session may otherwise keep authenticating for up to the auth-cache TTL, review manually", reason, userID, ev.ListErr))
}

// evictSessionsAndAudit is evictSessions followed by auditSessionListFailure, for callers
// that hold no lock at this point.
func (c *KeyorixCore) evictSessionsAndAudit(ctx context.Context, userID uint, ev sessionEvictions, mode sessionEvictMode, reason string) {
	c.evictSessions(userID, ev, mode, reason)
	c.auditSessionListFailure(ctx, userID, ev, mode, reason)
}
