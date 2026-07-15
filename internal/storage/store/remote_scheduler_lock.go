package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// WithSchedulerLock is reached on EVERY scheduler tick regardless of
// storage.type — server/main.go starts every background scheduler
// unconditionally — so a stub here (as this method used to be) is not the
// "never reached remotely" case some of this package's other stubs are: it was
// the sole blocker preventing several already-remote-proxied maintenance
// operations (notably #520's retention-purge fix) from ever actually running
// on a schedule under storage.type: remote, because the lock wrapping them
// failed first, before their own proxy logic ever got a chance to run (#530).
//
// fn cannot travel over the wire (it's an arbitrary closure that itself makes
// further RemoteStorage calls back through rs), so this cannot be a single
// atomic HTTP round trip the way, say, TransitionMachineIdentityState is.
// Instead it's TWO atomic round trips around fn running locally:
//
//  1. TryAcquireSchedulerLock — one atomic conditional write on the upstream,
//     exactly like LocalStorage's own advisory-lock acquire, just expressed as
//     a TTL lease row instead of a Postgres session lock (see
//     local_scheduler_lock_lease.go's package doc for why: a lease survives
//     being split across requests, an advisory lock does not).
//  2. fn runs locally, exactly as LocalStorage's WithSchedulerLock runs it
//     in-process, under panic recovery (runProtected).
//  3. ReleaseSchedulerLock — one atomic conditional delete, best-effort (its
//     failure is logged, not returned — see below for why).
//
// Between (1) and (3), a background heartbeat renews the lease (calling
// TryAcquireSchedulerLock again with the SAME holder token, which — per that
// method's own contract — is a safe renewal, not a new acquisition attempt) so
// a long-running fn is never preempted by its own lease expiring mid-job. If
// this process crashes or loses network connectivity to the upstream while fn
// is running, the heartbeats simply stop and the lease self-heals via
// ExpiresAt — replicating the exact safety property LocalStorage gets for free
// from Postgres tearing down the advisory lock's session on a dead connection
// (see the interface doc's ReleaseSchedulerLock comment).
//
// A best-effort release (rather than surfacing its error to the caller)
// mirrors that the lock has ALREADY served its purpose by the time release
// runs — fn already committed or failed — and ExpiresAt is the actual
// correctness backstop either way; failing the whole scheduler tick over a
// release that didn't make it to the upstream would incorrectly treat this
// tick's real outcome (whatever fn returned) as a failure.
func (rs *RemoteStorage) WithSchedulerLock(ctx context.Context, key int64, fn func() error) (bool, error) {
	holder, err := newSchedulerLockHolderToken()
	if err != nil {
		return false, fmt.Errorf("failed to generate scheduler lock holder token: %w", err)
	}

	acquired, err := rs.TryAcquireSchedulerLock(ctx, key, holder, schedulerLockTTL)
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}

	heartbeatCtx, stopHeartbeat := context.WithCancel(context.Background()) // NOSONAR
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(schedulerLockHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				if _, err := rs.TryAcquireSchedulerLock(heartbeatCtx, key, holder, schedulerLockTTL); err != nil {
					log.Printf("scheduler lock %d: heartbeat renewal failed (holder %s): %v", key, holder, err)
				}
			}
		}
	}()
	defer func() {
		stopHeartbeat()
		<-heartbeatDone
		// Best-effort: see the doc comment above for why this must not fail the tick.
		if err := rs.ReleaseSchedulerLock(context.Background(), key, holder); err != nil { // NOSONAR -- cleanup must proceed even if caller's ctx is cancelled; go:S8239
			log.Printf("scheduler lock %d: release failed (holder %s), relying on TTL expiry: %v", key, holder, err)
		}
	}()

	return true, runProtected(fn)
}

// schedulerLockTTL is how long an acquired (or renewed) scheduler-lock lease
// stays valid without a heartbeat. Large relative to
// schedulerLockHeartbeatInterval so a couple of missed heartbeats (a transient
// network blip to the upstream) don't cost the lock, while still bounding how
// long a genuinely crashed/partitioned holder can wedge the key.
const schedulerLockTTL = 45 * time.Second

// schedulerLockHeartbeatInterval is how often WithSchedulerLock renews its
// lease while fn is still running. A third of schedulerLockTTL, so a single
// missed heartbeat is never enough to lose the lock.
const schedulerLockHeartbeatInterval = 15 * time.Second

// newSchedulerLockHolderToken returns a fresh random per-acquisition-attempt
// token (mirrors internal/core/sso.go's randToken) — not a stable per-process
// identity, since a single process can hold multiple different scheduler locks
// (different keys) concurrently, each needing to prove ownership of only its
// own lease independently.
func newSchedulerLockHolderToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// schedulerLockAcquireRequest/schedulerLockAcquireResponse are the wire shapes
// for POST /api/v1/system/scheduler-lock/acquire.
type schedulerLockAcquireRequest struct {
	Key       int64  `json:"key"`
	Holder    string `json:"holder"`
	TTLMillis int64  `json:"ttl_millis"`
}

type schedulerLockAcquireResponse struct {
	Acquired bool `json:"acquired"`
}

// TryAcquireSchedulerLock proxies to POST /api/v1/system/scheduler-lock/acquire,
// which performs the SAME atomic conditional write LocalStorage's
// TryAcquireSchedulerLock does, server-side, in this ONE request — see that
// method's doc comment for the full acquire/renew/reclaim decision table this
// single round trip implements.
func (rs *RemoteStorage) TryAcquireSchedulerLock(ctx context.Context, key int64, holder string, ttl time.Duration) (bool, error) {
	body := schedulerLockAcquireRequest{Key: key, Holder: holder, TTLMillis: ttl.Milliseconds()}
	resp, err := rs.client.Post(ctx, "/api/v1/system/scheduler-lock/acquire", body)
	if err != nil {
		return false, fmt.Errorf("failed to acquire scheduler lock: %w", err)
	}
	if !resp.Success {
		return false, fmt.Errorf("acquire scheduler lock failed: %s", resp.Error.Error())
	}
	var result schedulerLockAcquireResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Acquired, nil
}

// schedulerLockReleaseRequest is the wire shape for POST
// /api/v1/system/scheduler-lock/release.
type schedulerLockReleaseRequest struct {
	Key    int64  `json:"key"`
	Holder string `json:"holder"`
}

// ReleaseSchedulerLock proxies to POST /api/v1/system/scheduler-lock/release,
// which performs the SAME atomic conditional delete LocalStorage's
// ReleaseSchedulerLock does — a release for a lock this holder doesn't (or no
// longer) own is a silent no-op on the upstream too, matching the interface
// doc's contract exactly across this HTTP hop.
func (rs *RemoteStorage) ReleaseSchedulerLock(ctx context.Context, key int64, holder string) error {
	body := schedulerLockReleaseRequest{Key: key, Holder: holder}
	resp, err := rs.client.Post(ctx, "/api/v1/system/scheduler-lock/release", body)
	if err != nil {
		return fmt.Errorf("failed to release scheduler lock: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("release scheduler lock failed: %s", resp.Error.Error())
	}
	return nil
}
