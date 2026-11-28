package main

import (
	"context"
	"io"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

// flushLastUsedOnShutdown stops the last-used coalescer on graceful shutdown:
// it writes the stamps the core recorded but has not yet flushed
// (internal/core/last_used_coalescer.go) and latches the coalescer shut so no
// new timer or background flush starts after this returns; a background flush
// in flight is cancelled and waited for within the same deadline (only a store
// call that ignores cancellation can outlive it, see lastUsedCoalescer.Stop).
// StopLastUsed (not FlushLastUsed) is used deliberately: the servers
// have already drained here, but a plain flush leaves the coalescer able to
// re-arm its timer on any late stamp, and a failed final flush re-arms it from
// finishFlush — either would touch the store after the process considers
// last-used bookkeeping finished. Bounded by its own 10 s context, including
// the wait for a background flush stuck in a slow write.
func flushLastUsedOnShutdown(coreService *core.KeyorixCore) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	coreService.StopLastUsed(ctx)
}

// secretReadDenialFlushTimeout bounds flushSecretReadDenialsOnShutdown, like
// the 10 s of flushLastUsedOnShutdown: up to 10000 summary rows are written one
// by one, and a slow database must not hold shutdown until SIGKILL.
const secretReadDenialFlushTimeout = 10 * time.Second

// flushSecretReadDenialsOnShutdown writes the secret-read denial summary rows
// for aggregation windows still open at shutdown (#3377). Without it the counts
// of refusals after each window's first row are lost on SIGTERM. Rows not
// written within the timeout are counted in a SECURITY log line. A window
// opened after this runs (a request still served past the HTTP drain timeout)
// is lost.
func flushSecretReadDenialsOnShutdown(coreService *core.KeyorixCore) {
	ctx, cancel := context.WithTimeout(context.Background(), secretReadDenialFlushTimeout)
	defer cancel()
	if n := coreService.FlushSecretReadDenialsWithin(ctx); n > 0 {
		log.Printf("SECURITY: shutdown: %d refused-secret-read summary row(s) NOT written to the audit trail within %s (%v); those refusal counts are lost",
			n, secretReadDenialFlushTimeout, ctx.Err())
	}
}

// closeAuditForwarder flushes/closes the wired SIEM audit forwarder (if any) on
// shutdown. core.AuditForwarder only declares Forward (core has no dependency
// on the concrete siem package), so the Close method is reached via a local
// interface rather than a direct type assertion to *siem.Forwarder.
func closeAuditForwarder(coreService *core.KeyorixCore) {
	type closer interface{ Close() }
	if cl, ok := coreService.AuditForwarder().(closer); ok {
		cl.Close()
	}
}

// storageCloseTimeout bounds closeStorageOnShutdown: the wait for the
// schedulers and the storage Close together. On Postgres Close waits for every
// pooled connection to come back (pgxpool.Pool.Close), and a request still
// running past the HTTP drain timeout keeps its connection, possibly for as
// long as a query to an unreachable database takes. The defers that run after
// this one (KEK wipe, single-writer and presence release, the lock-loss
// os.Exit(1)) must not wait on that.
const storageCloseTimeout = 5 * time.Second

// closeStorageOnShutdown closes the core's storage after everything that writes
// to it has stopped (deferred first in main, so it runs last): on Postgres it
// stops the background jobs CreateStorage started and releases the
// connections. waitSchedulers (startSchedulers' wait, nil before they started)
// is awaited first, so no scheduler tick runs against a closed storage. Both
// steps share storageCloseTimeout; past it, shutdown goes on without them. A
// storage without Close is left alone.
func closeStorageOnShutdown(coreService *core.KeyorixCore, waitSchedulers func()) {
	closeStorageWithin(coreService.Storage(), waitSchedulers, storageCloseTimeout)
}

func closeStorageWithin(st any, waitSchedulers func(), d time.Duration) {
	deadline := time.Now().Add(d)
	if waitSchedulers != nil && !doneWithin(waitSchedulers, time.Until(deadline)) {
		log.Printf("closing storage on shutdown: schedulers still running after %s; exiting without closing the storage", d)
		return
	}
	c, ok := st.(io.Closer)
	if !ok {
		return
	}
	var err error
	if !doneWithin(func() { err = c.Close() }, time.Until(deadline)) {
		log.Printf("closing storage on shutdown: still waiting after %s (a request or job still holds a connection); exiting without it", d)
		return
	}
	if err != nil {
		log.Printf("closing storage on shutdown: %v", err)
	}
}

// doneWithin runs f in its own goroutine and reports whether it returned within
// d. On false f keeps running; the caller must not read anything f writes.
func doneWithin(f func(), d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}
