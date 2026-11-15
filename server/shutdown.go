package main

import (
	"context"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

// flushLastUsedOnShutdown stops the last-used coalescer on graceful shutdown:
// it writes the stamps the core recorded but has not yet flushed
// (internal/core/last_used_coalescer.go) and then latches the coalescer shut so
// no timer or background flush goroutine can fire against the store after this
// returns. StopLastUsed (not FlushLastUsed) is used deliberately: the servers
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
