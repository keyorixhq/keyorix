package k8ssync

import (
	"context"
	"time"
)

// Logf is a minimal logging sink (satisfied by log.Printf). The agent never logs
// secret values — only counts, target identities, and error reasons.
type Logf func(format string, args ...interface{})

// Sync runs one reconcile pass and logs a one-line summary plus any per-target
// errors. Returns the Result for callers/tests.
func Sync(ctx context.Context, e *Engine, mappings []SecretMapping, logf Logf) Result {
	res, err := e.Reconcile(ctx, mappings)
	if err != nil {
		logf("k8s-sync: reconcile error: %v", err)
		return res
	}
	logf("k8s-sync: created=%d updated=%d unchanged=%d failed=%d",
		res.Created, res.Updated, res.Unchanged, res.Failed)
	for _, e := range res.Errors {
		logf("k8s-sync: %s", e)
	}
	return res
}

// Run reconciles once immediately, then every interval until ctx is cancelled. When
// status is non-nil, each pass's result is recorded for the health/readiness probes.
func Run(ctx context.Context, e *Engine, mappings []SecretMapping, interval time.Duration, logf Logf, status *Status) {
	sync := func() {
		res := Sync(ctx, e, mappings, logf)
		if status != nil {
			status.Record(res)
		}
	}
	sync()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sync()
		case <-ctx.Done():
			return
		}
	}
}
