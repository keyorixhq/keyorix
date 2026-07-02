// scheduler_run.go — shared driver for the background schedulers.
//
// Every periodic job in startHTTPServer has the same skeleton: run once on startup,
// then on a ticker until the context is cancelled, with the work guarded by the
// single-writer advisory lock (ADR-039). runScheduler owns that skeleton and times
// each tick into Prometheus (see server/middleware/scheduler_metrics.go); lockedRun
// runs the work under the lock and maps the result to a metric outcome. The per-job
// closures keep only their own logic — guards, lock key, and log lines unchanged.
package main

import (
	"context"
	"log"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// runScheduler starts a named scheduler goroutine: it runs tick once immediately, then
// every interval until ctx is cancelled. Each tick's outcome and (when it actually
// ran) its duration are recorded to Prometheus under name.
func runScheduler(ctx context.Context, name string, interval time.Duration, tick func() middleware.SchedulerOutcome) {
	middleware.RegisterScheduler(name)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		run := func() {
			start := time.Now()
			outcome := safeTick(name, tick)
			middleware.RecordSchedulerRun(name, outcome, time.Since(start))
		}
		run() // run once immediately on startup
		for {
			select {
			case <-ticker.C:
				run()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// safeTick recovers a panic from tick, converting it into a SchedulerFailure outcome
// instead of crashing the goroutine (and, since this is the process's only goroutine
// for `name`, silently ending that scheduler forever). This guards work a job's tick
// closure does BEFORE acquiring the advisory lock (e.g. legalHoldBlocks' DB read in
// main.go) — storage.WithSchedulerLock's own runProtected only covers work done AFTER
// the lock is held.
func safeTick(name string, tick func() middleware.SchedulerOutcome) (outcome middleware.SchedulerOutcome) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("%s scheduler tick panicked: %v", name, r)
			outcome = middleware.SchedulerFailure
		}
	}()
	return tick()
}

// lockedRun executes fn under scheduler advisory lock key and maps the result to a
// metric outcome: skipped when another replica holds the lock (a follower, by design),
// failure when fn errors or the lock cannot be acquired (logged via errLabel), success
// otherwise. The error log line mirrors the pre-refactor per-job wording.
func lockedRun(ctx context.Context, storage corestorage.Storage, key int64, errLabel string, fn func() error) middleware.SchedulerOutcome {
	ran, err := storage.WithSchedulerLock(ctx, key, fn)
	if err != nil {
		log.Printf("%s scheduler error: %v", errLabel, err)
		return middleware.SchedulerFailure
	}
	if !ran {
		return middleware.SchedulerSkipped
	}
	return middleware.SchedulerSuccess
}
