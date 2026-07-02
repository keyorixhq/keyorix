package main

import (
	"testing"

	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
)

// #118: a panic in tick — e.g. a DB read a job's closure does BEFORE acquiring the
// advisory lock, like legalHoldBlocks in main.go — must not crash the scheduler
// goroutine (which would silently end that job forever, since runScheduler's loop
// runs in its own single goroutine with nothing to restart it). safeTick is the guard
// that WithSchedulerLock's own runProtected can't provide, since that only wraps work
// done AFTER the lock is held.
func TestSafeTick_RecoversPanic(t *testing.T) {
	outcome := safeTick("test_job", func() middleware.SchedulerOutcome {
		panic("simulated pre-lock DB read panic")
	})
	assert.Equal(t, middleware.SchedulerFailure, outcome)
}

// The non-panic path is unaffected: tick's own outcome passes through untouched.
func TestSafeTick_PassesThroughOutcome(t *testing.T) {
	outcome := safeTick("test_job", func() middleware.SchedulerOutcome {
		return middleware.SchedulerSuccess
	})
	assert.Equal(t, middleware.SchedulerSuccess, outcome)
}
