package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// TestRunSchedulerAfter_TrackedWaitOutlastsAnInFlightTick: cancelling the context
// does not stop a tick that is already running, so the tracking WaitGroup must not
// be released until that tick has returned. This is the property
// startSchedulersForTest relies on to keep one test's tick out of the next test.
func TestRunSchedulerAfter_TrackedWaitOutlastsAnInFlightTick(t *testing.T) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(withSchedulerTracking(context.Background(), &wg))
	defer cancel()

	inTick := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	runScheduler(ctx, "test-tracked-inflight-tick", time.Hour, func() middleware.SchedulerOutcome {
		once.Do(func() { close(inTick) })
		<-release
		return middleware.SchedulerSuccess
	})
	<-inTick
	cancel()

	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
		t.Fatal("wait returned while a tick was still running: the next test would share the process with it")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		t.Fatal("wait never returned after the in-flight tick finished and the context was cancelled")
	}
}

// TestNoTestCallsStartSchedulersDirectly keeps every test in this package on
// startSchedulersForTest. A direct call starts goroutines nobody waits for; that
// was the merge_group root-3 data race (see startSchedulersForTest).
//
// What it recognises: the name startSchedulers immediately followed by an opening
// parenthesis, in this directory's _test.go files. It does not see a call through a function value or from another
// package (startSchedulers is unexported, so there is none today).
func TestNoTestCallsStartSchedulersDirectly(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("found no _test.go files: the guard would be vacuous")
	}
	direct := regexp.MustCompile(`\bstartSchedulers\(`)
	const helperFile = "scheduler_test_helpers_test.go"
	var sawHelperCall bool
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- a file from this package's own directory
		if err != nil {
			t.Fatal(err)
		}
		n := len(direct.FindAllIndex(raw, -1))
		if f == helperFile {
			sawHelperCall = n == 1
			continue
		}
		if n > 0 {
			t.Errorf("%s calls startSchedulers directly %d time(s); use startSchedulersForTest so the scheduler goroutines are cancelled and waited for before the test returns", f, n)
		}
	}
	if !sawHelperCall {
		t.Fatalf("%s should hold exactly one startSchedulers call (the helper's own): the guard's premise changed", helperFile)
	}
}
