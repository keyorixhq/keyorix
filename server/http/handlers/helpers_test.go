// helpers_test.go — regression coverage for #243: detached "fire and forget"
// side-effect goroutines spawned from auth handlers (audit logging,
// last-login recording) had no panic recovery. A panic there runs on a
// separate goroutine from the one serving the request, so the HTTP server's
// per-request recovery middleware never sees it — it takes down the whole
// process, on every user's login attempt. goSafe closes that gap.
package handlers

import (
	"testing"
	"time"
)

// TestGoSafe_RecoversPanic proves a panic inside the function passed to
// goSafe does not crash the test process. Before the #243 fix, the call sites
// in auth.go/webauthn.go/mfa.go used a bare `go func(){...}()` — a panic
// there is NOT caught by the HTTP server's request-recovery middleware
// (which only guards the goroutine serving the request) and would crash the
// whole process. If goSafe's recover() didn't work, this test binary itself
// would crash before reaching the assertion below.
func TestGoSafe_RecoversPanic(t *testing.T) {
	done := make(chan struct{})
	goSafe(func() {
		defer close(done)
		panic("simulated panic in background goroutine")
	})

	select {
	case <-done:
		// goSafe's recover() caught the panic; the goroutine ran to
		// completion (via the deferred close) instead of taking the
		// process down.
	case <-time.After(2 * time.Second):
		t.Fatal("goSafe goroutine never completed")
	}
}

// TestGoSafe_RunsFunction confirms goSafe still actually runs fn to
// completion in the non-panicking case — it must not swallow normal work.
func TestGoSafe_RunsFunction(t *testing.T) {
	done := make(chan struct{})
	goSafe(func() {
		close(done)
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goSafe did not run the function")
	}
}
