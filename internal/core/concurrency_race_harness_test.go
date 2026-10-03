// concurrency_race_harness_test.go — GUARD-2's reusable barrier helper for
// cross-replica check-then-act race tests.
//
// By the time GUARD-2 started, more than a dozen concurrency_*_postgres_test.go
// files in this package had each hand-rolled the identical shape: a
// sync.WaitGroup, a close(chan struct{}) barrier so neither goroutine can
// start before the other, then wg.Wait() — see
// concurrency_sod_grant_postgres_test.go,
// concurrency_break_glass_project_postgres_test.go, and
// concurrency_dual_control_approval_postgres_test.go for three independent
// copies of the same ~15 lines. raceReplicas below factors that mechanical
// part into one place so a new gap-closing test doesn't hand-roll a 13th
// copy, and a bug in the barrier logic itself (e.g. a goroutine leak, or a
// race in the harness that masks a real one) gets fixed once for every
// caller.
//
// "Many rounds" (GUARD-2's brief): a race's actual interleaving depends on OS
// goroutine scheduling, not a fixed inherent window — a race that only
// manifests 1 time in 20 needs repetition to surface reliably. Rather than a
// rounds parameter baked into this helper (which would force every caller to
// also thread a per-round fixture-reset callback through it, when most
// fixtures here are cheap to just rebuild from scratch), repetition is done
// the same way this package's own red/green proofs already run it: `go test
// -run <name> -count=20`, re-running the whole test (fixture setup included)
// N times. See GUARD-2's PR body for a live 10/10 reproduction this way.
//
// This deliberately does NOT replace each test's own oracle/invariant check —
// "what the invariant is" differs per decision (exactly one of a toxic SoD
// pair, never zero admins, a revoked credential never authenticates again,
// at most one winner of a unique name...). Callers build their own
// independent-connection replicas with postgres_contention_helpers_test.go's
// pgOpen/pgIsolatedSchemaDSN (own *gorm.DB, own LocalStorage, own
// *KeyorixCore per simulated replica — sharing a *KeyorixCore across
// "replicas" would make the race prove nothing, see that file's own header)
// and pass closures bound to each replica's core; this file only releases
// them at the same instant and assembles the results.
package core

// raceResult is the pair of outcomes raceReplicas hands back for the caller's
// own invariant check.
type raceResult struct {
	ErrA, ErrB error
}

// raceBarrierT is the subset of *testing.T this file needs, so callers in
// both *testing.T and *testing.F contexts (e.g. a future fuzz target) can use
// it without this file depending on the concrete type.
type raceBarrierT interface {
	Helper()
}

// raceReplicas runs opA and opB concurrently, released from the same closed
// channel so neither can start before the other, and blocks until both have
// returned.
func raceReplicas(t raceBarrierT, opA, opB func() error) raceResult {
	t.Helper()
	var res raceResult
	done := make(chan struct{})
	start := make(chan struct{})
	go func() {
		<-start
		res.ErrA = opA()
		done <- struct{}{}
	}()
	go func() {
		<-start
		res.ErrB = opB()
		done <- struct{}{}
	}()
	close(start)
	<-done
	<-done
	return res
}
