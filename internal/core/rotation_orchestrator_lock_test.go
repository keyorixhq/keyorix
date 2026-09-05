// rotation_orchestrator_lock_test.go — proves the g05 concurrency fix: protection
// against two concurrent backend-rotation calls for the SAME (backend, ref) pair now
// lives centrally in applyBackendRotation (rotationBackendLock), not inside any one
// executor. Before this change, that protection existed ONLY inside
// internal/rotation/awsiam.go's own private refLocks -- Azure's and GCP's
// GenerateUpstream implementations (internal/rotation/azure.go,
// internal/rotation/gcpsa.go) perform the exact same kind of unsynchronized
// list-then-mint-then-delete sequence against their respective cloud APIs, with
// nothing serializing two concurrent calls for the same ref. Confirmed by direct
// reading of both files: neither declares a sync.Mutex, sync.Map, nor calls Lock()
// anywhere -- same for postgres.go/mysql.go/redis.go/mongodb.go's Rotate path. That is
// the RED state this file's first sub-test reproduces directly (bypassing the fix, by
// calling the fake executor's GenerateUpstream on its own) before proving the fix
// (calling it THROUGH applyBackendRotation) closes it.
package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/rotation"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raceGeneratingExecutor is a rotation.GeneratingExecutor test double whose
// GenerateUpstream is instrumented to detect overlapping calls: the FIRST call to
// enter (call "A") signals aEntered and then blocks on releaseA until the test lets
// it proceed -- exactly the orchestration internal/rotation/awsiam_test.go's
// (now-removed) raceFakeIAM used, generalized away from AWS-specific semantics so it
// can stand in for ANY backend. inFlight/peak record how many calls were ever
// concurrently inside the body, the direct signal of whether serialization held.
type raceGeneratingExecutor struct {
	name string

	mu       sync.Mutex
	inFlight int
	peak     int
	calls    int

	aEntered chan struct{}
	releaseA chan struct{}
}

func newRaceGeneratingExecutor(name string) *raceGeneratingExecutor {
	return &raceGeneratingExecutor{name: name, aEntered: make(chan struct{}), releaseA: make(chan struct{})}
}

func (r *raceGeneratingExecutor) Name() string { return r.name }
func (r *raceGeneratingExecutor) Type() string { return "race-fake" }
func (r *raceGeneratingExecutor) Rotate(_ context.Context, _, _ string) error {
	return fmt.Errorf("race-fake: use GenerateUpstream")
}

func (r *raceGeneratingExecutor) GenerateUpstream(_ context.Context, ref string) (string, error) {
	r.mu.Lock()
	r.inFlight++
	if r.inFlight > r.peak {
		r.peak = r.inFlight
	}
	seq := r.calls
	r.calls++
	r.mu.Unlock()

	if seq == 0 {
		close(r.aEntered)
		<-r.releaseA
	}

	r.mu.Lock()
	r.inFlight--
	r.mu.Unlock()
	return fmt.Sprintf("val-%d-%s", seq, ref), nil
}

func (r *raceGeneratingExecutor) peakInFlight() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peak
}

// TestRaceGeneratingExecutor_UnserializedCallsOverlap is the RED half: calling the
// fake executor's GenerateUpstream directly from two goroutines for the same ref --
// with NOTHING serializing them, exactly how Azure's/GCP's/every other backend's
// GenerateUpstream/Rotate behaves today with no lock of its own -- lets the second
// call enter and complete while the first is still in flight. This is the baseline
// this package's orchestrator-level lock (tested below) must close.
func TestRaceGeneratingExecutor_UnserializedCallsOverlap(t *testing.T) {
	fake := newRaceGeneratingExecutor("unlocked")

	bDone := make(chan struct{})
	go func() {
		_, _ = fake.GenerateUpstream(context.Background(), "svc-app")
	}()
	<-fake.aEntered // call A is inside the body, blocked on releaseA

	go func() {
		_, _ = fake.GenerateUpstream(context.Background(), "svc-app")
		close(bDone)
	}()

	select {
	case <-bDone:
		// Expected pre-fix behaviour: B raced ahead and finished while A was still
		// blocked -- proving there is genuinely nothing serializing these calls at
		// the executor level.
	case <-time.After(2 * time.Second):
		t.Fatal("call B did not complete concurrently with A -- this fake no longer reproduces the unsynchronized baseline the orchestrator lock is supposed to fix")
	}
	assert.Equal(t, 2, fake.peakInFlight(), "both calls were concurrently in-flight with no lock in place -- confirms the RED baseline")

	close(fake.releaseA)
}

// TestApplyBackendRotation_ConcurrentSameBackendRef_Serializes is the GREEN half:
// the SAME fake executor, called the SAME way, but THROUGH applyBackendRotation (the
// shared entry point rotateOneSecret and RotateSecretOnDemand both use) -- must now
// serialize. Call B must not even enter GenerateUpstream until call A's entire
// applyBackendRotation call (which holds the per-(backend,ref) lock for its whole
// duration) has returned.
func TestApplyBackendRotation_ConcurrentSameBackendRef_Serializes(t *testing.T) {
	fake := newRaceGeneratingExecutor("locked")
	c := &KeyorixCore{}
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))

	secretA := &models.SecretNode{RotationBackend: fake.Name(), RotationRef: "svc-app"}
	secretB := &models.SecretNode{RotationBackend: fake.Name(), RotationRef: "svc-app"} // SAME (backend, ref)

	type outcome struct {
		val string
		err error
	}
	aCh := make(chan outcome, 1)
	bCh := make(chan outcome, 1)

	go func() {
		v, err := c.applyBackendRotation(context.Background(), secretA, "cand")
		aCh <- outcome{v, err}
	}()
	<-fake.aEntered // A is inside GenerateUpstream, holding the orchestrator lock

	go func() {
		v, err := c.applyBackendRotation(context.Background(), secretB, "cand")
		bCh <- outcome{v, err}
	}()

	// B must be blocked acquiring the lock A already holds -- it cannot even reach
	// GenerateUpstream, let alone finish, until A's applyBackendRotation returns.
	select {
	case <-bCh:
		t.Fatal("call B completed while call A was still inside applyBackendRotation for the SAME (backend, ref) -- the orchestrator lock did not serialize them")
	case <-time.After(2 * time.Second):
		// Expected once serialized: B is correctly still waiting for A's lock.
	}
	assert.Equal(t, 1, fake.peakInFlight(), "at most one call may be inside GenerateUpstream at a time for the same (backend, ref)")

	close(fake.releaseA) // let A's held GenerateUpstream return; A can now finish
	a := <-aCh
	b := <-bCh

	require.NoError(t, a.err)
	require.NoError(t, b.err)
	assert.Equal(t, "val-0-svc-app", a.val)
	assert.Equal(t, "val-1-svc-app", b.val)
	assert.Equal(t, 1, fake.peakInFlight(), "peak concurrency inside GenerateUpstream must never exceed 1 for the same (backend, ref), even after both calls complete")
}

// TestApplyBackendRotation_DifferentRefs_RunConcurrently confirms the lock is keyed
// per (backend, ref), NOT a single global lock: two DIFFERENT refs under the SAME
// backend must be able to run concurrently, exactly like awsiam.go's removed
// refLocks documented ("Keyed per ref ... so rotations for DIFFERENT IAM users still
// run concurrently"). A global lock here would be a correctness-preserving but
// needlessly serializing regression (every rotation across every ref queued behind
// one mutex), so this is asserted explicitly, not just assumed.
func TestApplyBackendRotation_DifferentRefs_RunConcurrently(t *testing.T) {
	fake := newRaceGeneratingExecutor("locked-multi-ref")
	c := &KeyorixCore{}
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))

	secretA := &models.SecretNode{RotationBackend: fake.Name(), RotationRef: "svc-a"}
	secretB := &models.SecretNode{RotationBackend: fake.Name(), RotationRef: "svc-b"} // DIFFERENT ref

	bDone := make(chan struct{})
	go func() {
		_, _ = c.applyBackendRotation(context.Background(), secretA, "cand")
	}()
	<-fake.aEntered // A (ref svc-a) is inside GenerateUpstream, holding ITS lock

	go func() {
		_, _ = c.applyBackendRotation(context.Background(), secretB, "cand")
		close(bDone)
	}()

	select {
	case <-bDone:
		// Expected: a different ref's lock is independent, so B is not blocked by A.
	case <-time.After(2 * time.Second):
		t.Fatal("call B (a DIFFERENT ref than A) was blocked -- the lock must be keyed per (backend, ref), not a single global lock")
	}

	close(fake.releaseA)
}

// TestRotationBackendLock_KeyedByBackendAndRefOnly proves the lock's identity is a
// pure function of (backend, ref) -- it never inspects, dispatches on, or otherwise
// depends on the concrete rotation.Executor type registered under that backend name.
// This is what makes coverage automatic for every CURRENT and FUTURE executor type:
// applyBackendRotation acquires this same lock unconditionally, before it ever checks
// whether exec is a rotation.GeneratingExecutor -- see TestRotationExecutorRegistry_*
// in rotation_executor_registry_exhaustiveness_test.go for the companion guard that
// keeps the set of known executor constructors from silently drifting stale.
func TestRotationBackendLock_KeyedByBackendAndRefOnly(t *testing.T) {
	c := &KeyorixCore{}

	same1 := c.rotationBackendLock("aws-prod", "svc-app")
	same2 := c.rotationBackendLock("aws-prod", "svc-app")
	assert.Same(t, same1, same2, "the same (backend, ref) pair must always resolve to the same mutex")

	diffRef := c.rotationBackendLock("aws-prod", "svc-other")
	assert.NotSame(t, same1, diffRef, "a different ref under the same backend must get its own mutex")

	diffBackend := c.rotationBackendLock("gcp-prod", "svc-app")
	assert.NotSame(t, same1, diffBackend, "the same ref under a different backend must get its own mutex")
}
