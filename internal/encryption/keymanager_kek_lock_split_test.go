// keymanager_kek_lock_split_test.go — step-1 correctness tests (§2.7 items 4 and 5).
//
// Item 4: concurrent GetDEK/GetKeyVersion readers racing a KEK rotation under
// -race; each state.Load() must return a fully-consistent snapshot (no half-
// written keyState).
//
// Item 5: two concurrent RotateKEKPassphrase calls with the same old passphrase;
// exactly one may succeed — the other must fail once it discovers the old
// passphrase is no longer active (rotateMu serialises them, but the passphrase
// check catches the second one after the first has changed the on-disk KEK).
package encryption

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestKEKLockSplit_ConcurrentReadersUnderRotation_NoRace (§2.7 item 4):
// 50 goroutines continuously call state.Load() while a KEK rotation is inside
// its slow (injected) directory fsync. The race detector must report no data
// races, and every loaded keyState must have all key-material fields either
// all-present (after Initialize) or all-absent (before Initialize) — never a
// partially-constructed mix.
func TestKEKLockSplit_ConcurrentReadersUnderRotation_NoRace(t *testing.T) {
	const delay = 100 * time.Millisecond
	passes := []string{"concur-p0", "concur-p1", "concur-p2"}
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize(passes[0]))

	var totalReads atomic.Int64

	for trial := range 2 {
		reached := make(chan struct{})
		done := make(chan error, 1)
		restore := armSlowSyncOnce("kek:syncdir-dek", delay, reached)
		go func(trial int) {
			done <- km.RotateKEKPassphrase(passes[trial], passes[trial+1])
		}(trial)

		<-reached // rotation is now inside the slow fsync, holding rotateMu

		// 50 concurrent readers while rotation's fsync is in-flight.
		// Each state.Load() must return an atomic snapshot: either fully-old
		// or fully-new, never a half-written keyState.
		var wg sync.WaitGroup
		for range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				st := km.state.Load()
				if st == nil {
					return
				}
				totalReads.Add(1)
				// Consistency: currentDEK and keyVersion must both be present
				// or both absent in a valid post-Initialize state. A rotation
				// must never publish a state where one is updated and the other
				// isn't.
				dekPresent := len(st.currentDEK) > 0
				verPresent := st.keyVersion != ""
				if dekPresent != verPresent {
					t.Errorf("inconsistent keyState snapshot: currentDEK len=%d, keyVersion=%q — partial state published",
						len(st.currentDEK), st.keyVersion)
				}
				// All key-material fields in a fully-initialized state are 32 bytes.
				if dekPresent {
					if len(st.evidenceSignKey) != 32 {
						t.Errorf("inconsistent keyState: currentDEK present but evidenceSignKey len=%d", len(st.evidenceSignKey))
					}
					if len(st.auditCheckpointKey) != 32 {
						t.Errorf("inconsistent keyState: currentDEK present but auditCheckpointKey len=%d", len(st.auditCheckpointKey))
					}
					if len(st.backupManifestKey) != 32 {
						t.Errorf("inconsistent keyState: currentDEK present but backupManifestKey len=%d", len(st.backupManifestKey))
					}
				}
			}()
		}
		wg.Wait()

		rotErr := <-done
		restore()
		require.NoError(t, rotErr, "trial %d: rotation failed", trial)
	}

	t.Logf("total reads while rotation in-flight: %d", totalReads.Load())
	if totalReads.Load() == 0 {
		t.Fatal("HARNESS: no reads executed while rotation was in-flight — concurrent measurement is void")
	}
}

// TestKEKLockSplit_ConcurrentRotations_Serialized (§2.7 item 5):
// Two goroutines race to call RotateKEKPassphrase with the same old passphrase.
// rotateMu serialises them: the first to acquire it rotates the KEK (changing
// the on-disk salt and wrapped DEK); the second then finds the old passphrase
// no longer matches the current on-disk KEK and fails. Exactly one rotation
// must succeed.
func TestKEKLockSplit_ConcurrentRotations_Serialized(t *testing.T) {
	dir := t.TempDir()
	const p0, p1, p2 = "serial-p0", "serial-p1", "serial-p2"
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize(p0))

	type result struct{ err error }
	ch := make(chan result, 2)

	// Both goroutines race for rotateMu. One wins, rotates from p0 → something.
	// The other (once it acquires rotateMu after the first finishes) verifies
	// p0 against the current on-disk DEK — which is now wrapped under a new
	// salt derived from either p1 or p2 — and fails "old passphrase is incorrect".
	go func() { ch <- result{km.RotateKEKPassphrase(p0, p1)} }()
	go func() { ch <- result{km.RotateKEKPassphrase(p0, p2)} }()

	r1 := <-ch
	r2 := <-ch

	successes := 0
	for _, r := range []result{r1, r2} {
		if r.err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 rotation to succeed (second must fail: p0 no longer active), got %d (errs: %v | %v)",
			successes, r1.err, r2.err)
	}
}
