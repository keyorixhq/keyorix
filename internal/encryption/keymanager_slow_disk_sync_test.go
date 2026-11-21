// keymanager_slow_disk_sync_test.go — IF1 fault class: SLOW DISK (bounded delay)
// on the key-material durable-write path, with the "no lock held across the slow
// op" oracle.
//
// fault_hooks.go / FuzzFaultInjectedOperations already cover the ENOSPC/EIO/
// short-write/effect-then-error shapes at the KEK/DEK write→rename→fsync seams.
// They do NOT cover a slow disk: a write or fsync that eventually succeeds but
// takes a long time. The failure mode a slow disk exposes is not data loss but
// AVAILABILITY — any lock held across the slow call stalls every operation that
// contends on it.
//
// This fault needs no new production seam: the existing fileFaultHook already
// runs inside every durableXxx helper (under whatever lock the caller holds). A
// hook that sleeps and returns nil injects a bounded delay and then lets the real
// durability call run — the exact wall-clock shape of a slow disk, with the real
// on-disk effect still happening.
//
// Oracles here:
//   - ATOMIC + RECOVERS (gate): a KEK rotation whose directory fsync is slow still
//     commits atomically; the DEK is unchanged; a freshly reopened key manager
//     recovers the same DEK under the NEW passphrase and rejects the OLD one.
//   - NO LOCK HELD ACROSS THE SLOW OP (acceptance, #4376): GetKeyVersion()/GetDEK()
//     and the KEK-derived key getters sit on the hot encrypt path
//     (service.go:EncryptSecret calls GetKeyVersion on every encrypt). KEK rotation
//     used to hold KeyManager.mu (write) across its fsyncs, so a slow fsync stalled
//     every encrypt for its full duration. It now holds only rotateMu and the DEK
//     flock, which readers never take, and publishes the new keys after the files
//     are durable: every reader probed while the fsync is stalled returns within a
//     small bound, returns the OLD keys (nothing is published before the rename and
//     directory fsync), and the NEW keys once the rotation returns. Red on a tree
//     where the rotation holds mu across the fsync.
//   - NO FD / GOROUTINE LEAK (gate): the slow-disk rotation leaves the open-fd and
//     goroutine counts where it found them.
package encryption

import (
	"bytes"
	"os"
	"runtime"
	"testing"
	"time"
)

// armSlowSyncOnce installs a fileFaultHook that, on the FIRST call for seam,
// closes reached (signalling the caller that the seam is now executing, with
// whatever locks the rotation holds there) and sleeps delay, then returns nil so the
// REAL durability call runs afterwards. Subsequent seams/calls are pass-through.
// Returns a restore func. Not for parallel use (fileFaultHook is a package global).
func armSlowSyncOnce(seam string, delay time.Duration, reached chan struct{}) (restore func()) {
	prev := fileFaultHook
	var fired bool
	fileFaultHook = func(s string) *fileFault {
		if s == seam && !fired {
			fired = true
			close(reached)
			time.Sleep(delay)
		}
		return nil
	}
	return func() { fileFaultHook = prev }
}

func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1 // not Linux / unavailable; caller treats <0 as "skip this oracle"
	}
	return len(entries)
}

// TestSlowDiskSync_KEKRotationAtomicAndRecovers is the gate: a KEK rotation whose
// directory fsync is slow (but succeeds) must still commit atomically and leave a
// store that reopens and decrypts.
func TestSlowDiskSync_KEKRotationAtomicAndRecovers(t *testing.T) {
	const oldPass, newPass = "slow-disk-old-pass", "slow-disk-new-pass"
	dir := t.TempDir()

	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(oldPass); err != nil {
		t.Fatalf("Initialize(oldPass): %v", err)
	}
	dek0 := bytes.Clone(km.GetDEK())
	if len(dek0) == 0 {
		t.Fatal("DEK is empty after Initialize")
	}

	fdBefore := openFDCount(t)

	reached := make(chan struct{})
	restore := armSlowSyncOnce("kek:syncdir-dek", 400*time.Millisecond, reached)
	err := km.RotateKEKPassphrase(oldPass, newPass)
	restore()
	if err != nil {
		t.Fatalf("FAIL-CLOSED oracle: rotation with a slow (but succeeding) fsync must complete, got: %v", err)
	}
	select {
	case <-reached:
	default:
		t.Fatal("HARNESS: the slow-sync seam kek:syncdir-dek never fired — rotation did not reach the directory fsync")
	}

	// Atomicity + recovery: the DEK is unchanged by a KEK rotation (only its
	// wrapping changes), and a FRESH key manager reopened from the same files
	// must recover that same DEK under the NEW passphrase and reject the OLD one.
	if !bytes.Equal(km.GetDEK(), dek0) {
		t.Fatal("DEK changed across KEK rotation — KEK rotation must preserve the DEK")
	}
	km2 := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km2.Initialize(newPass); err != nil {
		t.Fatalf("RECOVERY oracle: reopen under new passphrase after slow-disk rotation: %v", err)
	}
	if !bytes.Equal(km2.GetDEK(), dek0) {
		t.Fatal("RECOVERY oracle: reopened DEK does not match the pre-rotation DEK — store did not recover its key")
	}
	km3 := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km3.Initialize(oldPass); err == nil {
		t.Fatal("ATOMICITY oracle: the OLD passphrase still opens the store after rotation — the salt/DEK commit was not atomic")
	}

	// No-FD-leak oracle (Linux only; skipped where /proc is unavailable).
	if fdBefore >= 0 {
		// Settle: km2/km3 above opened and closed key files during Initialize.
		runtime.GC()
		fdAfter := openFDCount(t)
		if fdAfter > fdBefore+2 { // +2 slack: km2/km3 hold no persistent fds, but allow allocator/pipe noise
			t.Fatalf("FD-LEAK oracle: open fds grew %d -> %d across a slow-disk rotation", fdBefore, fdAfter)
		}
	}
}

// readerProbeBound is how long one key-manager read may take while a rotation's
// fsync is stalled for slowSyncDelay. Generous against scheduler and -race noise,
// far below the stall it must not track.
const (
	slowSyncDelay    = 300 * time.Millisecond
	readerProbeBound = 50 * time.Millisecond
	readerProbes     = 10
)

// probeReaders calls every key-manager getter readerProbes times while a
// rotation is stalled inside a slow fsync, failing on any call slower than
// readerProbeBound, and returns the evidence-signing key ID the last probe saw.
func probeReaders(t *testing.T, km *KeyManager, trial int) (eskID string) {
	t.Helper()
	var worst time.Duration
	for range readerProbes {
		for name, read := range map[string]func(){
			"GetKeyVersion":         func() { _ = km.GetKeyVersion() },
			"GetDEK":                func() { _ = km.GetDEK() },
			"GetEvidenceSignKey":    func() { _, eskID, _ = km.GetEvidenceSignKey() },
			"GetAuditCheckpointKey": func() { _, _, _ = km.GetAuditCheckpointKey() },
			"GetBackupManifestKey":  func() { _, _, _ = km.GetBackupManifestKey() },
		} {
			t0 := time.Now()
			read()
			took := time.Since(t0)
			worst = max(worst, took)
			if took > readerProbeBound {
				t.Fatalf("trial %d: %s took %v while the rotation's fsync was stalled for %v (bound %v) — "+
					"a lock readers take is held across the slow fsync", trial, name, took, slowSyncDelay, readerProbeBound)
			}
		}
	}
	t.Logf("trial %d: slowest reader under a %v stalled fsync: %v", trial, slowSyncDelay, worst.Round(time.Microsecond))
	return eskID
}

// requireStillStalled fails unless the rotation is still inside its slow seam,
// so the probes before it provably overlapped the stall rather than running
// after the rotation finished.
func requireStillStalled(t *testing.T, done <-chan error, trial int) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("HARNESS trial %d: the rotation returned (err=%v) before the reader probes finished — "+
			"the probes did not overlap the stalled fsync; raise slowSyncDelay", trial, err)
	default:
	}
}

// TestSlowDiskSync_ReadersNotBlockedAcrossKEKSync is the acceptance test for
// #4376 item 1 (3× replay): while a KEK rotation's directory fsync is stalled,
// every key-manager reader returns within readerProbeBound and still sees the
// old keys; after the rotation returns it sees the new ones.
func TestSlowDiskSync_ReadersNotBlockedAcrossKEKSync(t *testing.T) {
	// Passphrase chain, one rotation per trial.
	passes := []string{"hold-p0", "hold-p1", "hold-p2", "hold-p3"}
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(passes[0]); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	dek0 := km.GetDEK()

	goroutinesBefore := runtime.NumGoroutine()

	const trials = 3
	for i := range trials {
		oldPass, newPass := passes[i], passes[i+1]
		_, oldID, _ := km.GetEvidenceSignKey()

		reached := make(chan struct{})
		restore := armSlowSyncOnce("kek:syncdir-dek", slowSyncDelay, reached)
		done := make(chan error, 1)
		go func() { done <- km.RotateKEKPassphrase(oldPass, newPass) }()

		<-reached // rotation is now inside the slow directory fsync
		seenID := probeReaders(t, km, i)
		requireStillStalled(t, done, i)

		rotErr := <-done
		restore()
		if rotErr != nil {
			t.Fatalf("trial %d: rotation failed: %v", i, rotErr)
		}
		if seenID != oldID {
			t.Fatalf("trial %d: a reader saw evidence-signing key %q while the rotation was still inside its fsync, want the old %q — "+
				"the new keys were published before the key files were durable", i, seenID, oldID)
		}
		if _, newID, _ := km.GetEvidenceSignKey(); newID == oldID {
			t.Fatalf("trial %d: evidence-signing key ID unchanged (%q) after the KEK rotation returned", i, newID)
		}
		if !bytes.Equal(km.GetDEK(), dek0) {
			t.Fatalf("trial %d: DEK changed across a KEK rotation", i)
		}
	}

	// No-goroutine-leak oracle: every rotation goroutine was joined via done.
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > goroutinesBefore+1 {
		t.Fatalf("GOROUTINE-LEAK oracle: goroutines grew %d -> %d across %d slow-disk rotations",
			goroutinesBefore, after, trials)
	}
}
