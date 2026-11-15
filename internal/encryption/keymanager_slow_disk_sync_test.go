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
//   - NO LOCK HELD ACROSS THE SLOW OP (demonstration + calibration): KEK rotation
//     holds KeyManager.mu (write) across its fsyncs; GetKeyVersion()/GetDEK() take
//     it (read) on the hot encrypt path (service.go:EncryptSecret calls
//     GetKeyVersion on every encrypt). So a slow fsync stalls every encrypt for
//     its full duration. The test measures this and asserts the stall tracks the
//     injected delay (red), against a zero-contention baseline (green). This is a
//     hardening observation, not a defect; it is benign in production (rotation
//     is rare and admin-initiated) but real.
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
// closes reached (signalling the caller that the seam is now executing — and
// therefore that KeyManager.mu is held) and sleeps delay, then returns nil so the
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

// TestSlowDiskSync_HoldsReadLockAcrossSync demonstrates (3× replay) that a KEK
// rotation holds KeyManager.mu across its directory fsync, so a slow fsync stalls
// the hot encrypt path (GetKeyVersion RLock) for the whole delay. The
// zero-contention baseline is the green control proving the measurement reflects
// real lock contention, not a slow probe.
func TestSlowDiskSync_HoldsReadLockAcrossSync(t *testing.T) {
	const delay = 300 * time.Millisecond
	// Passphrase chain, one rotation per trial.
	passes := []string{"hold-p0", "hold-p1", "hold-p2", "hold-p3"}
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(passes[0]); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	goroutinesBefore := runtime.NumGoroutine()

	const trials = 3
	for i := range trials {
		oldPass, newPass := passes[i], passes[i+1]

		// Green control: probe latency with NO rotation holding the lock.
		base0 := time.Now()
		_ = km.GetKeyVersion()
		baseline := time.Since(base0)

		reached := make(chan struct{})
		restore := armSlowSyncOnce("kek:syncdir-dek", delay, reached)
		done := make(chan error, 1)
		go func() { done <- km.RotateKEKPassphrase(oldPass, newPass) }()

		<-reached // rotation is now inside the slow fsync, holding mu.Lock
		probe0 := time.Now()
		_ = km.GetKeyVersion() // RLock — blocks until rotation releases mu.Lock
		blocked := time.Since(probe0)

		rotErr := <-done
		restore()
		if rotErr != nil {
			t.Fatalf("trial %d: rotation failed: %v", i, rotErr)
		}

		t.Logf("trial %d: baseline GetKeyVersion=%v, blocked-under-slow-sync=%v (injected delay=%v)",
			i, baseline.Round(time.Microsecond), blocked.Round(time.Millisecond), delay)

		// RED: the probe is held off for most of the injected delay => mu.Lock is
		// held across the slow fsync.
		if blocked < delay/2 {
			t.Fatalf("trial %d: expected the hot-path RLock to be blocked >= %v by the slow fsync, got %v "+
				"(if this now passes, KeyManager.mu is no longer held across the directory fsync — revisit this characterization)",
				i, delay/2, blocked)
		}
		// GREEN control: with no rotation in flight the same probe is ~instant.
		if baseline > delay/10 {
			t.Fatalf("trial %d: zero-contention baseline GetKeyVersion took %v (> %v) — the probe itself is slow, "+
				"the blocked measurement would not prove lock contention", i, baseline, delay/10)
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
