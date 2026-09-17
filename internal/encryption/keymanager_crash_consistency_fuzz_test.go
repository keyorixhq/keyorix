//go:build !windows

package encryption

// keymanager_crash_consistency_fuzz_test.go — FuzzKEKRotationCrashConsistency.
//
// Crash-consistency fuzzing of KEK-passphrase rotation (RotateKEKPassphrase).
// Rotation persists two coupled files — dek.key (the DEK wrapped under a KEK) and
// kek.salt (the salt the KEK is derived from) — via write-pending → rename →
// fsync. A crash between any two of those steps leaves an intermediate on-disk
// state. This target interrupts the REAL rotation at each such step (via the
// nil-in-prod rotationCheckpoint seam) and asserts a sound invariant pair at
// every crash point:
//
//   - AVAILABILITY (no data loss): some combination of the on-disk files that
//     survive the crash (active + leftover .pending) plus a credential the
//     operator legitimately holds recovers EXACTLY the pre-rotation DEK. A state
//     with no such recovery is a permanent-data-loss bug.
//   - CONFIDENTIALITY (retire the old key): once a rotation has fully completed,
//     the OLD passphrase must no longer unwrap the active DEK. We assert only this
//     deny direction — it admits no legitimate exception.
//   - VALUE INTEGRITY: whenever recovery succeeds, the recovered DEK equals the
//     original byte-for-byte (never a silently different key).
//
// The oracle is sound: the DEK value under test is known, so recovery either
// yields it or does not; no "must accept" direction is asserted. The only
// false-positive source is the recovery model below (recoverDEK), which encodes
// the rotation's own documented recovery procedure and is kept deliberately small.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// rotationCrash is the sentinel a simulated crash panics with, so the harness can
// tell its own injected crash apart from a genuine panic in the code under test.
type rotationCrash struct{ label string }

// kekRotationGuardDeadline is a HANG backstop, not the shared fuzzutil 3s amplification
// guard. A legitimate iteration seeds a KeyManager (real 600k-iteration PBKDF2), rotates the
// KEK passphrase (more PBKDF2), then recovers by trying passphrases against the on-disk files
// (more PBKDF2) — inherently ~1-2s, and under -fuzz coverage instrumentation on a loaded
// continuous-fuzzing rig it brushes 3s. Its inputs are bounded (crashSel + two passphrases)
// with no untrusted-input-driven allocation, so there is no amplification to catch on a tight
// deadline — only a genuine hang, which this generous deadline still flags. The real PBKDF2
// KDF stays: the KEK derivation itself is under test here. See the 2026-09-17 rig deploy note.
const kekRotationGuardDeadline = 30 * time.Second

// crashLabels are the durability checkpoints commitNewKEKFiles emits, in order.
// Index 0 ("") means "run to completion, no crash".
var crashLabels = []string{
	"",                             // no crash — clean rotation
	"kek:after-write-salt-pending", // both active files still old
	"kek:after-write-dek-pending",  // both active files still old
	"kek:after-rename-dek",         // hazard: active DEK new, active salt still old
	"kek:after-rename-salt",        // on-disk complete (both new)
}

func FuzzKEKRotationCrashConsistency(f *testing.F) {
	// Seed every crash point, with distinct passphrases and with same-passphrase
	// (which re-salts but leaves the old passphrase valid — the confidentiality
	// check must skip it).
	for i := range crashLabels {
		f.Add(uint8(i), "old-correct-horse", "new-tr0ub4dor")
		f.Add(uint8(i), "same-pass", "same-pass")
	}
	f.Add(uint8(3), "\x00\x01", "\xff\xfe") // hazard window, non-UTF8 passphrases

	f.Fuzz(func(t *testing.T, crashSel uint8, oldPass, newPass string) {
		if oldPass == "" {
			oldPass = "seed-old-passphrase"
		}
		if newPass == "" {
			newPass = "seed-new-passphrase"
		}
		target := crashLabels[int(crashSel)%len(crashLabels)]

		// t.TempDir() must run on the test goroutine, not inside Guard's goroutine.
		dir := t.TempDir()

		// Local hang backstop with a generous deadline (see kekRotationGuardDeadline) instead
		// of fuzzutil.Guard's shared 3s, which is tuned for fast file/parse targets. An invariant
		// violation inside runCrashConsistencyCase is signalled by panic (the fuzzer records it
		// as a reproducer); this goroutine+select only catches a true hang.
		done := make(chan struct{})
		go func() {
			defer close(done)
			runCrashConsistencyCase(dir, oldPass, newPass, target)
		}()
		select {
		case <-done:
		case <-time.After(kekRotationGuardDeadline):
			t.Fatalf("kek-rotation-crash-consistency exceeded %s — possible hang", kekRotationGuardDeadline)
		}
	})
}

// runCrashConsistencyCase seeds a KeyManager, rotates it while crashing at target,
// then asserts the availability + confidentiality + value-integrity invariants.
// It panics on any violation (see FuzzKEKRotationCrashConsistency).
func runCrashConsistencyCase(dir, oldPass, newPass, target string) {
	// Seed: a fresh manager initialized under oldPass. This creates dek.key +
	// kek.salt and generates the DEK we must never lose.
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(oldPass); err != nil {
		// A fresh temp dir must always initialize; a failure here is a harness bug.
		panic(fmt.Sprintf("seed Initialize(oldPass=%q): %v", oldPass, err))
	}
	dek0 := append([]byte(nil), km.GetDEK()...)
	if len(dek0) == 0 {
		panic("seed DEK is empty")
	}

	// Rotate, interrupting at target (target == "" runs to completion).
	runRotationWithCrash(km, oldPass, newPass, target)

	// AVAILABILITY + VALUE INTEGRITY: the DEK must still be recoverable, and equal.
	rec, via, ok := recoverDEK(dir, oldPass, newPass)
	if !ok {
		panic(fmt.Sprintf("DATA LOSS: no recovery yields the DEK after crash %q (old=%q new=%q)", target, oldPass, newPass))
	}
	if !bytes.Equal(rec, dek0) {
		panic(fmt.Sprintf("DEK CORRUPTION after crash %q via %s: recovered key != original", target, via))
	}

	// CONFIDENTIALITY: after a fully completed rotation, the OLD passphrase must no
	// longer open the active DEK. Only meaningful when the passphrase actually
	// changed (same-passphrase rotation legitimately keeps it valid).
	completed := target == "" || target == "kek:after-rename-salt"
	if completed && newPass != oldPass {
		kmOld := NewKeyManager(dir, "dek.key", "kek.salt")
		if err := kmOld.Initialize(oldPass); err == nil {
			panic(fmt.Sprintf("RETIRED-KEY LIVE: old passphrase still unwraps the active DEK after a completed rotation (target=%q)", target))
		}
	}
}

// runRotationWithCrash runs RotateKEKPassphrase, arming the rotationCheckpoint seam
// to panic (simulating an abrupt crash) the moment the rotation reaches `target`.
// A target of "" runs the rotation to completion. Any non-sentinel panic — a real
// bug in the code under test — is re-raised so the fuzzer records it.
func runRotationWithCrash(km *KeyManager, oldPass, newPass, target string) {
	if target == "" {
		_ = km.RotateKEKPassphrase(oldPass, newPass)
		return
	}
	prev := rotationCheckpoint
	rotationCheckpoint = func(label string) {
		if label == target {
			panic(rotationCrash{label})
		}
	}
	defer func() {
		rotationCheckpoint = prev
		if r := recover(); r != nil {
			if _, ok := r.(rotationCrash); ok {
				return // our simulated crash — swallow it, the on-disk state is what we test
			}
			panic(r) // a genuine panic in the code under test — let the fuzzer see it
		}
	}()
	_ = km.RotateKEKPassphrase(oldPass, newPass)
}

// recoverDEK encodes the rotation's documented recovery procedure and returns the
// recovered DEK if any path succeeds. Order:
//  1. old passphrase against the active files (consistent pre-rename states);
//  2. new passphrase against the active files (completed states — salt renamed);
//  3. the hazard state (active DEK new, active salt still old): apply the leftover
//     kek.salt.pending — exactly what the code's own comment says an operator does
//     — then open with the new (or, for same-pass, old) passphrase.
//
// This is the only false-positive source: keep it minimal and review it as hard as
// the code under test.
func recoverDEK(dir, oldPass, newPass string) (dek []byte, via string, ok bool) {
	if dek, ok := tryOpen(dir, oldPass); ok {
		return dek, "old-passphrase", true
	}
	if dek, ok := tryOpen(dir, newPass); ok {
		return dek, "new-passphrase", true
	}
	pending := filepath.Join(dir, "kek.salt.pending")
	if _, err := os.Stat(pending); err == nil {
		if err := os.Rename(pending, filepath.Join(dir, "kek.salt")); err == nil {
			if dek, ok := tryOpen(dir, newPass); ok {
				return dek, "apply-pending-salt+new-passphrase", true
			}
			if dek, ok := tryOpen(dir, oldPass); ok {
				return dek, "apply-pending-salt+old-passphrase", true
			}
		}
	}
	return nil, "", false
}

// tryOpen attempts to initialize a fresh manager over the on-disk key files with
// passphrase; on success it returns a copy of the unwrapped DEK.
func tryOpen(dir, passphrase string) ([]byte, bool) {
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(passphrase); err != nil {
		return nil, false
	}
	return append([]byte(nil), km.GetDEK()...), true
}
