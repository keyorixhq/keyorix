//go:build !windows

package encryption

// keymanager_rewrap_crash_consistency_fuzz_test.go — FuzzDEKRewrapCrashConsistency.
//
// Phase 2 of the rotation crash-consistency spec: crash-consistency fuzzing of
// KEK-provider migration (RewrapDEK, ADR-041). RewrapDEK re-wraps the SAME DEK under a
// new KEK provider and atomically swaps the on-disk wrapped DEK (write-pending → rename →
// fsync). The new provider persists its own key material (a fresh salt for the password
// provider) as a side effect BEFORE the DEK file is touched. A crash between any two of
// those steps leaves an intermediate on-disk state. This target interrupts the REAL
// RewrapDEK at each durability checkpoint (via the nil-in-prod rotationCheckpoint seam,
// labels "rewrap:...") and asserts a sound invariant set at every crash point:
//
//   - AVAILABILITY (no data loss): at every crash state the active on-disk DEK recovers
//     to EXACTLY the pre-rewrap DEK — via the OLD provider before the rename, the NEW
//     provider after it. A state with no recovery is permanent data loss.
//   - CONFIDENTIALITY (retire the old wrapping key): once the rewrap has completed, the
//     OLD provider must no longer unwrap the active DEK. Only this deny direction is
//     asserted — it admits no legitimate exception.
//   - VALUE INTEGRITY: whenever recovery succeeds, the recovered DEK equals the original
//     byte-for-byte (never a silently-different key).
//
// Sound: the DEK value under test is known, so recovery either yields it or does not; no
// "must accept" direction is asserted. Two DISTINCT password providers (independent salt
// files) stand in for a provider migration, so the two KEKs always differ and the
// confidentiality direction is unconditional after completion. The only false-positive
// source is the tiny recovery model (recoverRewrap) below.
//
// Complements FuzzKEKRotationCrashConsistency (Phase 1, RotateKEKPassphrase — the two-file
// salt+DEK window): this one is the one-file DEK window plus the provider side effect.

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

const (
	rewrapDEKFile = "dek.key"
	rewrapSaltOld = "kek.salt.old"
	rewrapSaltNew = "kek.salt.new"
)

// rewrapCrashLabels are the durability checkpoints RewrapDEK emits, in order.
// Index 0 ("") means "run to completion, no crash".
var rewrapCrashLabels = []string{
	"",                               // no crash — clean rewrap
	"rewrap:after-provider-kek",      // new provider persisted its salt; active DEK still old-wrapped
	"rewrap:after-write-dek-pending", // pending written; active DEK still old-wrapped
	"rewrap:after-rename-dek",        // active DEK now new-wrapped (dir fsync pending)
	"rewrap:after-syncdir",           // on-disk complete
}

func FuzzDEKRewrapCrashConsistency(f *testing.F) {
	for i := range rewrapCrashLabels {
		f.Add(uint8(i), "old-correct-horse", "new-tr0ub4dor")
		f.Add(uint8(i), "same-pass", "same-pass") // distinct salts ⇒ distinct KEKs anyway
	}
	f.Add(uint8(3), "\x00\x01", "\xff\xfe") // rename point, non-UTF8 passphrases

	f.Fuzz(func(t *testing.T, crashSel uint8, oldPass, newPass string) {
		if oldPass == "" {
			oldPass = "seed-old-passphrase"
		}
		if newPass == "" {
			newPass = "seed-new-passphrase"
		}
		target := rewrapCrashLabels[int(crashSel)%len(rewrapCrashLabels)]

		// t.TempDir() must run on the test goroutine, not inside Guard's goroutine.
		dir := t.TempDir()

		// Inside Guard, signal any invariant violation with panic (Guard runs fn in a
		// goroutine; the fuzzer records a panic as a reproducer). Guard's own fatalf is
		// only for the hang case.
		fuzzutil.Guard(t.Fatalf, "dek-rewrap-crash-consistency", func() {
			runRewrapCrashCase(dir, oldPass, newPass, target)
		})
	})
}

// runRewrapCrashCase seeds a KeyManager under an OLD password provider, re-wraps its DEK
// under a NEW password provider while crashing at target, then asserts the availability +
// confidentiality + value-integrity invariants. It panics on any violation.
func runRewrapCrashCase(dir, oldPass, newPass, target string) {
	// Seed: a manager initialized under the OLD provider (salt in rewrapSaltOld). This
	// generates the DEK we must never lose and writes dek.key wrapped under KEK(old).
	kmSeed := NewKeyManager(dir, rewrapDEKFile, rewrapSaltOld)
	kmSeed.SetKeyProvider(crypto.NewPasswordKeyProvider(oldPass, dir, rewrapSaltOld))
	if err := kmSeed.Initialize(oldPass); err != nil {
		// A fresh temp dir must always initialize; a failure here is a harness bug.
		panic(fmt.Sprintf("seed Initialize(old=%q): %v", oldPass, err))
	}
	dek0 := append([]byte(nil), kmSeed.GetDEK()...)
	if len(dek0) == 0 {
		panic("seed DEK is empty")
	}

	// Re-wrap under the NEW provider (salt in rewrapSaltNew), interrupting at target.
	newProvider := crypto.NewPasswordKeyProvider(newPass, dir, rewrapSaltNew)
	runRewrapWithCrash(kmSeed, newProvider, target)

	// AVAILABILITY + VALUE INTEGRITY.
	rec, via, ok := recoverRewrap(dir, oldPass, newPass)
	if !ok {
		panic(fmt.Sprintf("DATA LOSS: no provider recovers the DEK after rewrap crash %q (old=%q new=%q)", target, oldPass, newPass))
	}
	if !bytes.Equal(rec, dek0) {
		panic(fmt.Sprintf("DEK CORRUPTION after rewrap crash %q via %s: recovered key != original", target, via))
	}

	// CONFIDENTIALITY: after a completed rewrap the OLD provider must not open the active
	// DEK. Distinct salt files guarantee distinct KEKs, so this holds unconditionally
	// (no same-key exception).
	completed := target == "" || target == "rewrap:after-rename-dek" || target == "rewrap:after-syncdir"
	if completed {
		if _, ok := tryOpenProvider(dir, oldPass, rewrapSaltOld); ok {
			panic(fmt.Sprintf("RETIRED-KEY LIVE: old provider still unwraps the active DEK after a completed rewrap (target=%q)", target))
		}
	}
}

// runRewrapWithCrash runs RewrapDEK, arming the rotationCheckpoint seam to panic
// (simulating an abrupt crash) the moment RewrapDEK reaches `target`. target "" runs to
// completion. Any non-sentinel panic — a real bug in the code under test — is re-raised
// so the fuzzer records it.
func runRewrapWithCrash(km *KeyManager, newProvider crypto.KeyProvider, target string) {
	if target == "" {
		_ = km.RewrapDEK(newProvider)
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
				return // our simulated crash — the on-disk state is what we test
			}
			panic(r) // a genuine panic in the code under test — let the fuzzer see it
		}
	}()
	_ = km.RewrapDEK(newProvider)
}

// recoverRewrap tries the OLD provider then the NEW provider against the active on-disk
// DEK. Before the rename the active DEK is old-wrapped (old opens); after it, new-wrapped
// (new opens). RewrapDEK never removes the active dek.key before the atomic rename, so an
// active file always exists — recovery never needs the .pending. This is the only
// false-positive source; keep it minimal.
func recoverRewrap(dir, oldPass, newPass string) (dek []byte, via string, ok bool) {
	if dek, ok := tryOpenProvider(dir, oldPass, rewrapSaltOld); ok {
		return dek, "old-provider", true
	}
	if dek, ok := tryOpenProvider(dir, newPass, rewrapSaltNew); ok {
		return dek, "new-provider", true
	}
	return nil, "", false
}

// tryOpenProvider initializes a fresh manager over the on-disk dek.key using a password
// provider with the given passphrase + salt path; on success returns a copy of the DEK.
func tryOpenProvider(dir, passphrase, saltPath string) ([]byte, bool) {
	km := NewKeyManager(dir, rewrapDEKFile, saltPath)
	km.SetKeyProvider(crypto.NewPasswordKeyProvider(passphrase, dir, saltPath))
	if err := km.Initialize(passphrase); err != nil {
		return nil, false
	}
	return append([]byte(nil), km.GetDEK()...), true
}
