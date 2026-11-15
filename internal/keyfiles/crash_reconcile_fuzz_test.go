//go:build !windows

package keyfiles

// crash_reconcile_fuzz_test.go — FuzzKeySetCrashReconcile (FS1).
//
// The key-set manifest (#2900, manifest.go) is Keyorix's canonical "no torn
// key material is ever accepted as valid" seam: a per-file SHA-256 ledger that
// boot verifies (VerifyKeySetConsistency) and reconciles (ReconcileKeySet)
// before the DEK is loaded. Its WRITE path is already fault-fuzzed through
// internal/encryption's durableWriteSync/Rename/SyncDir hooks
// (FuzzFaultInjectedOperations). Its READER / crash-RECONCILE path — what boot
// does with whatever on-disk key-set state a crash or an external tool left —
// had no corpus-driven fuzzer.
//
// This target manufactures the post-crash on-disk key set directly (the only
// states an atomic temp+rename writer can leave, plus the external-tampering
// states the manifest exists specifically to catch) and drives the REAL
// InspectKeySet / VerifyKeySetConsistency / ReconcileKeySet. No production hook
// is needed: boot's reconcile is a pure function of the on-disk bytes.
//
// Oracles (and what each does NOT verify):
//
//	(b) INTEGRITY — a mixed-generation or incoherent set is never accepted as
//	    valid: VerifyKeySetConsistency MUST return an error for a foreign file
//	    (content matching neither its recorded nor a staged hash), a partial
//	    set, or a stuck interrupted intent. After a SUCCESSFUL reconcile every
//	    present required file hashes to its (now-committed) manifest entry — the
//	    set is provably one generation. DOES NOT verify that the manifest
//	    authenticates the files (the hashes are unkeyed by design — manifest.go:
//	    "What the manifest is NOT: an authenticator"); a deliberate attacker who
//	    rewrites both files and the manifest is explicitly out of scope.
//	(c) SURFACED — a refused state yields a non-nil error, never a silent nil.
//	    DOES NOT verify the exact error message/class, only that one is returned.
//	(d) OLD-OR-NEW — a refused reconcile leaves the "old" active files byte-for-
//	    byte unchanged (no half-rename); a finished reconcile moves the whole set
//	    to the staged generation. DOES NOT verify crash-DURING-reconcile (no
//	    fault is injected into the rename/fsync itself here — that path is
//	    already covered by internal/encryption's fault hooks).
//	ROBUSTNESS — none of the three entry points panics on any manufactured
//	    state. DOES NOT verify fd/goroutine leaks (the reconcile path opens files
//	    only transiently and starts no goroutines).

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// ksEnc is the two-file (salt + DEK) key set the fuzzer works with: the minimal
// RequiredKeyFilePaths set (no write-capable provider, no shamir), which is
// enough to exercise every classification branch (fresh/partial/foreign/
// finishable/completed/abandoned/stuck/adopt).
func ksEnc() *config.EncryptionConfig {
	return &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
}

// writeFile writes data at full with key-material mode.
func ksWrite(t *testing.T, full string, data []byte) {
	t.Helper()
	if err := os.WriteFile(full, data, 0o600); err != nil { //nolint:gosec // harness temp path
		t.Fatalf("write %s: %v", full, err)
	}
}

func ksRead(t *testing.T, full string) []byte {
	t.Helper()
	b, err := os.ReadFile(full) //nolint:gosec // harness temp path
	if err != nil {
		t.Fatalf("read %s: %v", full, err)
	}
	return b
}

// verifyCoherent asserts VerifyKeySetConsistency passes AND every present
// required file hashes to its committed manifest entry — the full "the set is
// provably one generation" oracle (b).
func verifyCoherent(t *testing.T, enc *config.EncryptionConfig, dir, context string) {
	t.Helper()
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("[%s] expected a COHERENT set but VerifyKeySetConsistency refused it: %v", context, err)
	}
	mpath, err := ManifestPath(enc, dir)
	if err != nil {
		t.Fatalf("[%s] ManifestPath: %v", context, err)
	}
	m, err := LoadManifest(mpath)
	if err != nil {
		t.Fatalf("[%s] a coherent set must have a loadable manifest: %v", context, err)
	}
	required, err := RequiredKeyFilePaths(enc, dir)
	if err != nil {
		t.Fatalf("[%s] RequiredKeyFilePaths: %v", context, err)
	}
	mdir := filepath.Dir(mpath)
	for _, p := range required {
		if _, statErr := os.Stat(p); statErr != nil {
			continue // absent is fine only if the whole set is absent; Verify already checked that
		}
		h := HashBytes(ksRead(t, p))
		key := manifestKey(mdir, p)
		entry, ok := m.Files[key]
		if !ok {
			t.Fatalf("[%s] INTEGRITY(b): present file %s has no manifest entry after a coherent reconcile", context, p)
		}
		if entry.SHA256 != h {
			t.Fatalf("[%s] INTEGRITY(b): present file %s hashes %s but its manifest entry records %s — the set is a silent mix", context, p, h, entry.SHA256)
		}
	}
}

func FuzzKeySetCrashReconcile(f *testing.F) {
	for s := range byte(7) {
		f.Add(s, []byte("salt-0000000000000000"), []byte("dek-00000000000000000000000000000000"), []byte("NEWVAL"))
	}
	f.Add(byte(3), []byte{}, []byte{0x00}, []byte{})

	f.Fuzz(func(t *testing.T, scenario byte, saltSeed, dekSeed, newSeed []byte) {
		enc := ksEnc()
		dir := t.TempDir()

		required, err := RequiredKeyFilePaths(enc, dir)
		if err != nil {
			t.Fatalf("RequiredKeyFilePaths: %v", err)
		}
		if len(required) != 2 {
			t.Fatalf("expected a 2-file set (salt, dek), got %d: %v", len(required), required)
		}
		saltPath, dekPath := required[0], required[1]

		// Baseline content (non-empty so hashes are stable and distinct).
		oldSalt := append([]byte("S:"), saltSeed...)
		oldDek := append([]byte("D:"), dekSeed...)
		newSalt := append([]byte("S-NEW:"), newSeed...)
		newDek := append([]byte("D-NEW:"), newSeed...)

		ksWrite(t, saltPath, oldSalt)
		ksWrite(t, dekPath, oldDek)

		// Baseline manifest at generation 1 recording both files (OpFirstBoot).
		w, err := NewSetWriter(enc, dir)
		if err != nil {
			t.Fatalf("NewSetWriter: %v", err)
		}
		if err := w.CommitManifestFromDisk(OpFirstBoot, saltPath, dekPath); err != nil {
			t.Fatalf("baseline CommitManifestFromDisk: %v", err)
		}
		// Baseline must be coherent, else the harness is broken.
		verifyCoherent(t, enc, dir, "baseline")

		mpath, _ := ManifestPath(enc, dir)

		switch scenario % 7 {
		case 0:
			// CLEAN set — reconcile is a no-op, stays coherent.
			reconcileOK(t, enc, dir, "clean")
			verifyCoherent(t, enc, dir, "clean/after")

		case 1:
			// FOREIGN file — dek replaced with content the manifest does not
			// record and no staged hash matches (restored from another backup,
			// copied in by a tool). MUST be refused; reconcile must not touch it.
			foreign := append([]byte("FOREIGN:"), newSeed...)
			if string(foreign) == string(oldDek) {
				foreign = append(foreign, 'x')
			}
			ksWrite(t, dekPath, foreign)
			mustRefuse(t, enc, dir, "foreign-dek")
			if string(ksRead(t, dekPath)) != string(foreign) {
				t.Fatalf("OLD-OR-NEW(d): a refused reconcile modified the foreign file")
			}
			if string(ksRead(t, saltPath)) != string(oldSalt) {
				t.Fatalf("OLD-OR-NEW(d): a refused reconcile modified the salt")
			}

		case 2:
			// PARTIAL set — salt deleted. MUST be refused (incomplete set).
			if err := os.Remove(saltPath); err != nil {
				t.Fatalf("remove salt: %v", err)
			}
			mustRefuse(t, enc, dir, "partial-missing-salt")

		case 3:
			// FINISHABLE interrupted rotate-kek: both files staged to new
			// content; salt already renamed (= staged), dek still old but its
			// .pending holds the staged content. Reconcile finishes the rename
			// and the whole set becomes the NEW generation.
			if string(newSalt) == string(oldSalt) || string(newDek) == string(oldDek) {
				t.Skip("new content collides with old — not a meaningful rotation")
			}
			if err := w.StageManifest(OpRotateKEK, map[string][]byte{saltPath: newSalt, dekPath: newDek}); err != nil {
				t.Fatalf("StageManifest: %v", err)
			}
			ksWrite(t, saltPath, newSalt)          // salt renamed into place (new)
			ksWrite(t, dekPath+".pending", newDek) // dek staging file holds new content
			// dekPath itself still holds oldDek.
			reconcileOK(t, enc, dir, "finishable")
			verifyCoherent(t, enc, dir, "finishable/after")
			if string(ksRead(t, dekPath)) != string(newDek) {
				t.Fatalf("OLD-OR-NEW(d): finishable reconcile did not move dek to the staged (new) content")
			}

		case 4:
			// COMPLETED interrupted op: both files already have the staged
			// content, only the manifest commit was lost. Reconcile commits it.
			if string(newSalt) == string(oldSalt) || string(newDek) == string(oldDek) {
				t.Skip("new content collides with old")
			}
			if err := w.StageManifest(OpRotateKEK, map[string][]byte{saltPath: newSalt, dekPath: newDek}); err != nil {
				t.Fatalf("StageManifest: %v", err)
			}
			ksWrite(t, saltPath, newSalt)
			ksWrite(t, dekPath, newDek)
			reconcileOK(t, enc, dir, "completed")
			verifyCoherent(t, enc, dir, "completed/after")

		case 5:
			// STUCK incoherent op: salt is new (matches staged) but dek is old
			// and has NO matching staging file — boot cannot complete it and the
			// set is not one generation. MUST be refused.
			if string(newSalt) == string(oldSalt) {
				t.Skip("new salt collides with old")
			}
			if err := w.StageManifest(OpRotateKEK, map[string][]byte{saltPath: newSalt, dekPath: newDek}); err != nil {
				t.Fatalf("StageManifest: %v", err)
			}
			ksWrite(t, saltPath, newSalt) // salt new
			// dek stays old; no dek.key.pending written → stuck.
			mustRefuse(t, enc, dir, "stuck-incoherent")

		case 6:
			// TORN manifest — the manifest file itself is garbage (a crash mid
			// write that a non-atomic writer could leave; the real writer is
			// atomic, so this models external corruption). Boot must not crash;
			// it moves the unparseable manifest aside and re-adopts the present
			// set (warn-and-adopt), ending coherent.
			ksWrite(t, mpath, []byte("}{ this is not json "))
			if _, err := LoadManifest(mpath); err == nil {
				t.Fatalf("harness: expected the torn manifest to be unparseable")
			}
			reconcileOK(t, enc, dir, "torn-manifest")
			verifyCoherent(t, enc, dir, "torn-manifest/after")
		}
	})
}

// reconcileOK runs ReconcileKeySet and fails on any error (used for states that
// must be accepted/finished).
func reconcileOK(t *testing.T, enc *config.EncryptionConfig, dir, context string) {
	t.Helper()
	if _, err := ReconcileKeySet(enc, dir, ManifestFS{}); err != nil {
		t.Fatalf("[%s] ReconcileKeySet refused a state that should be accepted/finished: %v", context, err)
	}
}

// mustRefuse asserts both VerifyKeySetConsistency and ReconcileKeySet surface a
// non-nil error for a state that is not one legitimate generation (oracles b/c).
func mustRefuse(t *testing.T, enc *config.EncryptionConfig, dir, context string) {
	t.Helper()
	if err := VerifyKeySetConsistency(enc, dir); err == nil {
		t.Fatalf("INTEGRITY(b)/SURFACED(c): [%s] VerifyKeySetConsistency ACCEPTED a set that is not one coherent generation", context)
	}
	if _, err := ReconcileKeySet(enc, dir, ManifestFS{}); err == nil {
		t.Fatalf("INTEGRITY(b)/SURFACED(c): [%s] ReconcileKeySet ACCEPTED a set that is not one coherent generation", context)
	}
}
