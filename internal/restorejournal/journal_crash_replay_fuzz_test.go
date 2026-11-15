//go:build !windows

package restorejournal_test

// journal_crash_replay_fuzz_test.go — FuzzRestoreJournalCrashReplay (FS1).
//
// `admin restore` stages new files, writes this journal, then commits; a crash
// in between leaves the journal, and the server refuses to start until
// `admin restore --recover` finishes or undoes the restore. The journal's own
// durability layer (Read/Write/HashFile) is what every recovery decision rests
// on: Read must never silently accept a torn journal (that would let a
// half-installed restore look like "nothing to recover"), and the per-entry
// SHA-256 is the gate recovery uses to refuse installing a torn/tampered staged
// file (Entry.SHA256 doc: "Recovery installs a staged file only if it still
// hashes to this").
//
// This target manufactures post-crash states of the journal file and of the
// staged files, and drives the REAL Read / Write / HashFile. No production hook
// is needed (the layer is a pure function of bytes on disk).
//
// Oracles (and what each does NOT verify):
//
//	(a) ROUND-TRIP / NO LOSS — a journal Write then Read returns the same
//	    journal, version-stamped. DOES NOT verify fsync durability under a power
//	    cut (covered by scripts/powercut) — only the logical round-trip.
//	(c) SURFACED — an EXISTING journal that is truncated, garbled, or a wrong
//	    version is an error from Read, never found=false (silent "no journal to
//	    recover") and never found=true with a usable zero-value journal.
//	(b) STAGED-FILE INTEGRITY — the recovery install-gate (HashFile(staged) ==
//	    recorded SHA256) rejects a tampered or truncated staged file and errors
//	    on a missing one, so a torn staged file is never mistaken for the
//	    recorded content. DOES NOT verify the install/undo decision itself in
//	    server/admin/restore.go (that needs a full server config + DB; this
//	    fuzzes the journal layer that decision depends on — stated as a scope
//	    limit in the FS1 report).
//	ROBUSTNESS — Read never panics on arbitrary journal bytes.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/restorejournal"
)

func FuzzRestoreJournalCrashReplay(f *testing.F) {
	f.Add(byte(0), uint16(0), []byte("staged-content-A"), []byte("staged-content-B"), byte(1))
	f.Add(byte(1), uint16(5), []byte{}, []byte("x"), byte(0))
	f.Add(byte(2), uint16(9999), []byte("same"), []byte("same"), byte(2))
	f.Add(byte(3), uint16(3), []byte("one"), []byte("two"), byte(3))
	f.Add(byte(4), uint16(1), []byte("a"), []byte("b"), byte(4))
	f.Add(byte(5), uint16(2), []byte("db-bytes"), []byte("key-bytes"), byte(5))

	f.Fuzz(func(t *testing.T, journalMut byte, truncK uint16, stagedA, stagedB []byte, stagedMut byte) {
		dir := t.TempDir()
		jpath := filepath.Join(dir, restorejournal.FileName)

		// Two staged files with recorded SHA-256, as a real restore would record.
		stagedAPath := filepath.Join(dir, "fileA.restoring")
		stagedBPath := filepath.Join(dir, "fileB.restoring")
		if err := os.WriteFile(stagedAPath, stagedA, 0o600); err != nil {
			t.Fatalf("write stagedA: %v", err)
		}
		if err := os.WriteFile(stagedBPath, stagedB, 0o600); err != nil {
			t.Fatalf("write stagedB: %v", err)
		}
		j := restorejournal.Journal{
			Backend:        "sqlite",
			Timestamp:      "20261114T000000Z",
			CompletedEvent: "restore-completed",
			Entries: []restorejournal.Entry{
				{Path: filepath.Join(dir, "fileA"), Staged: stagedAPath, SHA256: restorejournal.HashBytes(stagedA)},
				{Path: filepath.Join(dir, "fileB"), Staged: stagedBPath, SHA256: restorejournal.HashBytes(stagedB), SQLiteDB: true},
			},
		}

		// ── oracle (a): write then read round-trips ───────────────────────
		if err := restorejournal.Write(jpath, j); err != nil {
			t.Fatalf("Write: %v", err)
		}
		got, found, err := restorejournal.Read(jpath)
		if err != nil || !found {
			t.Fatalf("baseline Read: found=%v err=%v (want found, no error)", found, err)
		}
		if got.Version != restorejournal.Version || len(got.Entries) != 2 {
			t.Fatalf("baseline round-trip mismatch: version=%d entries=%d", got.Version, len(got.Entries))
		}
		for i, e := range got.Entries {
			if e.SHA256 != j.Entries[i].SHA256 {
				t.Fatalf("round-trip lost entry %d SHA256", i)
			}
		}

		// ── oracle (b): the recovery install-gate rejects torn staged files ─
		// Mutate a staged file, then assert HashFile detects it (so recovery,
		// which installs only if HashFile==recorded, would refuse it).
		recorded := j.Entries[0].SHA256
		switch stagedMut % 4 {
		case 0:
			// unchanged — HashFile must still match.
			h, herr := restorejournal.HashFile(stagedAPath)
			if herr != nil || h != recorded {
				t.Fatalf("STAGED INTEGRITY(b): unchanged staged file no longer matches its recorded hash: h=%q rec=%q err=%v", h, recorded, herr)
			}
		case 1:
			// truncated — must NOT match (unless it was already empty).
			k := min(int(truncK), len(stagedA))
			if err := os.WriteFile(stagedAPath, stagedA[:k], 0o600); err != nil {
				t.Fatalf("truncate stagedA: %v", err)
			}
			h, herr := restorejournal.HashFile(stagedAPath)
			if herr == nil && h == recorded && k != len(stagedA) {
				t.Fatalf("STAGED INTEGRITY(b): a TRUNCATED staged file still matched its recorded hash — recovery would install torn content")
			}
		case 2:
			// tampered — append a byte; must not match.
			if err := os.WriteFile(stagedAPath, append(append([]byte(nil), stagedA...), 'Z'), 0o600); err != nil {
				t.Fatalf("tamper stagedA: %v", err)
			}
			h, herr := restorejournal.HashFile(stagedAPath)
			if herr == nil && h == recorded {
				t.Fatalf("STAGED INTEGRITY(b): a TAMPERED staged file still matched its recorded hash")
			}
		default:
			// deleted — HashFile must error (recovery then checks Path instead,
			// never treats a lost staged file as "installed").
			if err := os.Remove(stagedAPath); err != nil {
				t.Fatalf("remove stagedA: %v", err)
			}
			if _, herr := restorejournal.HashFile(stagedAPath); herr == nil {
				t.Fatalf("STAGED INTEGRITY(b): HashFile of a DELETED staged file did not error")
			}
		}

		// ── oracle (c): manufacture a torn journal and read it back ────────
		mutated, kind := mutateJournal(t, jpath, int(journalMut), int(truncK))
		if err := os.WriteFile(jpath, mutated, 0o600); err != nil {
			t.Fatalf("write mutated journal: %v", err)
		}
		rj, rfound, rerr := restorejournal.Read(jpath)

		// Does the raw mutated content parse as a v1 journal at all?
		var probe restorejournal.Journal
		parses := json.Unmarshal(mutated, &probe) == nil && probe.Version == restorejournal.Version

		switch {
		case parses:
			// A well-formed v1 journal must read cleanly.
			if rerr != nil || !rfound {
				t.Fatalf("SURFACED-WRONG: a parseable v1 journal (%s) failed Read: found=%v err=%v", kind, rfound, rerr)
			}
		default:
			// Not a well-formed v1 journal, and the file EXISTS (it was just
			// written above), including the empty and whitespace-only shapes.
			// Read must surface an error and report the file as found: an
			// existing journal read as found=false,nil makes `admin restore
			// --recover` remove the staged files a forward recovery needs.
			if rerr == nil {
				t.Fatalf("SILENT(c): an existing non-v1 journal (%s) read back with no error: found=%v version=%d bytes=%q", kind, rfound, rj.Version, truncForMsg(mutated))
			}
			if !rfound {
				t.Fatalf("SILENT-ABSENT(c): an existing journal (%s) errored but reported found=false: %v", kind, rerr)
			}
		}
	})
}

// mutateJournal reads the on-disk journal and returns a post-crash shape.
func mutateJournal(t *testing.T, jpath string, sel, truncK int) ([]byte, string) {
	t.Helper()
	orig, err := os.ReadFile(jpath)
	if err != nil {
		t.Fatalf("read journal for mutation: %v", err)
	}
	switch sel % 6 {
	case 0:
		return orig, "unchanged"
	case 1:
		k := min(truncK, len(orig))
		return orig[:k], "truncated"
	case 2:
		b := append([]byte(nil), orig...)
		if len(b) > 0 {
			b[truncK%len(b)] ^= 0x20
		}
		return b, "bitflip"
	case 3:
		return append(append([]byte(nil), orig...), []byte("GARBAGE}}}")...), "appended"
	case 4:
		// valid JSON but wrong version (a journal from another binary).
		return []byte(`{"version": 999, "backend": "sqlite", "entries": []}`), "wrong-version"
	default:
		return []byte{}, "empty"
	}
}

func truncForMsg(b []byte) string {
	if len(b) > 64 {
		return string(b[:64]) + "..."
	}
	return string(b)
}
