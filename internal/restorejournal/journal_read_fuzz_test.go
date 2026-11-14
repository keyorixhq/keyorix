package restorejournal

// FuzzJournalRead feeds arbitrary bytes to Read — the parser of the on-disk
// restore journal (.keyorix-restore-journal.json, journal.go). The journal is
// left behind by a `keyorix-server admin restore` killed mid-install and is
// read at boot: while a journal is present the server refuses to start
// (RefuseIfPresent), and `admin restore --recover` acts on what Read returns. A
// process killed during Write, or a damaged filesystem, can leave a truncated
// or garbage journal, so Read must parse it safely or reject it, never crash,
// and must never hand back a journal written in a format this binary does not
// understand.
//
// ORACLE (fail-closed version gate + never-panic):
//   - Read never panics on arbitrary file bytes.
//   - A journal Read reports as successfully parsed (found==true, err==nil) ALWAYS
//     has Version == the version this binary reads. Read's own contract is that
//     "a journal that exists but does not parse is an error, never absent" and a
//     version mismatch is such an error; recovery must never run against a
//     foreign-format journal it would misinterpret.
//   - Round-trip for an entry-less journal: a parsed journal re-written through
//     Write and read back is deep-equal to the first parse (the serializer and
//     parser agree on the fields recovery depends on).
//
// WHAT THIS DOES NOT VERIFY:
//   - It does not exercise the durability machinery (SyncEntryDirs / fsync /
//     atomic rename) under faults; TempDir writes are used.
//   - The round-trip is limited to journals with no Entries, because Write
//     fsyncs each entry's staged-file directory (SyncEntryDirs), which does not
//     exist for fuzzed paths. Entry parsing itself is still covered by the
//     version/never-panic oracle above.
//   - No semantic validation of recovery fields (Token, Installed, witness
//     values); Read is a pure decode + version check.
import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func FuzzJournalRead(f *testing.F) {
	f.Add([]byte(`{"version":1,"backend":"sqlite","timestamp":"t","entries":[]}`))
	f.Add([]byte(`{"version":1,"backend":"postgres","token":"tok","timestamp":"t","overwrite":true,"entries":[{"path":"/a","staged":"/a.staged","sha256":"h"}],"installed":true}`))
	f.Add([]byte(`{"version":2,"backend":"sqlite"}`)) // wrong version — must be an error, not a usable journal
	f.Add([]byte(`{"version":0}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, FileName)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skipf("could not write fixture: %v", err)
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Read panicked on %q: %v", data, r)
			}
		}()

		j, found, err := Read(path)
		if err != nil {
			return // a journal that does not parse (incl. wrong version) is an error — safe
		}
		if !found {
			return // only ErrNotExist, which cannot happen for a file we just wrote
		}
		// Parsed successfully: it MUST be a version this binary reads.
		if j.Version != Version {
			t.Fatalf("Read returned a usable journal with Version=%d (this binary reads %d) from %q", j.Version, Version, data)
		}

		// Round-trip for an entry-less journal (Write fsyncs entry dirs that do
		// not exist for fuzzed paths, so only the no-entry case is driven here).
		if len(j.Entries) != 0 {
			return
		}
		path2 := filepath.Join(dir, "rewritten.json")
		if err := Write(path2, j); err != nil {
			t.Fatalf("Write failed for a journal Read accepted (%q): %v", data, err)
		}
		j2, found2, err := Read(path2)
		if err != nil || !found2 {
			t.Fatalf("re-written journal failed to reload (found=%v err=%v) from %q", found2, err, data)
		}
		if !reflect.DeepEqual(j, j2) {
			t.Fatalf("journal round-trip mismatch:\n input  %q\n first  %+v\n reload %+v", data, j, j2)
		}
	})
}
