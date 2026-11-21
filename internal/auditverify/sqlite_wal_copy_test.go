package auditverify

// #4350: a WAL-mode SQLite artifact is verified from a private copy, so a
// read-only evidence directory works, nothing appears beside the artifact,
// and an un-checkpointed -wal shipped with the copy is still read.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// writeWALAuditDB writes an n-row chained audit database into dir/audit.db and
// switches it to WAL mode (a persistent header flag), as storage/factory_local.go
// does for every keyorix database, then closes it cleanly (no sidecars left).
func writeWALAuditDB(t *testing.T, dir string, n int) string {
	t.Helper()
	path := filepath.Join(dir, "audit.db")
	if err := os.WriteFile(path, buildSmallAuditDB(t, n, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode=WAL`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode=WAL: %q %v", mode, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	hdr, err := os.ReadFile(path)
	if err != nil || len(hdr) < 20 || hdr[18] != 2 || hdr[19] != 2 {
		t.Fatalf("premise: header does not say WAL (%v)", err)
	}
	return path
}

// readOnlyDir makes dir read-only for the rest of the test.
func readOnlyDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if f, err := os.Create(filepath.Join(dir, "probe")); err == nil { // running as root
		_ = f.Close()
		t.Skip("directory permissions are not enforced for this user")
	}
}

// privateTMPDIR points os.MkdirTemp at a fresh directory and returns it, so a
// test can see that the private copy is gone afterwards.
func privateTMPDIR(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	t.Setenv("TMPDIR", d)
	return d
}

func assertEmptyDir(t *testing.T, dir, what string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("%s: left behind %v", what, names)
	}
}

func verifySQLiteFile(t *testing.T, path string) *Result {
	t.Helper()
	db, err := OpenSQLiteReadOnly(path)
	if err != nil {
		t.Fatalf("OpenSQLiteReadOnly: %v", err)
	}
	res, err := Verify(context.Background(), db, Options{})
	if cerr := db.Close(); cerr != nil {
		t.Errorf("Close: %v", cerr)
	}
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return res
}

// Test A: a WAL-mode artifact in a read-only directory verifies.
func TestOpenSQLiteReadOnly_WALFileInReadOnlyDirVerifies(t *testing.T) {
	tmp := privateTMPDIR(t)
	dir := t.TempDir()
	path := writeWALAuditDB(t, dir, 6)
	readOnlyDir(t, dir)

	res := verifySQLiteFile(t, path)
	if res.Verdict != VerdictValid || res.ChainedEvents != 6 {
		t.Fatalf("verdict %s, %d chained events (want VALID, 6): %s", res.Verdict, res.ChainedEvents, res.Reason)
	}
	assertEmptyDir(t, tmp, "private copy after Close")
}

// Test B: verifying a WAL-mode artifact in a writable directory leaves the
// directory listing and every file's bytes exactly as they were.
func TestOpenSQLiteReadOnly_WALFileLeavesDirectoryUnchanged(t *testing.T) {
	tmp := privateTMPDIR(t)
	dir := t.TempDir()
	path := writeWALAuditDB(t, dir, 6)
	before := dirSnapshot(t, dir)

	res := verifySQLiteFile(t, path)
	if res.Verdict != VerdictValid {
		t.Fatalf("verdict %s: %s", res.Verdict, res.Reason)
	}
	if after := dirSnapshot(t, dir); !reflect.DeepEqual(before, after) {
		var names []string
		for k := range after {
			names = append(names, k)
		}
		t.Fatalf("verification changed the artifact directory: now holds %v", names)
	}
	assertEmptyDir(t, tmp, "private copy after Close")
}

// Test C: an un-checkpointed row that lives only in the -wal shipped with the
// copy is part of what is verified (immutable=1 would silently drop it).
func TestOpenSQLiteReadOnly_UncheckpointedWALRowIsVerified(t *testing.T) {
	privateTMPDIR(t)
	src := t.TempDir()
	path := writeWALAuditDB(t, src, 5)

	w, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	w.SetMaxOpenConns(1)
	if _, err := w.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	var prev string
	if err := w.QueryRow(`SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil {
		t.Fatal(err)
	}
	tr := true
	row := &AuditEventRow{
		EventType: "secret.read", IPAddress: "10.0.0.1", Description: "event 5", Success: &tr,
		EventTime: time.Date(2026, 1, 1, 0, 0, 5, 0, time.UTC), ActorType: "user",
	}
	if _, err := w.Exec(`INSERT INTO audit_events (event_type, ip_address, description, success, event_time, diff, impersonation, actor_type, prev_hash, entry_hash)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, row.EventType, row.IPAddress, row.Description, true, row.EventTime, "", false, row.ActorType, prev, ComputeEntryHash(row, prev)); err != nil {
		t.Fatal(err)
	}

	// The copy an operator ships: the main file and its -wal (the runbook also
	// ships the -shm), taken while the writer still has the database open (so
	// the -wal is not checkpointed).
	shipped := map[string][]string{
		"db and -wal":       {"audit.db", "audit.db-wal"},
		"db, -wal and -shm": {"audit.db", "audit.db-wal", "audit.db-shm"},
	}
	evidence := map[string]string{}
	for set, names := range shipped {
		evidence[set] = t.TempDir()
		for _, name := range names {
			b, err := os.ReadFile(filepath.Join(src, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(evidence[set], name), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = w.Close()

	// Premise: the main file alone holds only 5 rows; the 6th is in the -wal.
	mainOnly := t.TempDir()
	b, err := os.ReadFile(filepath.Join(evidence["db and -wal"], "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mainOnly, "audit.db"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	im, err := sql.Open("sqlite", "file:"+strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(filepath.Join(mainOnly, "audit.db"))+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := im.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("premise: main file without its -wal should hold 5 rows, holds %d (%v)", n, err)
	}
	_ = im.Close()

	for set, dir := range evidence {
		before := dirSnapshot(t, dir)
		readOnlyDir(t, dir)
		res := verifySQLiteFile(t, filepath.Join(dir, "audit.db"))
		if res.Verdict != VerdictValid || res.ChainedEvents != 6 {
			t.Fatalf("%s: verdict %s, %d chained events (want VALID with the -wal row, 6): %s", set, res.Verdict, res.ChainedEvents, res.Reason)
		}
		if after := dirSnapshot(t, dir); !reflect.DeepEqual(before, after) {
			t.Fatalf("%s: verification changed the evidence directory or a file in it", set)
		}
	}
}

// The private copy is removed when the copy itself fails, and the error says
// which file could not be copied.
func TestOpenSQLiteReadOnly_CopyFailureLeavesNothingBehind(t *testing.T) {
	tmp := privateTMPDIR(t)
	dir := t.TempDir()
	path := writeWALAuditDB(t, dir, 3)
	wal := path + "-wal"
	if err := os.WriteFile(wal, nil, 0o000); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(wal); err == nil { // running as root
		_ = f.Close()
		t.Skip("file permissions are not enforced for this user")
	}
	_, err := OpenSQLiteReadOnly(path)
	if err == nil || !strings.Contains(err.Error(), "audit.db-wal") {
		t.Fatalf("want an error naming the -wal that could not be copied, got %v", err)
	}
	assertEmptyDir(t, tmp, "private copy after a failed copy")
}
