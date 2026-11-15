package auditverify

// LIB-FUZZ-2 target 2a: a hostile SQLite file as the verifier's input.
//
// Inventory. `keyorix admin audit verify --sqlite <file>` opens an operator-named
// SQLite file with OpenSQLiteReadOnly (file:<path>?mode=ro) and runs the verifier
// queries (EventRange, GetSystemMetadata, StreamAuditEvents, LatestCheckpoint,
// ...). The file is by design an artifact that may have been tampered with: a
// copy taken from a live deployment, a restored backup, an auditor-supplied
// export (doc.go puts a corrupted or crafted file in scope). So every byte of
// the file reaches modernc.org/sqlite's pager, B-tree and record decoder before
// keyorix sees a single row, and then reaches scanAuditEventRow and the hash walk.
//
// The mutator works on the bytes of a small valid audit database (512-byte
// pages, 6 chained rows), so most inputs keep a readable schema and reach the
// verifier queries instead of dying at the 16-byte header.
//
// Oracles, none of which trusts the verifier under test:
//   - no panic, and each open+verify finishes inside the Guard deadline;
//   - read-only means read-only: after the run the directory holds exactly the
//     same entries and the database file the same bytes (no -journal, -wal or
//     -shm created beside it, no page written back);
//   - a VALID verdict implies an independent re-walk of the file (its own SQL,
//     its own hashing, nothing from walkChain) finds an unbroken chain.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// buildSmallAuditDB writes a 512-byte-page SQLite audit database with n chained
// events and returns its bytes. Only the seed uses production hashing; the
// oracle below has its own.
func buildSmallAuditDB(tb testing.TB, n int, mutate func(db *sql.DB)) []byte {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "seed.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		tb.Fatal(err)
	}
	for _, stmt := range []string{
		`PRAGMA page_size=512`,
		`PRAGMA journal_mode=DELETE`,
		`CREATE TABLE audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT, user_id INTEGER, secret_node_id INTEGER, project_id INTEGER,
			ip_address TEXT, description TEXT, success BOOLEAN, event_time DATETIME, diff TEXT,
			impersonated_by INTEGER, acting_as INTEGER, impersonation BOOLEAN, actor_type TEXT,
			machine_identity_id INTEGER, prev_hash TEXT, entry_hash TEXT)`,
		`CREATE TABLE audit_checkpoints (
			id INTEGER PRIMARY KEY AUTOINCREMENT, chained_events INTEGER, head_id INTEGER,
			head_hash TEXT, key_version TEXT, signature TEXT, anchor_token BLOB,
			anchored_at DATETIME, anchor_provider TEXT, created_at DATETIME)`,
		`CREATE TABLE system_metadata (key TEXT PRIMARY KEY, value TEXT, updated_at DATETIME)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			tb.Fatal(err)
		}
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tr := true
	prev := GenesisHash
	for i := range n {
		row := &AuditEventRow{
			EventType: "secret.read", IPAddress: "10.0.0.1", Description: fmt.Sprintf("event %d", i),
			Success: &tr, EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
		}
		h := ComputeEntryHash(row, prev)
		if _, err := db.Exec(`INSERT INTO audit_events (event_type, ip_address, description, success, event_time, diff, impersonation, actor_type, prev_hash, entry_hash)
			VALUES (?,?,?,?,?,?,?,?,?,?)`, row.EventType, row.IPAddress, row.Description, true, row.EventTime, "", false, row.ActorType, prev, h); err != nil {
			tb.Fatal(err)
		}
		prev = h
	}
	if mutate != nil {
		mutate(db)
	}
	if err := db.Close(); err != nil {
		tb.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// ---- independent chain oracle ---------------------------------------------

// independentChainBroken re-walks the file with its own SQL and its own hash and
// returns why the chain is not an unbroken, genesis-anchored one ("" if it is).
// It encodes only what a VALID verdict with no keys supplied must imply.
func independentChainBroken(path string) (string, error) {
	// t.TempDir() keeps "#" and "%" from a subtest name (seed#0), which a URI would
	// read as a fragment and an escape: the harness escapes its own path.
	db, err := sql.Open("sqlite", "file:"+strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path)+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT id, event_type, user_id, secret_node_id, project_id, ip_address, description,
		success, event_time, diff, impersonated_by, acting_as, impersonation, actor_type, prev_hash, entry_hash
		FROM audit_events ORDER BY id ASC`)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	prev, chained := GenesisHash, false
	for rows.Next() {
		var (
			id                               int64
			typ, ip, desc, diff, actor, p, e string
			uid, sid, pid, imp, act          sql.NullInt64
			succ                             sql.NullBool
			ts                               time.Time
			impersonation                    bool
		)
		if err := rows.Scan(&id, &typ, &uid, &sid, &pid, &ip, &desc, &succ, &ts, &diff, &imp, &act, &impersonation, &actor, &p, &e); err != nil {
			return "", err
		}
		if e == "" {
			if chained {
				return fmt.Sprintf("row %d has no entry_hash inside the chained region", id), nil
			}
			continue // legacy row before the chain starts
		}
		if !chained {
			chained = true
			if p != GenesisHash {
				return fmt.Sprintf("row %d starts the chain with a non-genesis prev_hash", id), nil
			}
		}
		if p != prev {
			return fmt.Sprintf("row %d prev_hash does not link to the previous entry_hash", id), nil
		}
		if e != oracleHash(p, typ, uid, sid, pid, ip, desc, succ, ts, diff, imp, act, impersonation, actor) {
			return fmt.Sprintf("row %d entry_hash does not match its contents", id), nil
		}
		prev = e
	}
	return "", rows.Err()
}

func oracleHash(prev, typ string, uid, sid, pid sql.NullInt64, ip, desc string, succ sql.NullBool, ts time.Time, diff string, imp, act sql.NullInt64, impersonation bool, actor string) string {
	h := sha256.New()
	put := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		h.Write(l[:])
		h.Write([]byte(s))
	}
	n := func(v sql.NullInt64) string {
		if !v.Valid {
			return ""
		}
		return strconv.FormatInt(v.Int64, 10)
	}
	b := ""
	if succ.Valid {
		b = strconv.FormatBool(succ.Bool)
	}
	for _, s := range []string{prev, typ, n(uid), n(sid), n(pid), ip, desc, b, strconv.FormatInt(ts.UnixMicro(), 10), diff, n(imp), n(act), strconv.FormatBool(impersonation), actor} {
		put(s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---- directory oracle -------------------------------------------------------

func dirSnapshot(tb testing.TB, dir string) map[string]string {
	tb.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		tb.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			tb.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// withoutKnownWALSidecars drops the -wal and -shm entries SQLite creates when
// it opens a file whose header says WAL (journal-mode bytes 18/19 == 2): a
// keyorix-side defect (issue #4350, which also covers the read-only-directory
// failure) that the oracle tolerates for exactly those two names and only for
// such a file. The database file's own bytes and every other entry still must
// not change. Delete this function when #4350 is fixed.
func withoutKnownWALSidecars(base string, before, after map[string]string) map[string]string {
	db := before[base]
	if len(db) < 20 || (db[18] != 2 && db[19] != 2) {
		return after
	}
	out := map[string]string{}
	for k, v := range after {
		if _, existed := before[k]; !existed && (k == base+"-wal" || k == base+"-shm") {
			continue
		}
		out[k] = v
	}
	return out
}

// checkHostileFileRun is the oracle for one open+verify of a hostile file.
func checkHostileFileRun(verdict Verdict, verified bool, path string, before, after map[string]string) error {
	after = withoutKnownWALSidecars(filepath.Base(path), before, after)
	if !reflect.DeepEqual(before, after) {
		var names []string
		for k := range after {
			if _, ok := before[k]; !ok {
				names = append(names, k)
			}
		}
		return fmt.Errorf("read-only verification changed the directory (new entries %v, or the database bytes changed)", names)
	}
	if verified && verdict == VerdictValid {
		why, err := independentChainBroken(path)
		if err != nil {
			return fmt.Errorf("verifier said VALID for a file the independent walk cannot read: %w", err)
		}
		if why != "" {
			return errors.New("verifier said VALID but " + why)
		}
	}
	return nil
}

func FuzzAuditVerifyHostileSQLiteFile(f *testing.F) {
	valid := buildSmallAuditDB(f, 6, nil)
	f.Add(valid)
	f.Add(buildSmallAuditDB(f, 6, func(db *sql.DB) { // content tampered, hash stale
		_, _ = db.Exec(`UPDATE audit_events SET description='forged' WHERE id=3`)
	}))
	f.Add(buildSmallAuditDB(f, 6, func(db *sql.DB) { // a middle row removed
		_, _ = db.Exec(`DELETE FROM audit_events WHERE id=3`)
	}))
	f.Add(buildSmallAuditDB(f, 6, func(db *sql.DB) { // negative ids, NULLs
		_, _ = db.Exec(`UPDATE audit_events SET user_id=-1 WHERE id=2`)
		_, _ = db.Exec(`UPDATE audit_events SET success=NULL WHERE id=4`)
	}))
	wal := append([]byte{}, valid...)
	wal[18], wal[19] = 2, 2 // header says WAL: opening it drops -wal/-shm beside the file (#4350, tolerated)
	f.Add(wal)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.db")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		before := dirSnapshot(t, dir)
		var (
			verdict  Verdict
			verified bool
		)
		fuzzutil.Guard(t.Fatalf, "OpenSQLiteReadOnly+Verify", func() {
			db, err := OpenSQLiteReadOnly(path)
			if err != nil {
				return
			}
			defer func() { _ = db.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*fuzzutil.GuardTimeout)
			defer cancel()
			res, err := Verify(ctx, db, Options{Now: func() time.Time { return time.Unix(0, 0) }})
			if err != nil || res == nil {
				return
			}
			verdict, verified = res.Verdict, true
		})
		if err := checkHostileFileRun(verdict, verified, path, before, dirSnapshot(t, dir)); err != nil {
			t.Fatal(err)
		}
	})
}

// TestHostileFileOracle_RedProof plants each fault the oracle exists to catch and
// requires it to be named, and requires the unplanted run to pass.
func TestHostileFileOracle_RedProof(t *testing.T) {
	write := func(b []byte) (dir, path string) {
		dir = t.TempDir()
		path = filepath.Join(dir, "audit.db")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir, path
	}

	good := buildSmallAuditDB(t, 6, nil)
	dir, path := write(good)
	snap := dirSnapshot(t, dir)
	// The verifier agrees with the independent walk on a genuine chain.
	db, err := OpenSQLiteReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(context.Background(), db, Options{})
	_ = db.Close()
	if err != nil || res.Verdict != VerdictValid {
		t.Fatalf("seed chain is not VALID: %v %+v", err, res)
	}
	if err := checkHostileFileRun(res.Verdict, true, path, snap, dirSnapshot(t, dir)); err != nil {
		t.Fatalf("oracle rejects a genuine, read-only run: %v", err)
	}

	// Planted: a verifier that answers VALID for a tampered chain.
	for name, mut := range map[string]func(*sql.DB){
		"edited row":       func(db *sql.DB) { _, _ = db.Exec(`UPDATE audit_events SET description='forged' WHERE id=3`) },
		"deleted row":      func(db *sql.DB) { _, _ = db.Exec(`DELETE FROM audit_events WHERE id=3`) },
		"re-linked row":    func(db *sql.DB) { _, _ = db.Exec(`UPDATE audit_events SET prev_hash=? WHERE id=2`, GenesisHash) },
		"emptied hash":     func(db *sql.DB) { _, _ = db.Exec(`UPDATE audit_events SET entry_hash='' WHERE id=4`) },
		"non-genesis head": func(db *sql.DB) { _, _ = db.Exec(`DELETE FROM audit_events WHERE id=1`) },
	} {
		dir, path := write(buildSmallAuditDB(t, 6, mut))
		if err := checkHostileFileRun(VerdictValid, true, path, dirSnapshot(t, dir), dirSnapshot(t, dir)); err == nil {
			t.Errorf("oracle accepted VALID for a tampered chain (%s)", name)
		}
	}

	// Planted: a verifier that wrote beside the database / into it.
	if err := os.WriteFile(filepath.Join(dir, "audit.db-shm"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkHostileFileRun(VerdictBroken, true, path, snap, dirSnapshot(t, dir)); err == nil {
		t.Error("oracle missed a -shm file created beside the database")
	}
	_ = os.Remove(filepath.Join(dir, "audit.db-shm"))
	if err := os.WriteFile(path, bytes.ToUpper(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkHostileFileRun(VerdictBroken, true, path, snap, dirSnapshot(t, dir)); err == nil {
		t.Error("oracle missed a rewritten database file")
	}

	// The #4350 exemption is exactly the WAL sidecars of a WAL-header file.
	walBytes := append([]byte{}, good...)
	walBytes[18], walBytes[19] = 2, 2
	wdir, wpath := write(walBytes)
	wsnap := dirSnapshot(t, wdir)
	for _, name := range []string{"audit.db-wal", "audit.db-shm"} {
		if err := os.WriteFile(filepath.Join(wdir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkHostileFileRun(VerdictBroken, true, wpath, wsnap, dirSnapshot(t, wdir)); err != nil {
		t.Errorf("the known WAL-sidecar behaviour should be tolerated for a WAL file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wdir, "audit.db-journal"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkHostileFileRun(VerdictBroken, true, wpath, wsnap, dirSnapshot(t, wdir)); err == nil {
		t.Error("the WAL exemption hid a -journal file")
	}
	_ = os.Remove(filepath.Join(wdir, "audit.db-journal"))
	if err := os.WriteFile(wpath, append(append([]byte{}, walBytes...), 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkHostileFileRun(VerdictBroken, true, wpath, wsnap, dirSnapshot(t, wdir)); err == nil {
		t.Error("the WAL exemption hid a rewritten database file")
	}
}
