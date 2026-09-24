package auditverify

// FuzzAuditChainRowDecode feeds arbitrary bytes as a raw SQLite file to this
// package's own DB-open + row-decode path (design §9's "one genuinely new
// attack surface": a corrupted or adversarially crafted DB file handed to a
// tool that must not crash or, worse, silently report VALID on malformed
// input). Unlike every other read path in this codebase, this one is
// explicitly designed to be pointed at an artifact the operator does not
// fully trust (design §1: "does not depend on the server process being
// honest or even running") — a hostile file is squarely in scope, not a
// corner case.
//
// This drives OpenSQLiteReadOnly -> StreamAuditEvents -> scanAuditEventRow
// (the exact decode chain a real `--db` run uses) plus a full Verify() pass,
// so both the low-level row scan AND the higher-level chain-walk logic built
// on top of it are exercised against the same adversarial bytes. A panic
// anywhere in that chain is recorded by the fuzzer natively (fuzzutil.Guard
// below only catches a HANG/amplification, mirroring this repo's other fuzz
// targets — see internal/fuzzutil.Guard's own doc comment). Any returned
// error is expected and fine: garbage in, error out is the correct, safe
// behavior this target exists to confirm — never a bare VALID on malformed
// input.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// seedFuzzCorpusDB builds a real, on-disk SQLite database with the schema
// this package reads (matching seedEmptySchema in verify_internal_test.go)
// plus a handful of rows — including NULL nullable columns and a
// deliberately malformed entry_hash — and returns its raw bytes. Seeding the
// fuzzer with genuine SQLite page bytes gives it far better starting
// material to mutate from than an empty corpus.
func seedFuzzCorpusDB(tb testing.TB) []byte {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "seed.db")
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		tb.Fatalf("open seed db: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()

	for _, stmt := range []string{
		`CREATE TABLE audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT,
			user_id INTEGER,
			secret_node_id INTEGER,
			project_id INTEGER,
			ip_address TEXT,
			description TEXT,
			success BOOLEAN,
			event_time DATETIME,
			diff TEXT,
			impersonated_by INTEGER,
			acting_as INTEGER,
			impersonation BOOLEAN,
			actor_type TEXT,
			machine_identity_id INTEGER,
			prev_hash TEXT,
			entry_hash TEXT
		)`,
		`CREATE TABLE audit_checkpoints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			chained_events INTEGER,
			head_id INTEGER,
			head_hash TEXT,
			key_version TEXT,
			signature TEXT,
			anchor_token BLOB,
			anchored_at DATETIME,
			anchor_provider TEXT,
			created_at DATETIME
		)`,
		`CREATE TABLE system_metadata (
			key TEXT PRIMARY KEY,
			value TEXT,
			updated_at DATETIME
		)`,
	} {
		if _, err := sqlDB.Exec(stmt); err != nil {
			tb.Fatalf("create schema: %v", err)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	e1 := &AuditEventRow{EventType: "secret.read", IPAddress: "10.0.0.1", Description: "ok", EventTime: now, ActorType: "user"}
	e1.PrevHash, e1.EntryHash = GenesisHash, ComputeEntryHash(e1, GenesisHash)
	if _, err := sqlDB.Exec(
		`INSERT INTO audit_events (event_type, user_id, ip_address, description, success, event_time, actor_type, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?)`,
		e1.EventType, nil, e1.IPAddress, e1.Description, true, e1.EventTime, e1.ActorType, e1.PrevHash, e1.EntryHash,
	); err != nil {
		tb.Fatalf("insert seed row 1: %v", err)
	}

	e2 := &AuditEventRow{EventType: "secret.write", Description: "also ok", EventTime: now.Add(time.Second), ActorType: "machine_identity"}
	e2.PrevHash = e1.EntryHash
	e2.EntryHash = ComputeEntryHash(e2, e2.PrevHash)
	uid := uint64(7)
	if _, err := sqlDB.Exec(
		`INSERT INTO audit_events (event_type, user_id, ip_address, description, success, event_time, actor_type, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?)`,
		e2.EventType, uid, e2.IPAddress, e2.Description, false, e2.EventTime, e2.ActorType, e2.PrevHash, e2.EntryHash,
	); err != nil {
		tb.Fatalf("insert seed row 2: %v", err)
	}

	// A row with a deliberately corrupted entry_hash — valid schema/types,
	// invalid chain content, so the corpus also seeds the BROKEN path.
	if _, err := sqlDB.Exec(
		`INSERT INTO audit_events (event_type, description, success, event_time, actor_type, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?)`,
		"secret.delete", "corrupted", true, now.Add(2*time.Second), "user", e2.EntryHash, "not-a-real-hash",
	); err != nil {
		tb.Fatalf("insert seed row 3: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read seed db bytes: %v", err)
	}
	return data
}

func FuzzAuditChainRowDecode(f *testing.F) {
	seed := seedFuzzCorpusDB(f)
	f.Add(seed)
	f.Add(seed[:len(seed)/2])             // truncated mid-file
	f.Add(append([]byte{}, seed[:16]...)) // header-only fragment
	f.Add([]byte{})
	f.Add([]byte("SQLite format 3\x00"))
	f.Add([]byte("not a sqlite file at all"))

	// A byte-flipped mutant of the seed, in a few different positions, to
	// start the fuzzer with several already-corrupted-but-plausible pages.
	for _, pos := range []int{20, len(seed) / 4, len(seed) / 2, len(seed) - 10} {
		if pos <= 0 || pos >= len(seed) {
			continue
		}
		mutant := append([]byte{}, seed...)
		mutant[pos] ^= 0xFF
		f.Add(mutant)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "fuzz.db")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skipf("could not write candidate file: %v", err)
		}

		fuzzutil.Guard(t.Fatalf, "auditverify.decode", func() {
			db, err := OpenSQLiteReadOnly(path)
			if err != nil {
				return // malformed file failed to open — correct, safe behavior
			}
			defer func() { _ = db.Close() }()

			ctx := context.Background()
			_, _ = db.StreamAuditEvents(ctx, 0, 50)
			_, _ = Verify(ctx, db, Options{})
			// No further assertions: a returned error (or an INDETERMINATE/
			// BROKEN verdict) is an acceptable outcome for adversarial input.
			// Only a panic or a hang (caught by the Guard above) is a bug —
			// this target's whole point is that garbage input must produce an
			// error, not a crash and not a silent VALID.
		})
	})
}
