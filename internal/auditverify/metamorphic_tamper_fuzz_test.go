package auditverify_test

// FuzzAuditChainMetamorphicTamper is the ACH1 metamorphic tamper target.
//
// It takes a FRESH, VALID, fully-checkpointed audit chain built through the
// real server write path (store.LocalStorage + core.KeyorixCore, exactly as
// differential_test.go does), applies ONE fuzz-driven structured mutation
// from a family (byte-flip, timestamp change, delete, truncate tail,
// duplicate, content-reorder, splice-from-another-log, replace-last-N,
// numeric nudge) and asserts the offline verifier's METAMORPHIC relation:
//
//   - if the mutation CHANGED the chain's authenticated content (the exact
//     16-column read-set auditverify.Verify authenticates — see db.go
//     auditEventColumns and hash.go ComputeEntryHash), Verify MUST NOT return
//     VALID. BROKEN / INDETERMINATE / SEALED, or a typed non-nil error, are
//     all acceptable "detected" outcomes; VALID is a MISS.
//   - if the mutation left the authenticated content byte-identical (a true
//     no-op, or a change confined to a column the verifier never reads, e.g.
//     machine_identity_id), Verify MUST return VALID — a BROKEN here would be
//     a false alarm (the verifier reacting to something it does not authenticate).
//
// The "authenticated content" fingerprint renders exactly the 16 columns the
// verifier reads (db.go auditEventColumns), over EVERY row in audit_events —
// including id 0, NULL ids and duplicate ids, which the keyset walk skips but
// the held==walked count guard reacts to (see fingerprintChain). event_time is
// rendered at UnixMicro precision, the same canonical form ComputeEntryHash
// hashes. This makes the fingerprint verdict-consistent by construction: a
// change the verifier cannot react to never changes the fingerprint, and
// vice versa.
//
// WHY A FULL-COVERAGE CHECKPOINT: every base chain is checkpointed AFTER its
// last event (head == max id) and verified WITH the checkpoint key. That
// closes the one ADR-029 gap a bare re-walk shares — a tail truncation below
// the checkpoint head is then detected via the signed chained-events count
// and head-hash (verify.go enforceCheckpoint). There are no post-checkpoint
// rows, so there is no legitimate "append a new validly-chained row beyond
// head" escape hatch (the one mutation that could change content yet stay
// VALID by design); the family never generates one.
//
// WHAT THIS TARGET DOES NOT VERIFY:
//   - It does not tamper the audit_checkpoints row, the high-water mark or the
//     retention anchor (metadata, not event content). Byte-level tamper of the
//     checkpoint signature / head hash is already owned by
//     tamper_exhaustive_test.go; forged-checkpoint and retention-anchor cases
//     by differential_test.go. Deleting the checkpoint while leaving the events
//     intact is a legitimately-VALID bare-walk outcome and is intentionally out
//     of this oracle's scope.
//   - It does not cover a coordinated MULTI-row re-chain (recompute every
//     downstream hash after editing one row) — that is a single logical edit
//     but many row writes; this target applies ONE mutation. The checkpoint
//     head-hash is what defends that case and is exercised by the truncate /
//     splice kinds that disturb the head.
//   - It does not exercise Postgres (SQLite file artifact only), key rotation
//     records, seals, break-glass, or the --anchor external-bundle path.
//   - The resguard meter is a SECONDARY bounded-work tripwire (wall + sampled
//     alloc) with ABSOLUTE, deliberately-generous ceilings, not the primary
//     oracle: it only fires on a gross (orders-of-magnitude) amplification, so
//     a within-ceiling slowdown is not caught. A true hang is caught by
//     `go test -timeout`, not here.

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// brd is a tiny deterministic consumer of the fuzz byte slice.
type brd struct {
	b []byte
	i int
}

func (r *brd) u8() byte {
	if r.i >= len(r.b) {
		r.i++ // keep advancing so distinct short inputs still differ
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

func (r *brd) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.u8()) % n
}

// authColumns are the exact audit_events columns the verifier reads
// (db.go auditEventColumns). Any text/int column here is a candidate for a
// byte-flip mutation.
var authTextColumns = []string{"event_type", "ip_address", "description", "diff", "actor_type", "prev_hash", "entry_hash"}

// fingerprintChain renders the authenticated surface of the audit_events table
// — EXACTLY the 16 columns auditverify.Verify reads (db.go auditEventColumns),
// over EVERY row including id 0, a NULL id and duplicate ids. The last three
// are critical: the verifier's keyset walk (id > ?) never visits them, but its
// held==walked count guard (verify.go, #3808) DOES react to their presence, so
// a fingerprint built from the keyset walk alone would miss a change the
// verifier detects (an id-0 insert reads as BROKEN while the walk-based
// fingerprint is unchanged — a harness false-alarm, not a verifier bug).
//
// event_time is rendered at UnixMicro precision — the exact form
// ComputeEntryHash hashes — so a representation-only change that leaves the
// instant identical does not spuriously change the fingerprint. The ordering
// (id, then every column) makes the rendering total and deterministic even for
// NULL/duplicate ids. machine_identity_id is deliberately absent: the verifier
// never reads it, so a change there must NOT change the fingerprint.
func fingerprintChain(f *diffFixture) string {
	rows, err := f.db.Raw(`SELECT id, event_type, user_id, secret_node_id, project_id, ip_address,
		description, success, event_time, diff, impersonated_by, acting_as, impersonation,
		actor_type, prev_hash, entry_hash
		FROM audit_events ORDER BY id IS NULL DESC, id ASC, prev_hash ASC, entry_hash ASC`).Rows()
	if err != nil {
		return "QUERY_ERR:" + err.Error()
	}
	defer func() { _ = rows.Close() }()

	var sb strings.Builder
	for rows.Next() {
		var (
			id                                      sql.NullInt64
			eventType, ipAddress, description, diff sql.NullString
			actorType, prevHash, entryHash          sql.NullString
			userID, secretNodeID, projectID         sql.NullInt64
			impersonatedBy, actingAs                sql.NullInt64
			success, impersonation                  sql.NullBool
			eventTime                               sql.NullTime
		)
		if err := rows.Scan(&id, &eventType, &userID, &secretNodeID, &projectID, &ipAddress,
			&description, &success, &eventTime, &diff, &impersonatedBy, &actingAs, &impersonation,
			&actorType, &prevHash, &entryHash); err != nil {
			return "SCAN_ERR:" + err.Error()
		}
		ni := func(v sql.NullInt64) string {
			if !v.Valid {
				return "∅"
			}
			return strconv.FormatInt(v.Int64, 10)
		}
		ns := func(v sql.NullString) string {
			if !v.Valid {
				return "∅"
			}
			return v.String
		}
		nb := func(v sql.NullBool) string {
			if !v.Valid {
				return "∅"
			}
			return strconv.FormatBool(v.Bool)
		}
		et := "∅"
		if eventTime.Valid {
			et = strconv.FormatInt(eventTime.Time.UnixMicro(), 10)
		}
		fmt.Fprintf(&sb, "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n",
			ni(id), ns(prevHash), ns(entryHash), ns(eventType), ni(userID), ni(secretNodeID),
			ni(projectID), ns(ipAddress), ns(description), nb(success), et, ns(diff),
			ni(impersonatedBy), ni(actingAs), nb(impersonation), ns(actorType))
	}
	if err := rows.Err(); err != nil {
		return "ROWS_ERR:" + err.Error()
	}
	return sb.String()
}

// bestEffortExec runs a raw tamper statement and ignores any error (a
// constraint violation / unknown column simply leaves the DB a no-op, which
// the fingerprint comparison then classifies correctly).
func bestEffortExec(f *diffFixture, sql string, args ...any) {
	_ = f.db.Exec(sql, args...).Error
}

// foreignRow is one record read out of an INDEPENDENT chain, used by the
// splice mutation.
type foreignRow struct {
	eventType, ipAddress, description, diff, actorType, prevHash, entryHash string
	eventTime                                                               time.Time
}

var (
	foreignOnce sync.Once
	foreignRows []foreignRow
)

// getForeignRows builds a second, independent chain (different content,
// different checkpoint epoch) ONCE, using the first fuzz iteration's *testing.T
// for a working TempDir, and caches its rows as splice material. The DB file is
// discarded after extraction (the foreignRow values are copied into memory).
func getForeignRows(t *testing.T) []foreignRow {
	foreignOnce.Do(func() {
		fx := newDiffFixture(t)
		fx.logEvents(8, 2*time.Hour) // different age => different timestamps/hashes
		if _, _, err := fx.core.WriteAuditCheckpoint(fx.ctx); err != nil {
			return
		}
		db, err := auditverify.OpenSQLiteReadOnly(fx.path)
		if err != nil {
			return
		}
		defer func() { _ = db.Close() }()
		batch, err := db.StreamAuditEvents(context.Background(), 0, 500)
		if err != nil {
			return
		}
		for _, e := range batch {
			foreignRows = append(foreignRows, foreignRow{
				eventType: e.EventType, ipAddress: e.IPAddress, description: e.Description,
				diff: e.Diff, actorType: e.ActorType, prevHash: e.PrevHash, entryHash: e.EntryHash,
				eventTime: e.EventTime,
			})
		}
	})
	if len(foreignRows) == 0 {
		return staticForeignRows()
	}
	return foreignRows
}

// staticForeignRows is a fallback splice source: well-formed-looking records
// whose hashes belong to no chain, so splicing one always breaks linkage.
func staticForeignRows() []foreignRow {
	rows := make([]foreignRow, 0, 4)
	for i := range 4 {
		rows = append(rows, foreignRow{
			eventType:   "secret.delete",
			ipAddress:   "10.0.0.1",
			description: fmt.Sprintf("foreign event %d", i),
			diff:        "",
			actorType:   "machine_identity",
			prevHash:    strings.Repeat(strconv.Itoa(i%10), 64),
			entryHash:   strings.Repeat(strconv.Itoa((i+5)%10), 64),
			eventTime:   time.Unix(1700000000+int64(i), 0).UTC(),
		})
	}
	return rows
}

// applyMutation performs exactly one fuzz-driven tamper. ids are the live row
// ids in ascending order. Returns a short label for diagnostics.
func applyMutation(r *brd, f *diffFixture, ids []uint64, foreign []foreignRow) string {
	if len(ids) == 0 {
		return "noop-empty"
	}
	kind := r.intn(11)
	pick := func() uint64 { return ids[r.intn(len(ids))] }

	switch kind {
	case 0: // byte-flip in a random authenticated text column of a random row
		col := authTextColumns[r.intn(len(authTextColumns))]
		id := pick()
		var cur string
		_ = f.db.Raw("SELECT "+col+" FROM audit_events WHERE id = ?", id).Scan(&cur).Error
		mut := flipOrSeed(cur, r)
		bestEffortExec(f, "UPDATE audit_events SET "+col+" = ? WHERE id = ?", mut, id)
		return "byteflip:" + col

	case 1: // timestamp change (authenticated via UnixMicro)
		id := pick()
		delta := int64(r.intn(100000)) - 50000
		bestEffortExec(f, "UPDATE audit_events SET event_time = ? WHERE id = ?",
			time.Now().UTC().Add(time.Duration(delta)*time.Second).Truncate(time.Microsecond), id)
		return "timestamp"

	case 2: // delete a random (possibly middle) row
		bestEffortExec(f, "DELETE FROM audit_events WHERE id = ?", pick())
		return "delete"

	case 3: // truncate tail below a random boundary
		cut := ids[r.intn(len(ids))]
		bestEffortExec(f, "DELETE FROM audit_events WHERE id > ?", cut)
		return "truncate-tail"

	case 4: // duplicate a row under id 0 (keyset walk never visits id 0)
		id := pick()
		bestEffortExec(f, `INSERT INTO audit_events
			(id, event_type, user_id, secret_node_id, project_id, ip_address, description, success,
			 event_time, diff, impersonated_by, acting_as, impersonation, actor_type, prev_hash, entry_hash)
			SELECT 0, event_type, user_id, secret_node_id, project_id, ip_address, description, success,
			 event_time, diff, impersonated_by, acting_as, impersonation, actor_type, prev_hash, entry_hash
			FROM audit_events WHERE id = ?`, id)
		return "duplicate-id0"

	case 5: // content-reorder: swap the full authenticated content of two rows
		if len(ids) < 2 {
			bestEffortExec(f, "UPDATE audit_events SET description = description WHERE id = ?", pick())
			return "noop-reorder"
		}
		a := ids[r.intn(len(ids))]
		b := ids[r.intn(len(ids))]
		if a == b {
			b = ids[(r.intn(len(ids))+1)%len(ids)]
		}
		swapContent(f, a, b)
		return "reorder-content"

	case 6: // splice: overwrite a row with a record from another log
		if len(foreign) == 0 {
			return "noop-splice"
		}
		fr := foreign[r.intn(len(foreign))]
		id := pick()
		bestEffortExec(f, `UPDATE audit_events SET event_type=?, ip_address=?, description=?, diff=?,
			actor_type=?, prev_hash=?, entry_hash=?, event_time=? WHERE id=?`,
			fr.eventType, fr.ipAddress, fr.description, fr.diff, fr.actorType, fr.prevHash, fr.entryHash,
			fr.eventTime, id)
		return "splice-foreign"

	case 7: // replace last N records' content
		n := 1 + r.intn(len(ids))
		for j := len(ids) - n; j < len(ids); j++ {
			if j < 0 {
				continue
			}
			bestEffortExec(f, "UPDATE audit_events SET description = ? WHERE id = ?",
				fmt.Sprintf("replaced-%d", r.u8()), ids[j])
		}
		return "replace-lastN"

	case 8: // numeric nudge on an authenticated nullable int column
		cols := []string{"user_id", "project_id", "secret_node_id"}
		col := cols[r.intn(len(cols))]
		id := pick()
		bestEffortExec(f, "UPDATE audit_events SET "+col+" = COALESCE("+col+",0) + 1 WHERE id = ?", id)
		return "numeric-nudge:" + col

	case 9: // CONTROL: true no-op (set description to itself) -> must stay VALID
		bestEffortExec(f, "UPDATE audit_events SET description = description WHERE id = ?", pick())
		return "control-noop"

	case 10: // CONTROL: mutate a column the verifier never reads -> must stay VALID
		bestEffortExec(f, "UPDATE audit_events SET machine_identity_id = COALESCE(machine_identity_id,0) + 1 WHERE id = ?", pick())
		return "control-unauth-col"
	}
	return "unreached"
}

func swapContent(f *diffFixture, a, b uint64) {
	type rowc struct {
		EventType   string
		IPAddress   string
		Description string
		Diff        string
		ActorType   string
		PrevHash    string
		EntryHash   string
		EventTime   time.Time
	}
	var ra, rb rowc
	q := "SELECT event_type, ip_address, description, diff, actor_type, prev_hash, entry_hash, event_time FROM audit_events WHERE id = ?"
	if err := f.db.Raw(q, a).Scan(&ra).Error; err != nil {
		return
	}
	if err := f.db.Raw(q, b).Scan(&rb).Error; err != nil {
		return
	}
	u := "UPDATE audit_events SET event_type=?, ip_address=?, description=?, diff=?, actor_type=?, prev_hash=?, entry_hash=?, event_time=? WHERE id=?"
	bestEffortExec(f, u, rb.EventType, rb.IPAddress, rb.Description, rb.Diff, rb.ActorType, rb.PrevHash, rb.EntryHash, rb.EventTime, a)
	bestEffortExec(f, u, ra.EventType, ra.IPAddress, ra.Description, ra.Diff, ra.ActorType, ra.PrevHash, ra.EntryHash, ra.EventTime, b)
}

// flipOrSeed flips one byte of s (XOR 0x01) or, if s is empty, seeds a value,
// so the mutation is guaranteed to change the stored byte string when applied.
func flipOrSeed(s string, r *brd) string {
	if s == "" {
		return "x"
	}
	bs := []byte(s)
	off := r.intn(len(bs))
	bs[off] ^= 0x01
	return string(bs)
}

func liveIDs(f *diffFixture) []uint64 {
	var ids []uint64
	rows, err := f.db.Raw("SELECT id FROM audit_events ORDER BY id ASC").Rows()
	if err != nil {
		return ids
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func FuzzAuditChainMetamorphicTamper(f *testing.F) {
	// Seeds: a few bytes selecting different mutation kinds / sizes.
	f.Add([]byte{})
	for k := byte(0); k < 11; k++ {
		f.Add([]byte{10, k, 3, 7, 1})      // N=13, kind k, various picks
		f.Add([]byte{0, k, 200, 5, 9, 42}) // N=3,  kind k
	}

	// Secondary bounded-work tripwire. resguard meters every Verify (wall/CPU
	// every input; alloc sampled) and FeedCoverage retains cost-raising inputs.
	// The FATAL ceilings are ABSOLUTE and deliberately generous so they survive
	// resguard's process-wide meter attribution under -parallel 2 (a benign
	// verify of a <=24-row chain is sub-millisecond and allocates KBs): only a
	// gross amplification — orders of magnitude, not a few x — trips them. A
	// genuine hang is caught by `go test -timeout` independently.
	probe := resguard.New(f, resguard.Options{SampleEvery: 16})
	const wallCeiling = 5 * time.Second
	const allocCeiling = 256 << 20 // 256 MiB

	ctx := context.Background()
	opts := auditverify.Options{CheckpointKey: fixedCheckpointKey}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := &brd{b: data}
		n := 3 + r.intn(22) // 3..24 events

		f := newDiffFixture(t)
		f.logEvents(n, time.Hour)
		_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
		if err != nil || !written {
			t.Skipf("fixture: checkpoint not written (err=%v written=%v)", err, written)
		}

		// Metamorphic base invariant: the untampered chain MUST verify VALID,
		// else any non-VALID after mutation is trivially (and wrongly) "detected".
		baseDB, err := auditverify.OpenSQLiteReadOnly(f.path)
		if err != nil {
			t.Fatalf("open base: %v", err)
		}
		baseRes, err := auditverify.Verify(ctx, baseDB, opts)
		_ = baseDB.Close()
		if err != nil {
			t.Fatalf("verify base errored: %v", err)
		}
		if baseRes.Verdict != auditverify.VerdictValid {
			t.Fatalf("fixture bug: freshly built checkpointed chain is not VALID: %s (%s)", baseRes.Verdict, baseRes.Reason)
		}

		fpBefore := fingerprintChain(f)
		ids := liveIDs(f)
		label := applyMutation(r, f, ids, getForeignRows(t))
		fpAfter := fingerprintChain(f)

		// Run the verifier under the resource meter (bounded-work tripwire).
		db, err := auditverify.OpenSQLiteReadOnly(f.path)
		if err != nil {
			// Opening a mutated artifact can legitimately fail (corrupt file);
			// an open error is a "detected / clear failure", acceptable only
			// when content actually changed.
			if fpAfter == fpBefore {
				t.Fatalf("[%s] open failed on a semantically-unchanged artifact: %v", label, err)
			}
			return
		}
		var res *auditverify.Result
		var verr error
		cost := probe.Measure(len(data), func() {
			res, verr = auditverify.Verify(ctx, db, opts)
		})
		_ = db.Close()
		resguard.FeedCoverage(cost)
		if cost.Wall > wallCeiling {
			t.Fatalf("[%s] bounded-work: Verify of a <=24-row chain took %s (ceiling %s)", label, cost.Wall, wallCeiling)
		}
		if cost.Sampled && cost.AllocBytes > allocCeiling {
			t.Fatalf("[%s] bounded-work: Verify allocated %d bytes (ceiling %d)", label, cost.AllocBytes, allocCeiling)
		}

		changed := fpAfter != fpBefore
		var verdict auditverify.Verdict
		if res != nil {
			verdict = res.Verdict
		}
		if v := metamorphicViolation(changed, verdict, verr); v != "" {
			t.Fatalf("%s [%s]\nreason=%q\nfp-before:\n%s\nfp-after:\n%s", v, label, reasonOf(res), fpBefore, fpAfter)
		}
	})
}

// metamorphicViolation is the oracle's decision, isolated as a pure function so
// it has a direct red/green proof (TestMetamorphicOracle_RedGreen) that does
// NOT require editing production code: it is fed the exact (changed, verdict,
// err) shapes a correct AND a broken verifier would produce.
//
// The relation:
//   - content changed  => Verify must be non-VALID (BROKEN/INDETERMINATE/SEALED
//     or a typed error). VALID+nil is a MISS.
//   - content unchanged => Verify must be VALID+nil. Any other outcome is a
//     FALSE ALARM (the verifier reacting to, or failing on, something it does
//     not authenticate).
//
// Returns "" when the relation holds, else a short violation class.
func metamorphicViolation(changed bool, verdict auditverify.Verdict, err error) string {
	if changed {
		if err != nil {
			return "" // a typed error is an acceptable "detected / clear failure"
		}
		if verdict == auditverify.VerdictValid {
			return "MISS: mutation changed authenticated content but verifier reported VALID"
		}
		return ""
	}
	// unchanged
	if err != nil {
		return "FALSE ALARM: verifier errored on a semantically-unchanged chain"
	}
	if verdict != auditverify.VerdictValid {
		return "FALSE ALARM: mutation left authenticated content unchanged but verifier reported " + string(verdict)
	}
	return ""
}

func reasonOf(res *auditverify.Result) string {
	if res == nil {
		return "(nil result / error)"
	}
	return res.Reason
}
