package auditverify_test

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// FuzzAuditChainOpSequence drives a fuzzer-chosen SEQUENCE of append /
// checkpoint / retention-purge / clock-advance operations through the real
// writer (store.LocalStorage + core, on a real SQLite file) and, after EVERY op,
// asks both verifiers (the online core.VerifyAuditChain and this package's
// independent auditverify.Verify) whether the chain is intact, against a
// slice-of-rows model that is the oracle. A program may end in ONE tamper op
// (terminal); then neither verifier may say the chain is intact.
//
// What the model knows (everything else is an assertion on the verifiers, not a
// copy of their logic):
//
//   - rows: the surviving chained events, oldest first, each with its event time;
//   - a purge at retention R removes exactly the rows with time < now-R (strictly
//     older, a prefix because the fake clock only moves forward) and then appends
//     one system.audit_purge row, even when it removed nothing;
//   - purged: cumulative rows removed by sanctioned purges;
//   - a checkpoint certifies len(rows)+purged.
//
// Assertions after every clean op:
//
//	online  Valid, ChainedEvents == len(rows)
//	offline VALID with the key; ChainedEvents == len(rows); PurgedEvents == purged
//	offline without the key: VALID while the surviving chain starts at genesis
//	  (nothing purged, or a purge removed every row and the chain restarted), else
//	  INDETERMINATE (an unauthenticated retention gap is never VALID and never
//	  credited), never BROKEN
//
// Every purge is run, including one that removes every surviving row and one
// that removes the row the latest checkpoint certified as head (#4351).
//
// Program encoding (op numbers are corpus encoding: APPEND ONLY, never renumber).
// bytes are (op, arg) pairs, at most auditChainMaxOps of them:
//
//	0 append 1+arg%3 events at the current clock
//	1 advance the clock by (1+arg%20) days and arg hours
//	2 write a checkpoint
//	3 purge with retention 7+arg%30 days
//	4 move the clock so the OLDEST row is exactly (7+arg%30) days old, then purge
//	  with that retention (the strict-< boundary); skipped if that would move the
//	  clock backwards
//	5 verify only
//	TERMINAL tamper ops (the program ends after the first one that applies):
//	6 rewrite the description of row arg%len
//	7 delete an interior row (needs >= 3 rows)
//	8 delete the newest row, only when a checkpoint certifies the current total
//	  (a truncation no checkpoint certifies is undetectable by design)
//	9 overwrite the entry_hash of row arg%len
//
// No bcrypt / key derivation here (the checkpoint HMAC key is a constant); the
// per-program cost is bounded by auditChainMaxOps and a row cap, and the only
// process-global state touched is i18n initialisation (idempotent).
//
// Not covered: external anchors, key transitions, seals (accept-loss), high-water
// marks, owed break-glass rows, legal holds, Postgres, and concurrent writers.
func FuzzAuditChainOpSequence(f *testing.F) {
	f.Add([]byte{0, 2, 2, 0, 0, 1, 2, 0})                          // append, checkpoint, append, checkpoint
	f.Add([]byte{0, 2, 1, 29, 0, 0, 2, 0, 1, 3, 3, 0, 5, 0})       // old events, newer, checkpoint, purge the old
	f.Add([]byte{0, 1, 1, 0, 0, 0, 2, 0, 4, 0, 5, 0})              // boundary purge: oldest row exactly at the cutoff survives
	f.Add([]byte{0, 2, 1, 29, 3, 0, 2, 0})                         // purge removes ALL rows (nothing newer), then checkpoint
	f.Add([]byte{0, 2, 2, 0, 0, 0, 6, 1})                          // tamper: description
	f.Add([]byte{0, 2, 2, 0, 7, 1})                                // tamper: interior delete
	f.Add([]byte{0, 2, 2, 0, 8, 0})                                // tamper: tail truncation after checkpoint
	f.Add([]byte{0, 2, 9, 2})                                      // tamper: entry hash
	f.Add([]byte{0, 2, 1, 29, 0, 2, 2, 0, 3, 0, 2, 0, 0, 0, 8, 0}) // purge then truncate

	// #4351: case 2, a purge removes the latest checkpoint's head; case 1 after
	// a checkpoint: the purge empties the table, the chain restarts, checkpoint.
	f.Add([]byte{0, 0, 2, 0, 2, 0, 1, 14, 3, 8, 1, 9, 3, 18, 5, 0})
	f.Add([]byte{0, 2, 2, 0, 1, 29, 3, 0, 0, 1, 2, 0, 5, 0})

	f.Fuzz(func(t *testing.T, prog []byte) {
		// Watchdog: a program that does not finish is a finding (a lock wait or a
		// loop), reported with the input and every goroutine's stack, instead of a
		// silently wedged worker.
		done := make(chan struct{})
		go func() {
			defer close(done)
			auditChainOpSequenceProgram(t, prog)
		}()
		select {
		case <-done:
		case <-time.After(45 * time.Second):
			buf := make([]byte, 1<<20)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("program did not finish in 45s: %v\n%s", prog, buf)
		}
	})
}

// auditChainOpSequenceProgram runs one program; it is a named function so a
// plain test can replay arbitrary programs under a goroutine-dumping timeout.
func auditChainOpSequenceProgram(t *testing.T, prog []byte) {
	{
		fx := newDiffFixture(t)
		fx.db.Config.Logger = logger.Discard // gorm's default logger prints every query: pure overhead here
		// The fake clock starts years before any real "now" and 40 ops move it at
		// most ~2.5 years, so it never reaches the real-time stamps system events get.
		clock := time.Date(2020, 1, 1, 10, 0, 0, 0, time.UTC)
		farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
		fx.core.SetClockForTesting(func() time.Time { return clock })

		type row struct {
			at     time.Time
			desc   string
			system bool
		}
		var (
			rows   []row
			purged int64
			cpAt   int64 = -1 // total certified by the latest checkpoint; -1 = none
			nextID uint64
			// gapVisible: the surviving chain starts after removed rows (a
			// non-genesis prev_hash). A purge that removes every row leaves the next
			// row to restart at genesis, so no gap is visible again.
			gapVisible bool
		)
		total := func() int64 { return int64(len(rows)) + purged }

		appendRow := func() {
			nextID++
			desc := fmt.Sprintf("event %d", nextID)
			tr := true
			if err := fx.local.LogAuditEvent(fx.ctx, &models.AuditEvent{
				EventType: "secret.read", Description: desc, Success: &tr, EventTime: clock, ActorType: "user",
			}); err != nil {
				t.Fatalf("append: %v", err)
			}
			rows = append(rows, row{at: clock, desc: desc})
		}

		// currentIDs reads the real surviving ids (oldest first) so tamper ops can
		// address rows; the model's list is what is asserted against.
		currentIDs := func() []uint64 {
			var ids []uint64
			if err := fx.db.Raw("SELECT id FROM audit_events ORDER BY id").Scan(&ids).Error; err != nil {
				t.Fatalf("list ids: %v", err)
			}
			return ids
		}

		check := func(step int, what string, tampered bool) {
			t.Helper()
			online := fx.oracle()
			db := fx.openIndependent()
			withKey, err := auditverify.Verify(fx.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
			if err != nil {
				t.Fatalf("step %d %s: offline verify (key): %v", step, what, err)
			}
			noKey, err := auditverify.Verify(fx.ctx, db, auditverify.Options{})
			if err != nil {
				t.Fatalf("step %d %s: offline verify (no key): %v", step, what, err)
			}
			if tampered {
				if online.Valid {
					t.Fatalf("step %d %s: TAMPER UNDETECTED by the online verifier", step, what)
				}
				if withKey.Verdict == auditverify.VerdictValid {
					t.Fatalf("step %d %s: TAMPER UNDETECTED by the offline verifier with the key (reason %q)", step, what, withKey.Reason)
				}
				if noKey.Verdict == auditverify.VerdictValid && what != "tamper-truncate-tail" {
					// without the key a tail truncation is invisible by design; every
					// other tamper changes the walk itself and must show.
					t.Fatalf("step %d %s: TAMPER UNDETECTED by the offline walk without the key (reason %q)", step, what, noKey.Reason)
				}
				return
			}
			if !online.Valid {
				t.Fatalf("step %d %s: online verifier rejects a chain built only by sanctioned ops: %s", step, what, online.Reason)
			}
			if online.ChainedEvents != int64(len(rows)) {
				t.Fatalf("step %d %s: online ChainedEvents=%d, model=%d", step, what, online.ChainedEvents, len(rows))
			}
			if withKey.Verdict != auditverify.VerdictValid {
				t.Fatalf("step %d %s: offline (key) %s: %s", step, what, withKey.Verdict, withKey.Reason)
			}
			if withKey.ChainedEvents != int64(len(rows)) || withKey.PurgedEvents != purged {
				t.Fatalf("step %d %s: offline (key) chained=%d purged=%d, model chained=%d purged=%d",
					step, what, withKey.ChainedEvents, withKey.PurgedEvents, len(rows), purged)
			}
			switch {
			case !gapVisible && noKey.Verdict != auditverify.VerdictValid:
				t.Fatalf("step %d %s: offline (no key) %s on a chain with no visible retention gap: %s", step, what, noKey.Verdict, noKey.Reason)
			case gapVisible && noKey.Verdict != auditverify.VerdictIndeterminate:
				t.Fatalf("step %d %s: offline (no key) %s after a purge, want INDETERMINATE (unauthenticated gap): %s", step, what, noKey.Verdict, noKey.Reason)
			}
		}

		// Which rows a purge removes: the PREFIX (by id) of rows strictly older than
		// the cutoff, stopping at the first row that is not (local_audit.go keeps
		// `id < B` as well as `event_time < cutoff`, so a row stamped out of order
		// is retained, never a hole in the middle). System events (the purge's own
		// row) are stamped with the REAL wall clock, not the injected one, so they
		// sit in the far future of this test's fake clock (see farFuture).
		prefixLen := func(at time.Time, days int) int {
			cutoff := at.AddDate(0, 0, -days)
			n := 0
			for n < len(rows) && rows[n].at.Before(cutoff) {
				n++
			}
			return n
		}
		purge := func(step int, days int) {
			cutoff := clock.AddDate(0, 0, -days)
			n := prefixLen(clock, days)
			want := int64(n)
			keep := append([]row(nil), rows[n:]...)
			res, err := fx.core.PurgeAuditLogs(fx.ctx, core.AuditLogRetentionConfig{RetentionDays: days})
			if err != nil {
				t.Fatalf("step %d purge(%dd): %v", step, days, err)
			}
			if res.DeletedCount != want {
				t.Fatalf("step %d purge(%dd): deleted %d rows, model says %d (cutoff %v, %d rows held)", step, days, res.DeletedCount, want, cutoff, len(rows))
			}
			if n > 0 {
				gapVisible = n < len(rows)
			}
			rows = append(keep, row{at: farFuture, desc: "purge", system: true})
			purged += want
		}

		const maxOps, maxRows = 40, 60
		ops := prog
		for i := 0; i+1 < len(ops) && i/2 < maxOps; i += 2 {
			op, arg := ops[i], int(ops[i+1])
			step := i / 2
			t.Logf("step %d: op %d arg %d (rows=%d purged=%d certified=%d clock=%s)", step, op%10, arg, len(rows), purged, cpAt, clock.Format(time.RFC3339))
			switch op % 10 {
			case 0:
				for k := 0; k < 1+arg%3 && len(rows) < maxRows; k++ {
					appendRow()
				}
				check(step, "append", false)
			case 1:
				clock = clock.Add(time.Duration(1+arg%20)*24*time.Hour + time.Duration(arg%24)*time.Hour)
				check(step, "advance", false)
			case 2:
				if len(rows) == 0 {
					continue
				}
				cp, written, err := fx.core.WriteAuditCheckpoint(fx.ctx)
				if err != nil {
					t.Fatalf("step %d checkpoint: %v", step, err)
				}
				if written && cp != nil {
					if cp.ChainedEvents != total() {
						t.Fatalf("step %d checkpoint certifies %d events, model total (chained+purged) is %d", step, cp.ChainedEvents, total())
					}
					cpAt = total()
				}
				check(step, "checkpoint", false)
			case 3:
				if len(rows) >= maxRows {
					continue
				}
				purge(step, 7+arg%30)
				check(step, "purge", false)
			case 4:
				if len(rows) == 0 || len(rows) >= maxRows || rows[0].system {
					continue
				}
				days := 7 + arg%30
				target := rows[0].at.AddDate(0, 0, days)
				if target.Before(clock) {
					continue
				}
				clock = target
				purge(step, days)
				check(step, "purge-at-boundary", false)
			case 5:
				check(step, "verify", false)
			case 6, 7, 8, 9:
				ids := currentIDs()
				if len(ids) != len(rows) {
					t.Fatalf("step %d: stored rows %d, model rows %d", step, len(ids), len(rows))
				}
				switch op % 10 {
				case 6:
					if len(ids) == 0 {
						continue
					}
					fx.exec("UPDATE audit_events SET description = ? WHERE id = ?", "tampered", ids[arg%len(ids)])
					check(step, "tamper-description", true)
				case 7:
					if len(ids) < 3 {
						continue
					}
					fx.exec("DELETE FROM audit_events WHERE id = ?", ids[1+arg%(len(ids)-2)])
					check(step, "tamper-delete-interior", true)
				case 8:
					if len(ids) == 0 || cpAt < 0 || cpAt != total() {
						continue
					}
					fx.exec("DELETE FROM audit_events WHERE id = ?", ids[len(ids)-1])
					check(step, "tamper-truncate-tail", true)
				case 9:
					if len(ids) == 0 {
						continue
					}
					fx.exec("UPDATE audit_events SET entry_hash = ? WHERE id = ?", fmt.Sprintf("%064x", arg+1), ids[arg%len(ids)])
					check(step, "tamper-entry-hash", true)
				}
				return
			}
		}
	}
}
