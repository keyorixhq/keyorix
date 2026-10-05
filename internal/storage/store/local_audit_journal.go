// local_audit_journal.go — ADR-115's opt-in local append-only audit journal
// (PERF-4 prototype): an alternative durability point for audit-before-
// disclosure. When enabled, LogAuditEvent/LogAuditEventWithAccessLog block
// on a local journal fsync (internal/auditjournal) instead of a Postgres/
// SQLite commit; a background replicator asynchronously replays durable
// journal records into the UNMODIFIED audit_events table, using the exact
// same computeAuditEntryHash/advisory-lock/chain-head logic
// commitBatchAttempt already uses today. See docs/adr-115-local-audit-journal.md.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditjournal"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// localAuditJournalState backs LocalStorage's local audit journal. See the
// localAuditJournal field's own doc comment (entry.go) for its lifetime.
type localAuditJournalState struct {
	writer    *auditjournal.Writer
	replicaID string

	// liveBatches carries each batch of just-fsynced records from the
	// journal's own flusher goroutine (via WithOnBatchCommitted) to
	// runJournalReplicator, which replays them into the DB asynchronously,
	// off the request path. Bounded (journalLiveQueueCapacity) so a
	// replicator that falls behind applies backpressure to NEW journal
	// writes rather than letting an unbounded not-yet-DB-visible backlog
	// grow in memory -- the same deliberate-backpressure shape
	// auditQueueCapacity already documents for the DB-direct path.
	liveBatches chan []auditjournal.Record
	wg          sync.WaitGroup
}

// journalPayload is the JSON-encoded body of every journal record this
// package writes. JSON (not the fixed binary TLV encoding
// computeAuditEntryHash uses) is deliberate here: this is the journal's
// OWN payload, never hashed into the global ADR-029 chain directly (only
// the replicator's own re-derivation of PrevHash/EntryHash from the
// decoded event is), so there is no byte-for-byte compatibility constraint
// -- only "decodes back to the same event," which encoding/json already
// guarantees and which FuzzDecodeRecord's sibling-layer guarantee (never
// panic) extends to: json.Unmarshal never panics on malformed bytes, it
// returns an error, exactly like this package's own record framing.
type journalPayload struct {
	Event     *models.AuditEvent
	AccessLog *models.SecretAccessLog
}

// journalLiveQueueCapacity bounds the live-replication handoff channel.
const journalLiveQueueCapacity = 64

// journalReplicatorRetryDelay is how long runJournalReplicator waits before
// retrying a batch that failed to replay. Replication failures are
// retried forever (never dropped) -- a journal record that is durable on
// disk but never reaches the DB would violate ADR-115's "idempotent,
// exactly-once-visible DB copy" guarantee.
const journalReplicatorRetryDelay = 500 * time.Millisecond

// EnableLocalAuditJournal turns on the ADR-115 local audit journal for this
// LocalStorage: LogAuditEvent/LogAuditEventWithAccessLog durability moves
// from "committed to this database" to "fsynced to the local journal at
// dir", with a background replicator asynchronously catching the database
// copy up using the existing, unmodified ADR-029 chain logic.
//
// Performs crash replay SYNCHRONOUSLY, before returning: every journal
// record already durable on disk (from this process's own prior crash, or
// any prior run against this same dir/replicaID) that the database has not
// yet seen is replayed before this call returns successfully. This is what
// makes "no acknowledged read lacks its audit entry after restart" true
// from the moment a restarted server starts accepting traffic, not just
// eventually.
//
// Returns an error, and leaves ls unmodified, if the journal directory is
// corrupt (see auditjournal.Validate) or replicaID/dir is empty -- per
// ADR-115 corruption must stop the server from starting, never silently
// fall back to the DB-only path.
func (ls *LocalStorage) EnableLocalAuditJournal(ctx context.Context, dir, replicaID string) error {
	if replicaID == "" {
		return fmt.Errorf("local audit journal: replica_id is required")
	}
	if dir == "" {
		return fmt.Errorf("local audit journal: directory is required")
	}
	if ls.auditFlusher == nil {
		return fmt.Errorf("local audit journal: cannot enable on a transaction-scoped storage")
	}

	if err := ls.db.WithContext(ctx).AutoMigrate(&models.AuditJournalReplayState{}); err != nil {
		return fmt.Errorf("local audit journal: migrate replay-state table: %w", err)
	}

	preExisting, err := auditjournal.Validate(dir)
	if err != nil {
		return fmt.Errorf("local audit journal: %w", err)
	}
	cursor, cursorFound, err := ls.auditJournalReplayCursor(ctx, replicaID)
	if err != nil {
		return fmt.Errorf("local audit journal: read replay cursor: %w", err)
	}
	toReplay := preExisting.Records
	if cursorFound {
		// Seq is 0-based, so "cursor == 0" (the last-replayed record was
		// seq 0) is a legitimate value, NOT the same thing as "no cursor
		// row exists yet" -- recordsAfter's Seq > cursor filter is only
		// correct once we know a cursor row genuinely exists. Without this
		// cursorFound guard, a fresh replica whose very first
		// EnableLocalAuditJournal crash-replay call found no row (so a
		// bare `0` default would be used as the cursor) would wrongly
		// exclude journal record #0 itself (0 is not > 0) the very first
		// time replay ever ran for it -- a real, confirmed bug this
		// comment exists to not reintroduce (see
		// TestLocalAuditJournal_KillNineLoop).
		toReplay = recordsAfter(preExisting.Records, cursor)
	}
	if err := ls.replayJournalRecords(ctx, replicaID, toReplay); err != nil {
		return fmt.Errorf("local audit journal: crash replay: %w", err)
	}

	st := &localAuditJournalState{
		replicaID:   replicaID,
		liveBatches: make(chan []auditjournal.Record, journalLiveQueueCapacity),
	}
	w, err := auditjournal.Open(dir, auditjournal.WithOnBatchCommitted(func(recs []auditjournal.Record) {
		st.liveBatches <- recs
	}))
	if err != nil {
		return fmt.Errorf("local audit journal: %w", err)
	}
	st.writer = w
	ls.localAuditJournal = st

	st.wg.Add(1)
	go ls.runJournalReplicator(st) // #nosec G118 -- a background replicator tied to this LocalStorage's own lifetime, not any single request; it deliberately outlives every caller's context (see runJournalReplicator's doc comment)

	return nil
}

// CloseLocalAuditJournal stops the replicator goroutine and closes the
// journal writer. Safe to call on a LocalStorage with no journal enabled
// (no-op). Primarily for tests and graceful shutdown; a production process
// exiting without calling this loses nothing durable -- everything the
// journal ever acknowledged is on disk, and the next EnableLocalAuditJournal
// call (on restart) replays whatever the replicator had not yet caught up
// to.
func (ls *LocalStorage) CloseLocalAuditJournal() error {
	st := ls.localAuditJournal
	if st == nil {
		return nil
	}
	ls.localAuditJournal = nil
	close(st.liveBatches)
	st.wg.Wait()
	return st.writer.Close()
}

// runJournalReplicator drains st.liveBatches (fed by the journal writer's
// own flusher goroutine, see EnableLocalAuditJournal's WithOnBatchCommitted)
// and replays each batch into the DB, off the request path. A batch that
// fails to replay is retried indefinitely -- never dropped -- per ADR-115's
// exactly-once-visible guarantee.
func (ls *LocalStorage) runJournalReplicator(st *localAuditJournalState) {
	defer st.wg.Done()
	for recs := range st.liveBatches {
		for {
			if err := ls.replayJournalRecords(context.Background(), st.replicaID, recs); err != nil {
				time.Sleep(journalReplicatorRetryDelay)
				continue
			}
			break
		}
	}
}

// logAuditEventViaJournal is LogAuditEvent's ADR-115 path: encode event (and
// optionally accessLog) as a journal payload and block on the local
// journal's own group-fsync (internal/auditjournal.Writer.Submit) -- this
// IS the durability point while the journal is enabled, replacing the
// Postgres/SQLite commit logAuditEventDirect/logAuditEventBatched would
// otherwise block on. A non-nil error here means the write is NOT durable
// anywhere -- the caller must fail closed exactly as it would on a failed
// DB commit, never disclose.
func (ls *LocalStorage) logAuditEventViaJournal(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error {
	payload, err := json.Marshal(journalPayload{Event: event, AccessLog: accessLog})
	if err != nil {
		return fmt.Errorf("local audit journal: encode payload: %w", err)
	}
	// #1650: detach from the caller's cancellation before blocking on the
	// journal's own fsync -- identical rationale to auditWriteContext's use
	// in the DB-direct/batched paths: a client disconnecting must never
	// turn "the mutation committed" into "committed with zero audit
	// record," and the journal append here is exactly as authoritative a
	// durability point as the DB commit it replaces.
	jctx, cancel := auditWriteContext(ctx)
	defer cancel()
	_, err = ls.localAuditJournal.writer.Submit(jctx, payload)
	return err
}

// recordsAfter returns the records in recs with Seq > cursor, preserving
// order.
func recordsAfter(recs []auditjournal.Record, cursor uint64) []auditjournal.Record {
	var out []auditjournal.Record
	for _, r := range recs {
		if r.Seq > cursor {
			out = append(out, r)
		}
	}
	return out
}

// auditJournalReplayCursor returns the last journal sequence number already
// replayed into the DB for replicaID, or 0 if none has ever been recorded.
// auditJournalReplayCursor returns (cursor, found, err). found is false
// when no cursor row has ever been written for replicaID -- a DISTINCT
// state from "found with a cursor value of 0" (0 is a legitimate replayed
// sequence number, see EnableLocalAuditJournal's cursorFound guard for why
// collapsing these two cases into a bare 0 was a real bug).
func (ls *LocalStorage) auditJournalReplayCursor(ctx context.Context, replicaID string) (cursor uint64, found bool, err error) {
	var row models.AuditJournalReplayState
	err = ls.db.WithContext(ctx).Where("replica_id = ?", replicaID).Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return row.LastReplayedSeq, true, nil
}

// replayJournalRecords replays records (already in ascending Seq order)
// into audit_events, in ONE transaction: each record's DB-chain
// PrevHash/EntryHash is assigned against the REAL current global chain
// head using the exact same computeAuditEntryHash the direct/batched paths
// already use (ADR-029) -- NOT the journal's own local, provisional chain
// -- and the per-replica replay cursor is advanced to the batch's highest
// Seq in that SAME transaction (models.AuditJournalReplayState). This
// atomicity is the entire crash-safety argument: rows and cursor commit
// together or not at all, so a restart's crash replay (EnableLocalAuditJournal)
// never double-replays a row the cursor already accounts for, and never
// skips a row the cursor doesn't yet account for.
func (ls *LocalStorage) replayJournalRecords(ctx context.Context, replicaID string, records []auditjournal.Record) error {
	if len(records) == 0 {
		return nil
	}
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Error; err != nil {
				return err
			}
		}

		var head struct{ EntryHash string }
		if err := tx.Model(&models.AuditEvent{}).
			Select("entry_hash").
			Order("id DESC").
			Limit(1).
			Scan(&head).Error; err != nil {
			return err
		}
		prev := head.EntryHash
		if prev == "" {
			prev = auditGenesisHash
		}

		maxSeq := records[0].Seq
		for _, rec := range records {
			var p journalPayload
			if err := json.Unmarshal(rec.Payload, &p); err != nil {
				return fmt.Errorf("decode journal payload (replica=%s seq=%d): %w", replicaID, rec.Seq, err)
			}
			if p.Event == nil {
				return fmt.Errorf("journal payload (replica=%s seq=%d) has no event", replicaID, rec.Seq)
			}

			event := p.Event
			event.ID = 0
			normalizeAuditEventForHash(event)
			event.PrevHash = prev
			event.EntryHash = computeAuditEntryHash(event, prev)
			seq := rec.Seq
			rid := replicaID
			event.JournalReplicaID = &rid
			event.JournalSeq = &seq
			if err := tx.Create(event).Error; err != nil {
				return err
			}
			prev = event.EntryHash

			if p.AccessLog != nil {
				p.AccessLog.ID = 0
				if err := tx.Create(p.AccessLog).Error; err != nil {
					return err
				}
			}
			if rec.Seq > maxSeq {
				maxSeq = rec.Seq
			}
		}

		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "replica_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"last_replayed_seq", "updated_at"}),
		}).Create(&models.AuditJournalReplayState{
			ReplicaID:       replicaID,
			LastReplayedSeq: maxSeq,
			UpdatedAt:       time.Now(),
		}).Error
	})
}
