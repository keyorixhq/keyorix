package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditjournal"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func journalTestRecords(t *testing.T, seqs ...uint64) []auditjournal.Record {
	t.Helper()
	out := make([]auditjournal.Record, 0, len(seqs))
	for _, s := range seqs {
		tr := true
		p, err := json.Marshal(journalPayload{Event: &models.AuditEvent{
			EventType: "journal_test.write", Description: "rec", Success: &tr,
			EventTime: time.Now(), ActorType: "system",
		}})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, auditjournal.Record{Seq: s, Payload: p})
	}
	return out
}

// TestReplayJournalRecords_RetryOfCommittedBatchIsNoOp pins coordinator
// review of #2758, item 4. The replicator retries a batch on any error,
// including one returned after the COMMIT actually landed (connection lost
// at COMMIT). Replaying an already-committed batch must add nothing and
// must succeed, or the replicator would either duplicate rows or retry
// forever against the unique index.
func TestReplayJournalRecords_RetryOfCommittedBatchIsNoOp(t *testing.T) {
	ls := openCrashTestDB(t, filepath.Join(t.TempDir(), "db.sqlite"))
	ctx := context.Background()
	const replica = "r1"

	recs := journalTestRecords(t, 0, 1, 2)
	if err := ls.replayJournalRecords(ctx, replica, recs); err != nil {
		t.Fatalf("first replay: %v", err)
	}
	if err := ls.replayJournalRecords(ctx, replica, journalTestRecords(t, 0, 1, 2)); err != nil {
		t.Fatalf("replay of an already-committed batch: %v", err)
	}
	// A batch overlapping the committed one replays only the new tail.
	if err := ls.replayJournalRecords(ctx, replica, journalTestRecords(t, 1, 2, 3)); err != nil {
		t.Fatalf("overlapping replay: %v", err)
	}
	if n := countReplicaRows(t, ls, replica); n != 4 {
		t.Fatalf("audit_events rows for %s = %d, want 4", replica, n)
	}
	if res, err := ls.VerifyAuditChain(ctx, nil); err != nil || !res.Valid {
		t.Fatalf("VerifyAuditChain = %+v, %v", res, err)
	}
}

// TestAuditJournalOrigin_ReplicaSeqIsUnique: the enforced backstop behind
// the in-transaction cursor check. One (replica, seq) can never be recorded
// for two audit rows.
func TestAuditJournalOrigin_ReplicaSeqIsUnique(t *testing.T) {
	ls := openCrashTestDB(t, filepath.Join(t.TempDir(), "db.sqlite"))
	if err := ls.db.Create(&models.AuditJournalOrigin{ReplicaID: "r1", Seq: 7, EntryHash: "a"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := ls.db.Create(&models.AuditJournalOrigin{ReplicaID: "r1", Seq: 7, EntryHash: "b"}).Error; err == nil {
		t.Fatal("a second audit row was recorded for the same (replica_id, seq)")
	}
	if err := ls.db.Create(&models.AuditJournalOrigin{ReplicaID: "r2", Seq: 7, EntryHash: "c"}).Error; err != nil {
		t.Fatalf("same seq on another replica: %v", err)
	}
}

// TestEnableLocalAuditJournal_RefusesJournalShorterThanCursor pins the part
// of coordinator review of #2758, item 5 that can be checked: a journal cut
// short at a record boundary still validates, but the DB replay cursor
// records how far the journal reached. Enable must refuse a journal that no
// longer contains the cursor's seq.
func TestEnableLocalAuditJournal_RefusesJournalShorterThanCursor(t *testing.T) {
	dir := t.TempDir()
	ls := openCrashTestDB(t, filepath.Join(t.TempDir(), "db.sqlite"))
	ctx := context.Background()
	const replica = "r1"
	if err := ls.EnableLocalAuditJournal(ctx, dir, replica); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	for i := 0; i < 5; i++ {
		tr := true
		if err := ls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "x", Success: &tr, EventTime: time.Now(), ActorType: "system"}); err != nil {
			t.Fatalf("LogAuditEvent: %v", err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for countReplicaRows(t, ls, replica) < 5 {
		if time.Now().After(deadline) {
			t.Fatal("replicator did not catch up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := ls.CloseLocalAuditJournal(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}

	restarted := NewLocalStorage(ls.db) // same database, fresh LocalStorage
	err = restarted.EnableLocalAuditJournal(ctx, dir, replica)
	if err == nil || !strings.Contains(err.Error(), "truncated or replaced") {
		t.Fatalf("Enable on an emptied journal with cursor at seq 4 = %v, want refusal", err)
	}
}

// TestCloseLocalAuditJournal_WithWritersInFlight pins coordinator review of
// #2758, item 1: closing while audit writes are in flight must not panic
// (a batch committed during Close used to send on the already-closed
// replication channel), every acknowledged write must reach audit_events,
// and writes after Close fail closed with ErrClosed.
func TestCloseLocalAuditJournal_WithWritersInFlight(t *testing.T) {
	dir := t.TempDir()
	ls := openCrashTestDB(t, filepath.Join(t.TempDir(), "db.sqlite"))
	ctx := context.Background()
	const replica = "r1"
	if err := ls.EnableLocalAuditJournal(ctx, dir, replica); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	var mu sync.Mutex
	acked := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				tr := true
				err := ls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "x", Success: &tr, EventTime: time.Now(), ActorType: "system"})
				if errors.Is(err, auditjournal.ErrClosed) {
					return
				}
				if err != nil {
					t.Errorf("LogAuditEvent: %v", err)
					return
				}
				mu.Lock()
				acked++
				mu.Unlock()
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	if err := ls.CloseLocalAuditJournal(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
	if err := ls.CloseLocalAuditJournal(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if acked == 0 {
		t.Fatal("no write was acknowledged before Close; the test exercised nothing")
	}
	// Close waits for the replicator to drain, so every acknowledged write
	// is already in the DB.
	if n := countReplicaRows(t, ls, replica); n != int64(acked) {
		t.Fatalf("audit_events rows = %d, acknowledged writes = %d", n, acked)
	}
	tr := true
	if err := ls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "x", Success: &tr, EventTime: time.Now()}); !errors.Is(err, auditjournal.ErrClosed) {
		t.Fatalf("LogAuditEvent after Close = %v, want ErrClosed (fail closed, no silent DB fallback)", err)
	}
}
