// local_audit_chain_linked_flight_test.go — PERF-MULTINODE-1: a batch whose
// head the flusher does not know goes as one linked flight (PostgreSQL links
// it onto the head it reads under KEYAUDIT), stores exactly the rows the Go
// encoding produces, keeps one linear chain across replicas, and fails closed.
// pg-gated (KEYORIX_TEST_PG_DSN) except the statement-shape test.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// linkedOnce commits batch through the path a flusher takes when its head
// cache is not armed, and requires it to go as one linked flight.
func linkedOnce(t *testing.T, ls *LocalStorage, batch []*auditBatchItem) {
	t.Helper()
	ls.invalidateAuditChainHead()
	before := ls.auditHead.linkedCommits.Load()
	require.NoError(t, ls.commitBatchTwoFlights(context.Background(), batch))
	require.Equal(t, before+1, ls.auditHead.linkedCommits.Load(), "the batch did not go as one linked flight")
}

// requireRowsMatchGo re-reads every stored row and recomputes its chain in Go:
// prev_hash is the previous row's entry_hash (genesis first, or after an
// unchained row), and entry_hash is computeAuditEntryHash of the stored fields.
func requireRowsMatchGo(t *testing.T, ls *LocalStorage) {
	t.Helper()
	events, _ := loadAuditRows(t, ls)
	prev := auditGenesisHash
	for _, e := range events {
		if e.EntryHash == "" {
			prev = auditGenesisHash
			continue
		}
		require.Equal(t, prev, e.PrevHash, "row %d prev_hash", e.ID)
		require.Equal(t, computeAuditEntryHash(&e, e.PrevHash), e.EntryHash, "row %d entry_hash", e.ID)
		prev = e.EntryHash
	}
}

// The SHA256 PostgreSQL computes over the Go suffix is the Go encoding, for
// every field shape buildMultiRowBatch varies (nil and set pointers, empty and
// non-ASCII strings, impersonation, success nil/true/false, sub-millisecond
// times), from an empty table (genesis), onto a chained head, and onto an
// unchained legacy row (empty entry_hash, which links to genesis).
func TestLinkedFlight_PostgresHashesMatchGo(t *testing.T) {
	ls, _ := pipelinePGStore(t)
	linkedOnce(t, ls, buildMultiRowBatch(7, "genesis"))
	requireRowsMatchGo(t, ls)
	linkedOnce(t, ls, buildMultiRowBatch(13, "onto-head"))
	linkedOnce(t, ls, buildMultiRowBatch(1, "single"))
	requireRowsMatchGo(t, ls)
	requireChainValid(t, ls, nil, 21)

	// The same batches through the two-flight path hash identically.
	ref, _ := pipelinePGStore(t)
	ref.auditLinkedOff.Store(true)
	for _, b := range [][]*auditBatchItem{buildMultiRowBatch(7, "genesis"), buildMultiRowBatch(13, "onto-head"), buildMultiRowBatch(1, "single")} {
		ref.invalidateAuditChainHead()
		require.NoError(t, ref.commitBatchTwoFlights(context.Background(), b))
	}
	assert.Zero(t, ref.auditHead.linkedCommits.Load())
	assertSameAuditRows(t, ref, ls)

	// An unchained legacy row on top: the next row links to genesis.
	unchained, _ := pipelinePGStore(t)
	require.NoError(t, unchained.db.Create(&models.AuditEvent{EventType: "legacy", EventTime: time.Now().UTC().Truncate(time.Microsecond)}).Error)
	linkedOnce(t, unchained, buildMultiRowBatch(3, "after-legacy"))
	requireRowsMatchGo(t, unchained)
	events, _ := loadAuditRows(t, unchained)
	assert.Equal(t, auditGenesisHash, events[1].PrevHash)
}

// Three replicas append concurrently. None of them can keep its head cache
// armed, so they commit linked; the chain stays one linear sequence and no
// acknowledged row is lost or duplicated.
func TestLinkedFlight_PostgresThreeReplicasConcurrent(t *testing.T) {
	a, _ := pipelinePGStore(t)
	schema := pipelinePGSchema(t, a)
	b, _ := pipelinePGStoreInSchema(t, schema)
	c, _ := pipelinePGStoreInSchema(t, schema)
	replicas := []*LocalStorage{a, b, c}
	const writers, perWriter = 8, 30
	var wg sync.WaitGroup
	errs := make(chan error, len(replicas)*writers*perWriter)
	for _, ls := range replicas {
		for w := range writers {
			wg.Go(func() {
				for i := range perWriter {
					item := buildMultiRowBatch(1, fmt.Sprintf("conc-%p-%d-%d", ls, w, i))[0]
					errs <- ls.LogAuditEventWithAccessLog(context.Background(), item.event, item.accessLog)
				}
			})
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	var linked int64
	for i, ls := range replicas {
		t.Logf("replica %d: linked %d, one-flight %d, misses %d", i, ls.auditHead.linkedCommits.Load(),
			ls.auditHead.oneFlightCommits.Load(), ls.auditHead.oneFlightMisses.Load())
		linked += ls.auditHead.linkedCommits.Load()
	}
	assert.Positive(t, linked, "no batch went as a linked flight")
	requireChainValid(t, a, nil, len(replicas)*writers*perWriter)
	requireRowsMatchGo(t, a)
	_, logs := loadAuditRows(t, a)
	assert.Len(t, logs, len(replicas)*writers*perWriter, "every item carries its access-log row")
}

// Two replicas in strict alternation: after the other one wrote, an armed
// one-flight attempt misses and its retry is a linked flight (one flight, not
// two); a disarmed replica commits linked straight away.
func TestLinkedFlight_PostgresTwoReplicasAlternate(t *testing.T) {
	a, writesA := pipelinePGStore(t)
	b, _ := pipelinePGStoreInSchema(t, pipelinePGSchema(t, a))
	total := 0
	step := func(ls *LocalStorage, tag string, wantLinked, wantMiss int64) {
		t.Helper()
		linked, misses := ls.auditHead.linkedCommits.Load(), ls.auditHead.oneFlightMisses.Load()
		batch := buildMultiRowBatch(3, tag)
		commitAll(t, ls, batch)
		total += len(batch)
		assert.Equal(t, wantLinked, ls.auditHead.linkedCommits.Load()-linked, "%s: linked commits", tag)
		assert.Equal(t, wantMiss, ls.auditHead.oneFlightMisses.Load()-misses, "%s: one-flight misses", tag)
		assert.Equal(t, batch[2].event.EntryHash, chainHeadHash(t, ls), "%s: the batch's last row must be the head", tag)
	}
	step(a, "a-boot", 1, 0) // linked; nothing to compare with, so it arms
	step(a, "a-1", 0, 0)    // one flight from the cache
	step(b, "b-boot", 1, 0)
	step(a, "a-after-b", 1, 1) // the armed attempt misses, the retry is linked
	step(b, "b-after-a", 1, 1)
	for i := range 4 { // both disarmed now: linked straight away, no more misses
		step(b, fmt.Sprintf("b-alt-%d", i), 1, 0)
		before := writesA.Load()
		step(a, fmt.Sprintf("a-alt-%d", i), 1, 0)
		// One flight for the batch, one for step's own head read (two flights
		// would make it three).
		assert.Equal(t, int64(2), writesA.Load()-before, "a-alt-%d: a linked batch is one flight", i)
	}
	requireChainValid(t, a, nil, total)
	requireRowsMatchGo(t, a)
}

// A committed linked batch whose entry_hash the Go encoding does not
// reproduce (here: a suffix altered on its way out, standing in for an
// encoding drift) fails every item without a retry (no row appended twice),
// turns linking off, and is reported by VerifyAuditChain. The next batch
// commits in two flights.
func TestLinkedFlight_PostgresHashMismatchFailsClosedOnce(t *testing.T) {
	ls, _ := pipelinePGStore(t)
	commitAll(t, ls, buildMultiRowBatch(2, "before"))
	auditLinkedSuffixHook = func(s [][]byte) [][]byte {
		out := make([][]byte, len(s))
		for i, b := range s {
			out[i] = append([]byte{}, b...)
		}
		out[1][len(out[1])-1] ^= 1
		return out
	}
	t.Cleanup(func() { auditLinkedSuffixHook = nil })
	ls.invalidateAuditChainHead()
	errs := ls.commitAuditBatch(buildMultiRowBatch(3, "drift"))
	auditLinkedSuffixHook = nil
	for i, err := range errs {
		require.ErrorIs(t, err, errAuditLinkedHashMismatch, "item %d", i)
	}
	assert.True(t, ls.auditLinkedOff.Load())
	events, _ := loadAuditRows(t, ls)
	require.Len(t, events, 5, "the drifted batch must be stored once, never retried")
	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, v.Valid, "VerifyAuditChain must report the row")

	linked := ls.auditHead.linkedCommits.Load()
	ls.invalidateAuditChainHead()
	commitAll(t, ls, buildMultiRowBatch(2, "after"))
	assert.Equal(t, linked, ls.auditHead.linkedCommits.Load(), "linking must stay off")
	requireConnIdle(t, ls)
}

// Ids stored out of chain order (a trigger rewriting them) fail the linked
// statement's check before COMMIT; the two-flight retry fails too; nothing is
// written and the connection goes back idle.
func TestLinkedFlight_PostgresOutOfOrderIDsFailClosed(t *testing.T) {
	ls, _ := pipelinePGStore(t)
	commitAll(t, ls, buildMultiRowBatch(3, "before"))
	require.NoError(t, ls.db.Exec(`CREATE SEQUENCE kx_reverse_ids INCREMENT -1 MINVALUE 1 MAXVALUE 1000000 START 1000000`).Error)
	require.NoError(t, ls.db.Exec(`CREATE FUNCTION kx_reverse_id() RETURNS trigger AS $$
BEGIN
  NEW.id := nextval('kx_reverse_ids');
  RETURN NEW;
END $$ LANGUAGE plpgsql`).Error)
	require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_reverse_id BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION kx_reverse_id()`).Error)

	ls.invalidateAuditChainHead()
	linked := ls.auditHead.linkedCommits.Load()
	err := ls.commitBatchTwoFlights(context.Background(), buildMultiRowBatch(3, "reversed"))
	require.Error(t, err)
	assert.Equal(t, linked, ls.auditHead.linkedCommits.Load())
	requireConnIdle(t, ls)
	requireChainValid(t, ls, nil, 3)
}

// The linked statement runs from a cached generic plan, not re-planned per
// batch.
func TestLinkedFlight_PostgresRunsFromGenericPlans(t *testing.T) {
	ls, _ := pipelinePGStore(t)
	commitAll(t, ls, buildMultiRowBatch(2, "boot"))
	const flights = 12
	for range flights {
		linkedOnce(t, ls, buildMultiRowBatch(2, "plans"))
	}
	var rows []struct {
		Statement    string
		GenericPlans int64
		CustomPlans  int64
	}
	require.NoError(t, ls.db.Raw("SELECT statement, generic_plans, custom_plans FROM pg_prepared_statements").Scan(&rows).Error)
	found := 0
	for _, r := range rows {
		if !strings.Contains(r.Statement, "audit linked batch") || !strings.Contains(r.Statement, "c.i < 2)") {
			continue
		}
		found++
		// Postgres plans a statement with parameters per execution for its first
		// five runs, then keeps the generic plan when it costs no more.
		assert.LessOrEqual(t, r.CustomPlans, int64(5), "re-planned on every flight: %q", r.Statement)
		assert.GreaterOrEqual(t, r.GenericPlans, int64(flights-5), "not run from its cached plan: %q", r.Statement)
	}
	require.Equal(t, 1, found, "the linked statement must be cached: %+v", rows)
}

// linkedAuditInsert keeps GORM's bind variables in order, casts each to its
// column's type, takes prev_hash and entry_hash from the linked rows in batch
// order, and refuses any other statement shape.
func TestLinkedAuditInsert_Shape(t *testing.T) {
	types := map[string]string{"event_type": "text", "description": "text", "user_id": "bigint", "prev_hash": "text", "entry_hash": "text", "id": "bigint"}
	cols := []clause.Column{{Name: "event_type"}, {Name: "prev_hash"}, {Name: "entry_hash"}, {Name: "user_id"}}
	vals := clause.Values{Columns: cols, Values: [][]any{{"a", "", "", 1}, {"b", "", "", nil}}}
	sql, vars, err := linkedAuditInsert(`"audit_events"`, vals, []any{"a", "", "", 1, "b", "", "", nil}, 2, types)
	require.NoError(t, err)
	assert.Equal(t, `INSERT INTO "audit_events" ("event_type","user_id","prev_hash","entry_hash") SELECT v.v1, v.v2, c.prev_hash, c.entry_hash `+
		`FROM (VALUES (1,$1::text,$2::bigint),(2,$3::text,$4::bigint)) AS v(i, v1, v2) JOIN c ON c.i = v.i ORDER BY v.i `+
		`RETURNING "id","prev_hash","entry_hash"`, sql)
	assert.Equal(t, []any{"a", 1, "b", nil}, vars)

	for name, tc := range map[string]struct {
		vals clause.Values
		vars []any
		n    int
	}{
		"rows":    {vals, []any{"a", "", "", 1, "b", "", "", nil}, 3},
		"vars":    {vals, []any{"a", "", "", 1}, 2},
		"no hash": {clause.Values{Columns: []clause.Column{{Name: "event_type"}}, Values: [][]any{{"a"}}}, []any{"a"}, 1},
		"sets id": {clause.Values{Columns: []clause.Column{{Name: "id"}, {Name: "prev_hash"}, {Name: "entry_hash"}}, Values: [][]any{{1, "", ""}}}, []any{1, "", ""}, 1},
		"no type": {clause.Values{Columns: []clause.Column{{Name: "diff"}, {Name: "prev_hash"}, {Name: "entry_hash"}}, Values: [][]any{{"", "", ""}}}, []any{"", "", ""}, 1},
		"no rows": {clause.Values{}, nil, 0},
	} {
		_, _, err := linkedAuditInsert(`"audit_events"`, tc.vals, tc.vars, tc.n, types)
		assert.True(t, errors.Is(err, errAuditLinkedUnavailable), "%s: %v", name, err)
	}
}
