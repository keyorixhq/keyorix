// local_audit_chain_linked_flight.go — PERF-MULTINODE-1: the Postgres audit
// group commit in ONE flight when the flusher does NOT know the chain head.
//
// The one-flight commit (local_audit_chain_one_flight.go) needs the head's
// entry_hash before it can hash the batch, so it works only while the
// flusher's head cache is armed. With several Keyorix nodes on one database the
// other nodes keep moving the head, the cache never arms, and every batch used
// to take the two-flight path (local_audit_chain_pipeline.go): flight 1 takes
// KEYAUDIT and reads the head, the client hashes, flight 2 inserts and commits.
// KEYAUDIT was held across that client round trip, and KEYAUDIT is what every
// node's appends queue on.
//
// The linked flight lets PostgreSQL do the one step that needs the head. The
// entry hash is SHA256(field(prev_hash) || suffix), where suffix is the
// encoding of the row's own fields (auditEntryHashSuffix) and field(s) is s
// preceded by its big-endian uint64 byte length. The client computes every
// row's suffix, which does not depend on the head, and sends:
//
//	BEGIN; [SET LOCAL synchronous_commit = off;]
//	SELECT pg_advisory_xact_lock(KEYAUDIT);
//	WITH RECURSIVE h  = the id-DESC head (this statement's snapshot, after the lock),
//	               c  = prev_hash/entry_hash of row 1..n, row 1 linked onto h
//	                    (genesis when h is absent or unchained), row i+1 onto row i,
//	                    entry_hash = encode(sha256(field(prev) || suffix_i), 'hex'),
//	               e  = the events INSERT: GORM's VALUES joined to c in batch order,
//	                    each row's prev_hash/entry_hash taken from c,
//	                    RETURNING id, prev_hash, entry_hash
//	  check: raises unless the stored rows are the n rows of this batch, all above
//	         h, linked prev_hash -> entry_hash in id order;
//	INSERT secret_access_logs ...; COMMIT
//
// So the head is still read, and the batch still hashed and inserted, all
// under the lock (ADR-029); only the hashing of the head-dependent links moves
// into the statement. The suffix encoding stays in Go, in one place, shared
// with computeAuditEntryHash and VerifyAuditChain; SQL only applies SHA256 to
// a 64-character hex string and those bytes. The lock is held for the
// statement's execution, never across a client round trip.
//
// The client checks the result too: every returned entry_hash must equal
// computeAuditEntryHash of its event and returned prev_hash. That runs after
// COMMIT (the whole transaction is one flight), so a mismatch cannot stop the
// rows: it fails every item of the batch (no value is disclosed, and the batch
// is not appended a second time), logs a SECURITY line, and turns the linked
// flight off for this process. VerifyAuditChain reports the row. The
// encodings are pinned against each other (TestLinkedFlight_PostgresHashesMatchGo).
//
// When it is used: wherever the flusher would have taken two flights (the
// cache not armed, or a one-flight attempt that missed), for a batch that fits
// one INSERT. A batch that cannot go linked (too large, or GORM built an
// unexpected statement), a linked attempt that provably wrote nothing, and a
// process where linking was turned off take two flights exactly as before. The
// armed one-flight commit and the pipelined batches are unchanged, so a single
// node's steady state sends the same statements as before this change.
package store

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm/clause"
)

// errAuditLinkedUnavailable means a batch cannot be sent as a linked flight;
// the caller commits it in two flights. Nothing was sent.
var errAuditLinkedUnavailable = errors.New("audit linked flight unavailable for this batch")

// errAuditLinkedHashMismatch means a linked batch COMMITTED but an entry_hash
// PostgreSQL computed differs from computeAuditEntryHash. Its items fail
// without a retry (finishAuditBatch): the rows are already in the table.
var errAuditLinkedHashMismatch = errors.New("SECURITY: audit linked flight stored an entry_hash that does not match the Go encoding")

// auditLinkedSQL is the linked statement. %[1]s is the events table, %[2]d the
// batch size, %[3]s the events INSERT that takes each row's prev_hash and
// entry_hash from c (auditLinkedInsert), $%[4]d the suffixes (bytea[], batch
// order), $%[5]d the genesis hash.
//
// The check's raise must never become a NULL (a NULL message casts to a NULL
// int and lets COMMIT run): every part of the message is non-NULL and an
// unknown condition takes the ELSE branch.
const auditLinkedSQL = `WITH RECURSIVE h AS (SELECT id, entry_hash FROM %[1]s ORDER BY id DESC LIMIT 1),
 c(i, prev_hash, entry_hash) AS (
  SELECT 1, p.prev, encode(sha256(int8send(octet_length(p.prev)::bigint) || convert_to(p.prev, 'UTF8') || ($%[4]d::bytea[])[1]), 'hex')
   FROM (SELECT COALESCE(NULLIF((SELECT entry_hash FROM h), ''), $%[5]d::text) AS prev) AS p
  UNION ALL
  SELECT c.i + 1, c.entry_hash, encode(sha256(int8send(octet_length(c.entry_hash)::bigint) || convert_to(c.entry_hash, 'UTF8') || ($%[4]d::bytea[])[c.i + 1]), 'hex')
   FROM c WHERE c.i < %[2]d),
 e AS (%[3]s)
 SELECT CASE WHEN s.n = %[2]d AND s.unlinked = 0 AND (s.first_src = 0 OR s.first_prev = $%[5]d::text) THEN 0
 ELSE ('audit linked batch not chained in id order: ' || s.n || ' rows stored, ' || s.unlinked || ' unlinked, lowest is '
  || CASE WHEN s.first_src = 0 THEN 'the head' ELSE 'row ' || COALESCE(s.first_id::text, 'none') END)::int END,
 COALESCE(s.head_id, 0), COALESCE(s.head_hash, ''), s.ids, s.prevs, s.entries
 FROM (SELECT count(*) FILTER (WHERE w.src = 1) AS n,
  count(*) FILTER (WHERE w.rn > 1 AND w.prev_hash IS DISTINCT FROM COALESCE(NULLIF(w.lp, ''), $%[5]d::text)) AS unlinked,
  (array_agg(w.src ORDER BY w.id))[1] AS first_src, (array_agg(w.prev_hash ORDER BY w.id))[1] AS first_prev, min(w.id) AS first_id,
  max(w.id) FILTER (WHERE w.src = 0) AS head_id, max(w.entry_hash) FILTER (WHERE w.src = 0) AS head_hash,
  array_agg(w.id ORDER BY w.id) FILTER (WHERE w.src = 1) AS ids,
  array_agg(w.prev_hash ORDER BY w.id) FILTER (WHERE w.src = 1) AS prevs,
  array_agg(w.entry_hash ORDER BY w.id) FILTER (WHERE w.src = 1) AS entries
  FROM (SELECT src, id, prev_hash, entry_hash, lag(entry_hash) OVER (ORDER BY id) AS lp, row_number() OVER (ORDER BY id) AS rn
   FROM (SELECT 0 AS src, id, NULL::text AS prev_hash, entry_hash FROM h UNION ALL SELECT 1, id, prev_hash, entry_hash FROM e) AS t) AS w) AS s`

// auditLinkedSuffixHook, when set (tests only), rewrites the suffixes sent,
// standing in for an encoding that drifted between Go and SQL.
var auditLinkedSuffixHook func([][]byte) [][]byte

// linkedAuditInsert rebuilds GORM's multi-row events INSERT (the VALUES
// clause and vars a DryRun Create built) as an INSERT ... SELECT from those
// VALUES joined to the linked rows c, in batch order, so that each row's
// prev_hash and entry_hash come from c instead of being bound. Every other
// value is GORM's own bind variable, unchanged and in the same order, cast to
// its column's type (types, from the catalog: a bind variable in a VALUES list
// under a SELECT has no column to take its type from), so the stored row is
// the one the other paths store. Rows are inserted in batch order, and the
// statement's check proves they were stored in that id order. It refuses
// (errAuditLinkedUnavailable) any statement whose shape is not exactly n rows
// of plain bind variables over typed columns that include prev_hash and
// entry_hash.
func linkedAuditInsert(table string, vals clause.Values, vars []any, n int, types map[string]string) (string, []any, error) {
	cols := len(vals.Columns)
	if len(vals.Values) != n || cols == 0 || len(vars) != n*cols {
		return "", nil, fmt.Errorf("%w: INSERT has %d rows of %d columns and %d vars, want %d rows", errAuditLinkedUnavailable, len(vals.Values), cols, len(vars), n)
	}
	var target, selected, aliases, casts []string
	keep := make([]bool, cols)
	hashes := 0
	for i, c := range vals.Columns {
		switch c.Name {
		case "prev_hash", "entry_hash":
			hashes++
			continue
		case "id":
			return "", nil, fmt.Errorf("%w: INSERT sets the id", errAuditLinkedUnavailable)
		}
		typ, ok := types[c.Name]
		if !ok {
			return "", nil, fmt.Errorf("%w: no column type for %q", errAuditLinkedUnavailable, c.Name)
		}
		keep[i] = true
		alias := fmt.Sprintf("v%d", len(aliases)+1)
		target = append(target, pgx.Identifier{c.Name}.Sanitize())
		aliases = append(aliases, alias)
		selected = append(selected, "v."+alias)
		casts = append(casts, typ)
	}
	if hashes != 2 {
		return "", nil, fmt.Errorf("%w: INSERT does not set prev_hash and entry_hash", errAuditLinkedUnavailable)
	}
	var b strings.Builder
	out := make([]any, 0, n*len(casts))
	fmt.Fprintf(&b, "INSERT INTO %s (%s,\"prev_hash\",\"entry_hash\") SELECT %s, c.prev_hash, c.entry_hash FROM (VALUES ",
		table, strings.Join(target, ","), strings.Join(selected, ", "))
	for r := range n {
		if r > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "(%d", r+1)
		k := 0
		for c := range cols {
			if !keep[c] {
				continue
			}
			out = append(out, vars[r*cols+c])
			fmt.Fprintf(&b, ",$%d::%s", len(out), casts[k])
			k++
		}
		b.WriteByte(')')
	}
	fmt.Fprintf(&b, `) AS v(i, %s) JOIN c ON c.i = v.i ORDER BY v.i RETURNING "id","prev_hash","entry_hash"`, strings.Join(aliases, ", "))
	return b.String(), out, nil
}

// auditEventsColumnTypes is the PostgreSQL type of every column of the audit
// events table, by name (format_type: the spelling a cast takes), resolved
// once per LocalStorage (ls.auditColTypes). It runs on pc, the connection the
// flight will use: the flusher never asks the pool for a second connection.
func (ls *LocalStorage) auditEventsColumnTypes(ctx context.Context, pc *pgx.Conn, table string) (map[string]string, error) {
	if m := ls.auditColTypes.Load(); m != nil {
		return *m, nil
	}
	rows, err := pc.Query(ctx, `SELECT a.attname::text, format_type(a.atttypid, a.atttypmod)
 FROM pg_attribute a WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped`, table)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	var name, typ string
	if _, err := pgx.ForEachRow(rows, []any{&name, &typ}, func() error {
		m[name] = typ
		return nil
	}); err != nil {
		return nil, err
	}
	ls.auditColTypes.Store(&m)
	return m, nil
}

// auditLinkedPlan is a linked-flight transaction built and not yet sent.
type auditLinkedPlan struct {
	f          *auditFlight
	preamble   int
	events     []*models.AuditEvent
	logInserts []auditPipelineInsert
}

// prepareAuditLinked builds batch's linked flight. Every error before
// anything is sent wraps errAuditLinkedUnavailable.
func (ls *LocalStorage) prepareAuditLinked(ctx context.Context, pc *pgx.Conn, batch []*auditBatchItem) (*auditLinkedPlan, error) {
	if ls.auditLinkedOff.Load() {
		return nil, fmt.Errorf("%w: turned off after an entry_hash mismatch", errAuditLinkedUnavailable)
	}
	table, err := ls.auditEventsTable(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errAuditLinkedUnavailable, err)
	}
	events := make([]*models.AuditEvent, 0, len(batch))
	suffixes := make([][]byte, 0, len(batch))
	var accessLogs []*models.SecretAccessLog
	for _, item := range batch {
		item.event.ID = 0
		item.event.PrevHash, item.event.EntryHash = "", ""
		if item.accessLog != nil {
			item.accessLog.ID = 0
			accessLogs = append(accessLogs, item.accessLog)
		}
		events = append(events, item.event)
		suffixes = append(suffixes, auditEntryHashSuffix(item.event))
	}
	if hook := auditLinkedSuffixHook; hook != nil {
		suffixes = hook(suffixes)
	}
	perStmt, err := auditInsertRowsPerStatement(events[0])
	if err != nil || len(events) > perStmt {
		return nil, fmt.Errorf("%w: a batch of %d rows does not fit one INSERT", errAuditLinkedUnavailable, len(events))
	}
	st := ls.auditDryRun(ctx).Clauses(auditInsertCheckReturning).Create(&events)
	if st.Error != nil {
		return nil, fmt.Errorf("%w: %w", errAuditLinkedUnavailable, st.Error)
	}
	stmt := st.Statement
	if s := stmt.Schema; s == nil || s.AfterCreate || s.AfterSave {
		return nil, fmt.Errorf("%w: %T has after-create hooks", errAuditLinkedUnavailable, events[0])
	}
	vals, ok := stmt.Clauses["VALUES"].Expression.(clause.Values)
	if !ok {
		return nil, fmt.Errorf("%w: INSERT has no VALUES clause", errAuditLinkedUnavailable)
	}
	quoted := pgx.Identifier{table}.Sanitize()
	types, err := ls.auditEventsColumnTypes(ctx, pc, quoted)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errAuditLinkedUnavailable, err)
	}
	insertSQL, vars, err := linkedAuditInsert(quoted, vals, stmt.Vars, len(events), types)
	if err != nil {
		return nil, err
	}
	linkedSQL := fmt.Sprintf(auditLinkedSQL, quoted, len(events), insertSQL, len(vars)+1, len(vars)+2)

	f := &auditFlight{ls: ls, ctx: ctx}
	f.queue("BEGIN")
	if durability := auditCommitDurabilityStatement(ls.auditSkipDurableSync); durability != "" {
		f.queue(durability)
	}
	f.queue("SELECT pg_advisory_xact_lock($1)", int64(auditAdvisoryLockKey))
	plan := &auditLinkedPlan{f: f, preamble: len(f.stmts), events: events}
	f.queue(linkedSQL, append(vars, suffixes, auditGenesisHash)...)
	if err := forEachAuditInsertChunk(accessLogs, func(chunk []*models.SecretAccessLog) error {
		ids := make([]*uint, len(chunk))
		for i, l := range chunk {
			ids[i] = &l.ID
		}
		ins, err := queueAuditInsert(f, chunk, ids, false)
		plan.logInserts = append(plan.logInserts, ins)
		return err
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", errAuditLinkedUnavailable, err)
	}
	f.queue("COMMIT")
	return plan, nil
}

// readLinked reads the linked statement's row: the check passed (it raises
// otherwise), the head it linked onto, and the stored rows in id order, which
// go onto events in batch order (the check proved they link in that order).
func (p *auditLinkedPlan) readLinked() (read auditChainHead, err error) {
	var (
		passed         int32
		headID         int64
		headHash       string
		ids            []uint
		prevs, entries []string
	)
	err = p.f.br.QueryRow().Scan(&passed, &headID, &headHash, &ids, &prevs, &entries)
	if err == nil && (len(ids) != len(p.events) || len(prevs) != len(p.events) || len(entries) != len(p.events)) {
		err = fmt.Errorf("audit linked flight: INSERT stored %d rows, want %d", len(ids), len(p.events))
	}
	for i := 0; err == nil && i < len(ids); i++ {
		if ids[i] == 0 {
			err = fmt.Errorf("audit linked flight: row %d was stored with id 0", i)
			break
		}
		e := p.events[i]
		e.ID, e.PrevHash, e.EntryHash = ids[i], prevs[i], entries[i]
	}
	if headID < 0 {
		headID = 0
	}
	return auditChainHead{id: uint(headID), hash: headHash}, p.f.done(int64(len(ids)), err)
}

// read reads the results of a sent linked plan, in order. beforeCommit is
// true when err belongs to a statement queued before COMMIT (see
// errAuditOneFlightRolledBack). On success it cross-checks every stored
// entry_hash against computeAuditEntryHash (see the file comment).
func (p *auditLinkedPlan) read(ls *LocalStorage) (read, last auditChainHead, beforeCommit bool, err error) {
	f := p.f
	beforeCommit = true
	err = func() error {
		for range p.preamble {
			if err := f.exec(); err != nil {
				return err
			}
		}
		var rerr error
		if read, rerr = p.readLinked(); rerr != nil {
			return rerr
		}
		for _, ins := range p.logInserts {
			if err := readAuditInsert(f, ins); err != nil {
				return err
			}
		}
		beforeCommit = false
		tag, err := f.br.Exec()
		if err == nil && tag.String() != "COMMIT" {
			err = fmt.Errorf("audit pipeline: COMMIT answered %q", tag.String())
		}
		return f.done(0, err)
	}()
	if err := f.close(err); err != nil {
		return read, auditChainHead{}, beforeCommit, err
	}
	if err := ls.crossCheckAuditLinked(read, p.events); err != nil {
		return read, auditChainHead{}, false, err
	}
	tail := p.events[len(p.events)-1]
	return read, auditChainHead{id: tail.ID, hash: tail.EntryHash}, false, nil
}

// crossCheckAuditLinked recomputes a committed linked batch's chain in Go:
// the first row must link onto the head the statement read (genesis when
// absent or unchained), each later row onto the previous one, and every
// entry_hash must be computeAuditEntryHash of its row. A mismatch turns the
// linked flight off for this process and fails the batch's items.
func (ls *LocalStorage) crossCheckAuditLinked(read auditChainHead, events []*models.AuditEvent) error {
	prev := read.hash
	if prev == "" {
		prev = auditGenesisHash
	}
	for i, e := range events {
		if e.PrevHash != prev || e.EntryHash != computeAuditEntryHash(e, prev) {
			ls.auditLinkedOff.Store(true)
			log.Printf("%v: row %d (batch row %d) prev_hash %q entry_hash %q; linked flights are off until restart, "+
				"`keyorix-server admin verify-audit` reports the row", errAuditLinkedHashMismatch, e.ID, i, e.PrevHash, e.EntryHash)
			return fmt.Errorf("%w: row %d", errAuditLinkedHashMismatch, e.ID)
		}
		prev = e.EntryHash
	}
	return nil
}

// runAuditLinked commits batch on pc as one linked flight. It returns the head
// the statement linked onto and the batch's last row. errAuditLinkedUnavailable
// (nothing sent) and errAuditOneFlightRolledBack (sent, provably nothing
// written) mean the caller may commit the batch in two flights instead.
func (ls *LocalStorage) runAuditLinked(ctx context.Context, pc *pgx.Conn, batch []*auditBatchItem) (read, last auditChainHead, err error) {
	plan, err := ls.prepareAuditLinked(ctx, pc, batch)
	if err != nil {
		return read, last, err
	}
	plan.f.send(pc)
	read, last, beforeCommit, err := plan.read(ls)
	if auditOneFlightRolledBack(err, beforeCommit) {
		return read, last, fmt.Errorf("%w: %w", errAuditOneFlightRolledBack, err)
	}
	if err == nil && ls.auditHead != nil {
		ls.auditHead.linkedCommits.Add(1)
	}
	return read, last, err
}
