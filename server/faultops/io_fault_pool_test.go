package faultops

// io_fault_pool_test.go: a test-only gorm.ConnPool wrapper that injects
// environment faults BENEATH the storage layer, at a fuzz-chosen SQL statement or
// COMMIT of one operation: disk full (ENOSPC), an I/O error (EIO), an I/O error
// reported AFTER the statement took effect, a dropped connection (on PostgreSQL the
// backend is really terminated with pg_terminate_backend), a stalled write that
// hits its deadline, and a COMMIT whose acknowledgement is lost (unknown outcome).
//
// Why a pool wrapper and not a seam in production code: gorm hands every statement
// and every transaction boundary to db.Statement.ConnPool, so replacing that one
// field on the world's root *gorm.DB sits under the whole storage layer with no
// production change. faultstorage faults a storage METHOD; this faults a SQL
// STATEMENT inside it, which is the only way to reach a storage method that issues
// several autocommit statements (a partial write) or a transaction whose COMMIT
// outcome the caller cannot know.
//
// What it does NOT model: a torn page or a sector-level fault inside SQLite or
// PostgreSQL (the engine would refuse to open, or recover, below this layer; that
// is scripts/powercut and scripts/powercut-pg), and a wire-level cut of a business
// transaction between COMMIT sent and acknowledged on a real PostgreSQL socket
// (server/pgfault does that for the audit-commit path only; here the same outcome
// is produced one layer higher, by running the real COMMIT and then reporting a
// connection error).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

type ioFaultKind uint8

const (
	// ioDiskFullBefore: ENOSPC, the statement did not run.
	ioDiskFullBefore ioFaultKind = iota
	// ioEIOBefore: EIO, the statement did not run.
	ioEIOBefore
	// ioEIOAfter: the statement ran and took effect, then EIO is reported (an
	// fsync that fails after the kernel applied the write). Ambiguous outcome.
	ioEIOAfter
	// ioConnDropBefore: the connection is lost before the statement runs. On
	// PostgreSQL inside a transaction the backend is really terminated.
	ioConnDropBefore
	// ioSlowDeadline: the write stalls until its deadline; the statement did not run.
	ioSlowDeadline
	// ioCommitAckLost: the real COMMIT runs, then a connection error is reported.
	ioCommitAckLost
	// ioCommitNeverArrived: the connection is lost before COMMIT reaches the
	// server, so the transaction cannot have committed.
	ioCommitNeverArrived
	numIOFaultKinds
)

func (k ioFaultKind) String() string {
	switch k {
	case ioDiskFullBefore:
		return "enospc-before"
	case ioEIOBefore:
		return "eio-before"
	case ioEIOAfter:
		return "eio-after-effect"
	case ioConnDropBefore:
		return "conn-drop-before"
	case ioSlowDeadline:
		return "slow-deadline"
	case ioCommitAckLost:
		return "commit-ack-lost"
	case ioCommitNeverArrived:
		return "commit-never-arrived"
	}
	return fmt.Sprintf("io-kind-%d", uint8(k))
}

func (k ioFaultKind) isCommit() bool { return k == ioCommitAckLost || k == ioCommitNeverArrived }

// storageKind maps the driver-level fault onto the storage-level kind the existing
// oracles reason about: an outcome the caller cannot know is effect-then-error.
func (k ioFaultKind) storageKind() faultstorage.FaultKind {
	if k == ioEIOAfter || k == ioCommitAckLost {
		return faultstorage.KindEffectThenError
	}
	return faultstorage.KindError
}

type ioFault struct {
	kind ioFaultKind
	at   int // 1-based ordinal: statements for statement kinds, COMMITs for commit kinds
	// sticky: after the first hit, every later statement of the same class keeps
	// failing, as a full or failing disk does: every write for ENOSPC, every
	// statement for EIO. A sticky fault also defeats an in-method fallback read,
	// which is what makes the fail-closed authz oracle (c) sound for it.
	sticky bool
}

func isWriteSQL(q string) bool {
	q = strings.ToUpper(strings.TrimSpace(q))
	for _, w := range []string{"INSERT", "UPDATE", "DELETE", "SAVEPOINT", "RELEASE", "CREATE", "ALTER", "DROP"} {
		if strings.HasPrefix(q, w) {
			return true
		}
	}
	return false
}

// ioAttribution says which storage method the faulted statement belongs to, so the
// existing oracles' per-method rules apply. It is the most recently STARTED storage
// call, which is exact for the sequential request path and a best effort when a
// detached goroutine interleaves (the fuzz target drains those before judging).
type ioAttribution struct {
	method string
	nth    int
	sql    string
}

type ioFaultPool struct {
	inner   gorm.ConnPool
	backend string
	admin   *gorm.DB // PostgreSQL only: a direct handle, outside the faulted pool
	calls   func() []faultstorage.CallRecord

	mu      sync.Mutex
	armed   *ioFault
	stmts   int
	commits int
	fired   bool
	// terminated counts PostgreSQL backends this pool really terminated.
	terminated int
	attr       ioAttribution
	// base is the length of the call log when the pool was armed (see Arm).
	base int
	// swallow is a PLANTED BUG for the red proofs: a write that hit a "before"
	// fault is reported as a success without running, which is exactly the defect
	// "success returned after a failed durable write" the oracles must catch.
	swallow bool
}

func (p *ioFaultPool) Arm(f *ioFault) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.armed, p.stmts, p.commits, p.fired, p.attr = f, 0, 0, false, ioAttribution{}
	// The call log also holds the setup's calls; an ordinal counts from here, like
	// FaultyStorage.Arm's NthCall, so the per-method rules keyed on it keep their meaning.
	p.base = 0
	if p.calls != nil {
		p.base = len(p.calls())
	}
}

func (p *ioFaultPool) Disarm() { p.Arm(nil) }

func (p *ioFaultPool) Fired() (bool, ioAttribution) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fired, p.attr
}

func (p *ioFaultPool) hit(query string, commit, audit bool) (ioFaultKind, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.armed == nil {
		return 0, false
	}
	if p.fired {
		k := p.armed.kind
		if !p.armed.sticky || (k != ioDiskFullBefore && k != ioEIOBefore) {
			return 0, false
		}
		if k == ioDiskFullBefore && !commit && !isWriteSQL(query) {
			return 0, false
		}
		return k, true
	}
	if p.armed.kind.isCommit() != commit {
		return 0, false
	}
	if commit {
		p.commits++
		if p.commits != p.armed.at {
			return 0, false
		}
	} else {
		p.stmts++
		if p.stmts != p.armed.at {
			return 0, false
		}
	}
	p.fired = true
	p.attr = p.attribute(query, commit, audit)
	return p.armed.kind, true
}

func (p *ioFaultPool) attribute(query string, commit, audit bool) ioAttribution {
	a := ioAttribution{sql: strings.Join(strings.Fields(query), " ")}
	if audit {
		a.sql += " [transaction writes audit_events]"
	}
	a.method = storageMethodOnStack()
	if commit && a.method == "" {
		a.method = "WithTransaction"
	}
	if os.Getenv("IOFAULT_STACK") != "" { // triage aid: where did the faulted statement come from
		buf := make([]byte, 16<<10)
		fmt.Fprintf(os.Stderr, "IOFAULT-STACK method=%q\n%s\n", a.method, buf[:runtime.Stack(buf, false)])
	}
	if audit && (a.method == "" || (commit && a.method == "WithTransaction")) {
		// A statement of the audit append that no storage method issued (the chain-tail
		// read of the audit writer), or the COMMIT of a transaction that writes
		// audit_events (whose acknowledgement may be lost): both are LogAuditEvent's work,
		// so that method's rules apply, and they are the rules the storage-level fuzz can
		// drive (a COMMIT-level WithTransaction row could not be driven there).
		a.method = "LogAuditEvent"
	}
	if a.method == "" {
		return a // a statement outside any storage call (a detached flusher): no method rules apply
	}
	log := p.calls()
	if p.base <= len(log) {
		log = log[p.base:]
	}
	for _, c := range log {
		if c.Method == a.method {
			a.nth++
		}
	}
	return a
}

var storageMethodSet = sync.OnceValue(func() map[string]bool {
	m := map[string]bool{}
	for _, n := range storageInterfaceMethodNames() {
		m[n] = true
	}
	return m
})

// storageMethodOnStack names the innermost storage.Storage method the calling
// goroutine is executing, from the call stack. The faultstorage call log only says
// which method STARTED last, which is wrong for a statement issued by a cache hit,
// by a detached goroutine, or after a method returned; the stack is exact.
func storageMethodOnStack() string {
	pcs := make([]uintptr, 64)
	n := runtime.Callers(3, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	const marker = "/internal/storage/store.(*LocalStorage)."
	for {
		fr, more := frames.Next()
		if i := strings.Index(fr.Function, marker); i >= 0 {
			name := fr.Function[i+len(marker):]
			if j := strings.IndexAny(name, ".-"); j >= 0 {
				name = name[:j]
			}
			if storageMethodSet()[name] {
				return name
			}
		}
		if !more {
			return ""
		}
	}
}

// errFor builds the error a real engine reports for this fault. Only the class is
// meaningful; the oracles never compare the text.
func (p *ioFaultPool) errFor(k ioFaultKind) error {
	enospc := k == ioDiskFullBefore
	if p.backend == "postgres" {
		if enospc {
			return &pgconn.PgError{Severity: "ERROR", Code: "53100", Message: `could not extend file "base/16384/2619": No space left on device`}
		}
		return &pgconn.PgError{Severity: "ERROR", Code: "58030", Message: `could not write block 0 of relation base/16384/2619: Input/output error`}
	}
	if enospc {
		return fmt.Errorf("database or disk is full (13): %w", syscall.ENOSPC)
	}
	return fmt.Errorf("disk I/O error (10): %w", syscall.EIO)
}

func errConnReset() error {
	return &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
}

// stallToDeadline models a write that does not return before its deadline.
func stallToDeadline(ctx context.Context) error {
	t := time.NewTimer(30 * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return fmt.Errorf("write: i/o timeout: %w", context.DeadlineExceeded)
	}
}

type fakeResult struct{}

func (fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (fakeResult) RowsAffected() (int64, error) { return 1, nil }

// ioConn is the part shared by the root pool and a transaction.
type ioConn struct {
	p     *ioFaultPool
	inner gorm.ConnPool
	tx    *sql.Tx // nil at the root
	audit bool    // some statement of this transaction wrote audit_events
}

// touchesAudit records and reports whether q (or an earlier statement of this
// transaction) writes the audit table: such a transaction is the best-effort audit
// write, whose loss on a reported success is documented (LogAuditEvent in
// bestEffortTables), so the lost-audit oracle must not blame it.
func (c *ioConn) touchesAudit(q string) bool {
	if strings.Contains(q, "audit_events") {
		if c.tx != nil {
			c.audit = true // per transaction; the root is shared and must stay unmarked
		}
		return true
	}
	return c.audit
}

// dropBackend terminates the PostgreSQL backend serving this transaction. It
// reports whether it did; false means the caller must simulate the drop itself.
func (c *ioConn) dropBackend(ctx context.Context) bool {
	if c.p.admin == nil || c.tx == nil {
		return false
	}
	var pid int
	if err := c.tx.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		return false
	}
	if c.p.admin.Exec("SELECT pg_terminate_backend(?)", pid).Error != nil {
		return false
	}
	c.p.mu.Lock()
	c.p.terminated++
	c.p.mu.Unlock()
	return true
}

func (c *ioConn) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	return c.inner.PrepareContext(ctx, q)
}

func (c *ioConn) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	kind, fire := c.p.hit(q, false, c.touchesAudit(q))
	if !fire {
		return c.inner.ExecContext(ctx, q, args...)
	}
	switch kind {
	case ioDiskFullBefore, ioEIOBefore:
		if c.p.swallow {
			return fakeResult{}, nil
		}
		return nil, c.p.errFor(kind)
	case ioSlowDeadline:
		return nil, stallToDeadline(ctx)
	case ioConnDropBefore:
		if c.dropBackend(ctx) {
			return c.inner.ExecContext(ctx, q, args...)
		}
		return nil, errConnReset()
	case ioEIOAfter:
		if _, err := c.inner.ExecContext(ctx, q, args...); err != nil {
			return nil, err
		}
		return nil, c.p.errFor(kind)
	}
	return c.inner.ExecContext(ctx, q, args...)
}

func (c *ioConn) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	kind, fire := c.p.hit(q, false, c.touchesAudit(q))
	if !fire {
		return c.inner.QueryContext(ctx, q, args...)
	}
	switch kind {
	case ioDiskFullBefore, ioEIOBefore:
		if c.p.swallow && (strings.Contains(strings.ToUpper(q), "INSERT") || strings.Contains(strings.ToUpper(q), "UPDATE") || strings.Contains(strings.ToUpper(q), "DELETE")) {
			return c.inner.QueryContext(ctx, "SELECT 1 WHERE 1=0") // an empty answer: the write silently did not happen
		}
		return nil, c.p.errFor(kind)
	case ioSlowDeadline:
		return nil, stallToDeadline(ctx)
	case ioConnDropBefore:
		if c.dropBackend(ctx) {
			return c.inner.QueryContext(ctx, q, args...)
		}
		return nil, errConnReset()
	case ioEIOAfter:
		rows, err := c.inner.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		_ = rows.Close()
		return nil, c.p.errFor(kind)
	}
	return c.inner.QueryContext(ctx, q, args...)
}

// QueryRowContext cannot return an error row directly (sql.Row has no public
// constructor), so a faulted single-row read is reported as a cancelled context.
func (c *ioConn) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	if _, fire := c.p.hit(q, false, c.touchesAudit(q)); fire {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		return c.inner.QueryRowContext(cctx, q, args...)
	}
	return c.inner.QueryRowContext(ctx, q, args...)
}

// ioRoot is the pool gorm sees at the root. It must NOT implement
// gorm.TxCommitter, or gorm would treat every call as already inside a transaction.
type ioRoot struct{ *ioConn }

func (r *ioRoot) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	b, ok := r.inner.(gorm.TxBeginner)
	if !ok {
		return nil, errors.New("ioFaultPool: the wrapped pool cannot begin a transaction")
	}
	tx, err := b.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &ioTx{&ioConn{p: r.p, inner: tx, tx: tx}}, nil
}

func (r *ioRoot) GetDBConn() (*sql.DB, error) {
	if g, ok := r.inner.(gorm.GetDBConnector); ok {
		return g.GetDBConn()
	}
	if d, ok := r.inner.(*sql.DB); ok {
		return d, nil
	}
	return nil, gorm.ErrInvalidDB
}

type ioTx struct{ *ioConn }

func (t *ioTx) Commit() error {
	kind, fire := t.p.hit("COMMIT", true, t.audit)
	if !fire {
		return t.tx.Commit()
	}
	switch kind {
	case ioCommitAckLost:
		if err := t.tx.Commit(); err != nil {
			return err
		}
		return errConnReset()
	case ioDiskFullBefore, ioEIOBefore: // sticky: the commit's own write fails too
		_ = t.tx.Rollback()
		return t.p.errFor(kind)
	case ioCommitNeverArrived:
		if t.dropBackend(context.Background()) {
			return t.tx.Commit()
		}
		_ = t.tx.Rollback()
		return errConnReset()
	}
	return t.tx.Commit()
}

func (t *ioTx) Rollback() error { return t.tx.Rollback() }

// installIOFaultPool replaces w.db's connection pool with a pass-through
// ioFaultPool and returns it. Every LocalStorage built on w.db afterwards (the
// world rebuilds one on each reset) goes through it. Call once per world.
func installIOFaultPool(tb tbLite, w *faultWorld) *ioFaultPool {
	tb.Helper()
	orig := w.db.ConnPool
	p := &ioFaultPool{inner: orig, backend: w.backend, calls: func() []faultstorage.CallRecord { return w.faulty.Calls() }}
	if w.backend == "postgres" {
		admin, err := gorm.Open(postgres.Open(os.Getenv(pgDSNEnv)), &gorm.Config{})
		if err != nil {
			tb.Fatalf("io fault pool: open PostgreSQL admin handle: %v", err)
		}
		sqlDB, err := admin.DB()
		if err != nil {
			tb.Fatalf("io fault pool: admin sql.DB: %v", err)
		}
		sqlDB.SetMaxOpenConns(1)
		tb.Cleanup(func() { _ = sqlDB.Close() })
		p.admin = admin
	}
	root := &ioRoot{&ioConn{p: p, inner: orig}}
	w.db.Config.ConnPool = root
	w.db.Statement.ConnPool = root
	tb.Cleanup(func() {
		w.db.Config.ConnPool = orig
		w.db.Statement.ConnPool = orig
	})
	return p
}
