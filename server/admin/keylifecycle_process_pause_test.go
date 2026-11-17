// keylifecycle_process_pause_test.go — the rotate_dek_pause child of the
// process-level key-lifecycle harness (keylifecycle_process_harness_test.go): a
// REAL DEK rotation that parks itself at an exact phase so the parent can SIGKILL
// it there. A wall-clock kill cannot reach these phases: the window between the
// sweep's COMMIT and the dek.key.pending -> dek.key rename is a few syscalls long.
//
// The pause sits at the DATABASE DRIVER boundary, not in production code: the
// child runs the production Service.RotateDEKWithSweep over a *gorm.DB whose
// connection pool is wrapped by klPausePool. The wrapper only watches the SQL the
// rotation sends; it changes no statement and no result. Two pause points:
//
//   - klPauseAfterCommit: right after the COMMIT of the transaction that wrote the
//     redo marker (dek_rotation.promote_pending). The rows are under the new DEK,
//     dek.key is still the old one and dek.key.pending is the only copy of the new
//     one: the state RecoverInterruptedRotation exists for.
//   - klPauseBeforeMarkerClear: right before the DELETE of that marker, after the
//     promote. dek.key is the new DEK, the marker is still committed.
//
// What it does NOT reproduce: the CLI's openKeyWriter steps that do not apply to
// a source store this harness built (the restore-journal refusal, the
// missing-keys refusal); the child runs the lock, key-set reconcile, crash
// recovery and Initialize steps in the same order openKeyWriter does.
package admin

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
)

const (
	klPauseAfterCommit       = "after-commit"
	klPauseBeforeMarkerClear = "before-marker-clear"
	// klRedoMarkerKey is internal/encryption's dekRotationPromotePendingKey
	// (unexported). TestKLRedProof_OracleD_Recovery fails if the pause never
	// triggers, so a renamed key cannot make the pause silently miss.
	klRedoMarkerKey = "dek_rotation.promote_pending"
)

// klChildRotatePause runs a real DEK rotation that parks at KL_PAUSE, writes
// KL_READY, and waits to be SIGKILLed. Returning at all is UNEXPECTED: the
// pause point was not reached (or the rotation failed before it).
func klChildRotatePause(cfg *config.Config) klResult {
	dir := os.Getenv(klEnvDir)
	pass := os.Getenv(klMasterPassEnv)
	mode := os.Getenv(klEnvPause)
	svc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return klResultFromErr(err)
	}
	defer svc.Shutdown()
	if err := svc.ReconcileKeySet(); err != nil {
		return klResultFromErr(err)
	}
	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		return klResultFromErr(err)
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	if err := svc.RecoverInterruptedRotation(db); err != nil {
		return klResultFromErr(err)
	}
	if err := svc.Initialize(pass); err != nil {
		return klResultFromErr(err)
	}
	pool := &klPausePool{inner: db.Statement.ConnPool, mode: mode, ready: os.Getenv(klEnvReady)}
	db.ConnPool = pool
	db.Statement.ConnPool = pool
	_, rerr := svc.RotateDEKWithSweep(pass, db)
	return klResult{ErrKind: "UNEXPECTED", ErrMsg: fmt.Sprintf("rotation returned without reaching pause point %q (err=%v)", mode, rerr)}
}

// klPausePool wraps the rotation's connection pool. armed is set once the
// redo-marker transaction has committed.
type klPausePool struct {
	inner gorm.ConnPool
	mode  string
	ready string
	armed atomic.Bool
}

func (p *klPausePool) pause() {
	_ = os.WriteFile(p.ready, []byte(p.mode), 0600)
	// The parent SIGKILLs us here. The bound only matters for an orphaned child.
	time.Sleep(2 * klChildTimeout)
}

func klIsDelete(query string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "DELETE")
}

// klIsMarkerWrite: a statement that writes (not deletes) the redo marker. A
// DELETE of it (clearCompletedRotationMarker, recovery) must not arm the pause.
func klIsMarkerWrite(query string, args []any) bool {
	return !klIsDelete(query) && klIsMarkerSQL(query, args)
}

func klIsMarkerSQL(query string, args []any) bool {
	if !strings.Contains(query, "system_metadata") {
		return false
	}
	for _, a := range args {
		if s, ok := a.(string); ok && s == klRedoMarkerKey {
			return true
		}
	}
	return false
}

func (p *klPausePool) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return p.inner.PrepareContext(ctx, query)
}

// pauseBeforeMarkerDelete parks before the DELETE of the redo marker once the
// marker's transaction has committed. gorm runs that DELETE in its own implicit
// transaction, so both the pool and klPauseTx call this.
func (p *klPausePool) pauseBeforeMarkerDelete(query string, args []any) {
	if p.mode == klPauseBeforeMarkerClear && p.armed.Load() && klIsDelete(query) && klIsMarkerSQL(query, args) {
		p.pause()
	}
}

func (p *klPausePool) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	p.pauseBeforeMarkerDelete(query, args)
	return p.inner.ExecContext(ctx, query, args...)
}

func (p *klPausePool) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return p.inner.QueryContext(ctx, query, args...)
}

func (p *klPausePool) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return p.inner.QueryRowContext(ctx, query, args...)
}

// GetDBConn keeps db.DB() working through the wrapper.
func (p *klPausePool) GetDBConn() (*sql.DB, error) {
	switch inner := p.inner.(type) {
	case *sql.DB:
		return inner, nil
	case gorm.GetDBConnector:
		return inner.GetDBConn()
	}
	return nil, fmt.Errorf("klPausePool: inner pool %T has no *sql.DB", p.inner)
}

// klTxPool is what a transaction's connection pool must offer gorm: the
// statements plus Commit/Rollback (*sql.Tx, or storage's gated SQLite tx).
type klTxPool interface {
	gorm.ConnPool
	gorm.TxCommitter
}

func (p *klPausePool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	var (
		inner gorm.ConnPool
		err   error
	)
	switch b := p.inner.(type) {
	case gorm.TxBeginner:
		inner, err = b.BeginTx(ctx, opts)
	case gorm.ConnPoolBeginner:
		inner, err = b.BeginTx(ctx, opts)
	default:
		return nil, fmt.Errorf("klPausePool: inner pool %T cannot begin a transaction", p.inner)
	}
	if err != nil {
		return nil, err
	}
	tx, ok := inner.(klTxPool)
	if !ok {
		return nil, fmt.Errorf("klPausePool: transaction %T has no Commit/Rollback", inner)
	}
	return &klPauseTx{klTxPool: tx, pool: p}, nil
}

// klPauseTx records whether its transaction wrote the redo marker, and pauses
// after that transaction's COMMIT returned success.
type klPauseTx struct {
	klTxPool
	pool        *klPausePool
	wroteMarker bool
}

func (t *klPauseTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	t.pool.pauseBeforeMarkerDelete(query, args)
	if klIsMarkerWrite(query, args) {
		t.wroteMarker = true
	}
	return t.klTxPool.ExecContext(ctx, query, args...)
}

func (t *klPauseTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if klIsMarkerWrite(query, args) {
		t.wroteMarker = true
	}
	return t.klTxPool.QueryContext(ctx, query, args...)
}

func (t *klPauseTx) Commit() error {
	err := t.klTxPool.Commit()
	if err == nil && t.wroteMarker {
		t.pool.armed.Store(true)
		if t.pool.mode == klPauseAfterCommit {
			t.pool.pause()
		}
	}
	return err
}
