package resguard

import (
	"sync/atomic"

	"gorm.io/gorm"
)

// DBMeter is the database-cost seam: a gorm plugin that counts the SQL
// statements and rows affected per input, so a single logical operation that
// fans out into an unbounded number of queries (an N+1 blow-up, a per-element
// round-trip driven by attacker input) shows up as a large Cost.DBQueries even
// though nothing is slow enough to trip a wall-clock guard on a fast local DB.
//
// Install it once on the fuzzworld DB with Install(db); the Probe reads and
// resets it per input. It counts every callback-visible statement (create,
// query, update, delete, raw row); it does NOT see work done inside the DB
// (a server-side trigger, a recursive CTE) — only statements issued by this
// process. Stated so DBQueries is read as "round-trips", not "total DB work".
type DBMeter struct {
	queries atomic.Int64
	rows    atomic.Int64
}

// NewDBMeter returns a DBMeter not yet attached to any DB.
func NewDBMeter() *DBMeter { return &DBMeter{} }

func (m *DBMeter) reset() { m.queries.Store(0); m.rows.Store(0) }

func (m *DBMeter) read() (queries int, rows int64) {
	return int(m.queries.Load()), m.rows.Load()
}

// Queries/Rows expose live totals outside the Probe.
func (m *DBMeter) Queries() int { return int(m.queries.Load()) }
func (m *DBMeter) Rows() int64  { return m.rows.Load() }

// Install registers after-callbacks on db for every statement kind. Idempotent
// per db only if called once; calling twice double-counts (gorm keeps both
// callbacks), so install exactly once per world.
func (m *DBMeter) Install(db *gorm.DB) error {
	count := func(tx *gorm.DB) {
		m.queries.Add(1)
		if tx.RowsAffected > 0 {
			m.rows.Add(tx.RowsAffected)
		}
	}
	cb := db.Callback()
	// Register on the tail of each processor so RowsAffected is populated.
	if err := cb.Create().After("gorm:create").Register("resguard:count_create", count); err != nil {
		return err
	}
	if err := cb.Query().After("gorm:query").Register("resguard:count_query", count); err != nil {
		return err
	}
	if err := cb.Update().After("gorm:update").Register("resguard:count_update", count); err != nil {
		return err
	}
	if err := cb.Delete().After("gorm:delete").Register("resguard:count_delete", count); err != nil {
		return err
	}
	if err := cb.Row().After("gorm:row").Register("resguard:count_row", count); err != nil {
		return err
	}
	if err := cb.Raw().After("gorm:raw").Register("resguard:count_raw", count); err != nil {
		return err
	}
	return nil
}
