package fuzzworld

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// This file adds the Phase-2 integrity checks for a reused world (RSG1): a
// digest that must match the baseline after every reset, a live-vs-declared
// table-list check so a forgotten table fails loudly, a process-state reset
// registry for state that lives OUTSIDE the DB, and a re-verify step that
// replays a failing input on a fresh world to separate a genuine finding from a
// STATE-DEPENDENT one.

// WorldDigest is a cheap fingerprint of a world's observable state: per-table
// row counts and (Postgres only) sequence last-values. After a reset it must
// equal the post-bootstrap baseline; a mismatch means the reset did not restore
// the world and every subsequent input ran against drifted state.
type WorldDigest struct {
	Backend   string
	Rows      map[string]int64
	Sequences map[string]int64
}

// Digest reads the row count of each table in tables (and, on Postgres, every
// sequence in the current schema). tables is the same hand-named list the reset
// uses, so Digest and Reset cover exactly the same surface.
func Digest(w *World, tables []string) (WorldDigest, error) {
	d := WorldDigest{Backend: w.Backend, Rows: map[string]int64{}, Sequences: map[string]int64{}}
	for _, t := range tables {
		var n int64
		if err := w.DB.Table(t).Count(&n).Error; err != nil {
			return d, fmt.Errorf("digest count %s: %w", t, err)
		}
		d.Rows[t] = n
	}
	if w.Backend == BackendPostgres {
		rows, err := w.DB.Raw("SELECT sequencename, last_value FROM pg_sequences WHERE schemaname = current_schema()").Rows()
		if err != nil {
			return d, fmt.Errorf("digest sequences: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var name string
			var last sql.NullInt64
			if err := rows.Scan(&name, &last); err != nil {
				return d, fmt.Errorf("digest scan sequence: %w", err)
			}
			d.Sequences[name] = last.Int64 // 0 when the sequence has never advanced
		}
		if err := rows.Err(); err != nil {
			return d, err
		}
	}
	return d, nil
}

// Equal reports whether two digests match, with a human diff of the first few
// mismatches when they do not.
func (d WorldDigest) Equal(other WorldDigest) (bool, string) {
	var diffs []string
	if d.Backend != other.Backend {
		diffs = append(diffs, fmt.Sprintf("backend %s != %s", d.Backend, other.Backend))
	}
	diffMap := func(kind string, a, b map[string]int64) {
		for k, av := range a {
			if bv, ok := b[k]; !ok {
				diffs = append(diffs, fmt.Sprintf("%s %s present only in first", kind, k))
			} else if av != bv {
				diffs = append(diffs, fmt.Sprintf("%s %s: %d != %d", kind, k, av, bv))
			}
		}
		for k := range b {
			if _, ok := a[k]; !ok {
				diffs = append(diffs, fmt.Sprintf("%s %s present only in second", kind, k))
			}
		}
	}
	diffMap("rows", d.Rows, other.Rows)
	diffMap("seq", d.Sequences, other.Sequences)
	sort.Strings(diffs)
	if len(diffs) == 0 {
		return true, ""
	}
	if len(diffs) > 8 {
		diffs = append(diffs[:8], fmt.Sprintf("… and %d more", len(diffs)-8))
	}
	return false, strings.Join(diffs, "; ")
}

// LiveTables returns the application tables that actually exist in w's schema,
// excluding the engine's own metadata tables.
func LiveTables(w *World) ([]string, error) {
	var names []string
	var err error
	switch w.Backend {
	case BackendPostgres:
		err = w.DB.Raw("SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY tablename").Scan(&names).Error
	default:
		err = w.DB.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").Scan(&names).Error
	}
	return names, err
}

// CheckResetList fails loudly when the hand-named reset list has drifted from
// the live schema: a live table missing from the reset list (a FORGOTTEN table
// that would accumulate rows across inputs and decay the fuzzer) or a reset-list
// entry that no longer exists (a STALE name). exempt lists tables that live but
// are intentionally never reset (static lookup data a migration seeds); they are
// neither forgotten nor stale. Returns nil when the lists agree.
func CheckResetList(w *World, resetTables []string, exempt ...string) error {
	live, err := LiveTables(w)
	if err != nil {
		return fmt.Errorf("live tables: %w", err)
	}
	liveSet := toSet(live)
	resetSet := toSet(resetTables)
	exemptSet := toSet(exempt)

	var forgotten, stale []string
	for t := range liveSet {
		if !resetSet[t] && !exemptSet[t] {
			forgotten = append(forgotten, t)
		}
	}
	for t := range resetSet {
		if !liveSet[t] {
			stale = append(stale, t)
		}
	}
	if len(forgotten) == 0 && len(stale) == 0 {
		return nil
	}
	sort.Strings(forgotten)
	sort.Strings(stale)
	var b strings.Builder
	fmt.Fprintf(&b, "reset table list drifted from live schema (%s)", w.Backend)
	if len(forgotten) > 0 {
		fmt.Fprintf(&b, "; FORGOTTEN (live but not reset): %s", strings.Join(forgotten, ", "))
	}
	if len(stale) > 0 {
		fmt.Fprintf(&b, "; STALE (reset but not live): %s", strings.Join(stale, ", "))
	}
	return fmt.Errorf("%s", b.String())
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ProcessReset is a registry of reset functions for state that lives OUTSIDE
// the DB and would otherwise leak across inputs in a reused world: an auth/token
// cache, a fake clock, rate limiters, connection pools, an in-memory key
// directory. A harness registers each with Add; the per-iteration reset calls
// Run alongside World.Reset so "reset" means the whole world, not just its rows.
type ProcessReset struct{ fns []func() }

// Add registers a reset function (nil is ignored).
func (p *ProcessReset) Add(fn func()) {
	if fn != nil {
		p.fns = append(p.fns, fn)
	}
}

// Run calls every registered reset function in registration order.
func (p *ProcessReset) Run() {
	for _, fn := range p.fns {
		fn()
	}
}

// ReVerify replays a failing input on a freshly built world to tell a genuine
// finding from a state-dependent artefact. replay runs the input against fresh
// and returns whether it failed there. If it failed on both the reused world
// (the caller already knows that) and fresh, ReVerify returns "" — the finding
// reproduces, report it normally. If it passed on fresh, ReVerify returns a
// STATE-DEPENDENT message: a lead (the failure needs accumulated state), not
// noise to discard.
func ReVerify(fresh *World, replay func(*World) (failed bool)) string {
	if replay(fresh) {
		return "" // reproduces on a clean world: a real finding
	}
	return "STATE-DEPENDENT: input fails in the reused world but PASSES on a freshly built one — " +
		"the failure depends on state accumulated across inputs, not on the input alone; investigate the accumulation, not just the input"
}
