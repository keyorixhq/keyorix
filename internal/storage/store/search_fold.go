package store

import (
	"github.com/keyorixhq/keyorix/internal/identity"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// foldedContainsClause returns a WHERE fragment and its bind argument that
// match rows whose text column col contains term, ignoring case in the
// Unicode sense, identically on SQLite and PostgreSQL.
//
// Both sides are folded with identity.FoldForSearch: the term here in Go, the
// column in SQL (keyorix_fold on SQLite, registered in
// internal/storage/sqlitedialect/fold.go; LOWER plus a final-sigma translate on
// PostgreSQL). A bare LIKE or LOWER() cannot be used: on SQLite both fold ASCII
// only, and on PostgreSQL LIKE is case-sensitive.
//
// col must be a trusted constant column name, never user input. term is
// LIKE-escaped (escapeLIKE) after folding, so %, _ and \ stay literal.
//
// Index note: a leading-wildcard LIKE over a function of the column was never
// index-assisted (neither the old LOWER(col) LIKE nor plain LIKE '%x%' could
// use a btree index), so this adds no new scan; it only adds a per-row fold.
func foldedContainsClause(dialect, col, term string) (string, string) {
	arg := "%" + escapeLIKE(identity.FoldForSearch(term)) + "%"
	if dialect == "postgres" {
		return "translate(LOWER(" + col + "), 'ς', 'σ') LIKE ? ESCAPE '\\'", arg
	}
	return sqlite.FoldFunc + "(" + col + ") LIKE ? ESCAPE '\\'", arg
}
