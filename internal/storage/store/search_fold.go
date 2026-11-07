package store

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/identity"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// foldedContainsClause returns a WHERE fragment and its bind argument that
// match rows whose text column col contains term, ignoring case in the
// Unicode sense, identically on SQLite and PostgreSQL.
//
// On SQLite both sides are folded with identity.FoldForSearch: the term here in
// Go, the column by keyorix_fold (registered in
// internal/storage/sqlitedialect/fold.go). On PostgreSQL both sides go through
// one SQL expression, normalize(..., NFC), LOWER and a final-sigma translate,
// so the fold is the same whatever the column collation (on a C/POSIX-collated
// database LOWER() leaves non-ASCII letters unchanged, on both sides, so an
// exact-case search still finds itself but a different-case one does not).
// The stored column is NFC-normalized on both backends, so a name stored
// decomposed (NFD) is found by composed input.
// A bare LIKE or LOWER() cannot be used: on SQLite both fold ASCII only, and on
// PostgreSQL LIKE is case-sensitive.
//
// PostgreSQL's normalize() and the non-ASCII translate literals need a UTF8
// server encoding; on any other encoding the statement errors (search fails
// closed, never a wider result).
//
// col must be a trusted constant column name, never user input. term is
// LIKE-escaped (escapeLIKE) after folding, so %, _ and \ stay literal.
//
// Index note: a leading-wildcard LIKE over a function of the column was never
// index-assisted (neither the old LOWER(col) LIKE nor plain LIKE '%x%' could
// use a btree index), so this adds no new scan; it only adds a per-row fold.
func foldedContainsClause(dialect, col, term string) (string, string) {
	if dialect == "postgres" {
		// The term goes through the same SQL fold as the column, not Go's
		// unicode.ToLower: PostgreSQL LOWER() follows the column collation, so on a
		// C/POSIX-collated database it leaves non-ASCII letters alone, and a term
		// lowered in Go would no longer match even its own exact-case value.
		// LOWER, normalize and translate leave \ % _ untouched, so escaping the
		// raw term first is safe.
		//
		// A bind parameter carries the database default collation, not the
		// column's, so "? || substr(col, 1, 0)" (an empty string from the column)
		// gives the term the column's collation; otherwise a column-level
		// COLLATE "C" in a non-C database would still fold the two sides apart.
		const fold = "translate(LOWER(normalize(%s, NFC)), 'ς', 'σ')"
		return fmt.Sprintf(fold, col) + " LIKE " + fmt.Sprintf(fold, "? || substr("+col+", 1, 0)") + " ESCAPE '\\'",
			"%" + escapeLIKE(term) + "%"
	}
	return sqlite.FoldFunc + "(" + col + ") LIKE ? ESCAPE '\\'",
		"%" + escapeLIKE(identity.FoldForSearch(term)) + "%"
}
