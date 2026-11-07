package sqlite

import (
	"database/sql/driver"

	msqlite "modernc.org/sqlite"

	"github.com/keyorixhq/keyorix/internal/identity"
)

// FoldFunc is the name of the SQL scalar function registered on every SQLite
// connection: keyorix_fold(text) returns identity.FoldForSearch(text).
//
// SQLite's built-in LOWER() and LIKE fold ASCII only, so a search for "äö"
// would not find "ÄÖ" there while PostgreSQL finds it. Rather than add folded
// shadow columns (a schema migration) for every searchable display column,
// list filters compare keyorix_fold(column) with a Go-folded pattern. The
// built-in LOWER() is intentionally left alone: expression indexes such as
// the projects LOWER(name) unique index were built with its ASCII semantics.
const FoldFunc = "keyorix_fold"

func init() {
	// Registered once, process-wide, for every connection the "sqlite" driver
	// opens afterwards (including ones that bypass this dialector).
	msqlite.MustRegisterDeterministicScalarFunction(FoldFunc, 1,
		func(_ *msqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			switch v := args[0].(type) {
			case string:
				return identity.FoldForSearch(v), nil
			case []byte:
				return identity.FoldForSearch(string(v)), nil
			default: // NULL, numbers: pass through unchanged
				return v, nil
			}
		})
}
