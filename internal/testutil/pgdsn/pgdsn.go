// Package pgdsn builds a schema-scoped Postgres DSN from either accepted DSN
// form (see PGSearchPathDSN) for tests that isolate themselves into a fresh
// schema on a shared KEYORIX_TEST_PG_DSN server.
package pgdsn

import (
	"net/url"
	"strings"
)

// PGSearchPathDSN returns base with search_path pointed at schema, for either
// DSN form KEYORIX_TEST_PG_DSN is allowed to take:
//   - keyword/value ("host=localhost port=5432 dbname=x user=y sslmode=disable"):
//     append " search_path=<schema>", the libpq keyword/value syntax.
//   - URL ("postgres://user:pass@host:port/db?sslmode=disable"): append
//     "search_path=<schema>" as a query parameter — space-concatenating onto a
//     URL is invalid syntax and fails to parse (pgconn: "failed to configure
//     TLS (sslmode is invalid)"), since the trailing " search_path=x" gets
//     read as part of the query string's last value, not a new parameter.
func PGSearchPathDSN(base, schema string) string {
	if strings.HasPrefix(base, "postgres://") || strings.HasPrefix(base, "postgresql://") {
		sep := "?"
		if strings.Contains(base, "?") {
			sep = "&"
		}
		return base + sep + "search_path=" + url.QueryEscape(schema)
	}
	return base + " search_path=" + schema
}
