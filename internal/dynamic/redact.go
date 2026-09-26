package dynamic

import (
	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// redactedPlaceholder mirrors ports.RedactSensitive's own placeholder
// constant — kept here (unused by this file's own re-exports below) purely so
// redact_test.go's assertions can reference it without importing ports for a
// single string literal.
const redactedPlaceholder = "***REDACTED***"

// RedactSensitive strips connection-string/DSN credential fragments (URL
// userinfo, ODBC/query-string key=value credential fields) from s. It is a
// defense-in-depth text filter, not a parser or a guarantee: it cannot prove
// no future backend or driver version ever echoes a credential in some other
// shape, but it removes every shape the drivers this package wraps today
// (pgx, go-sql-driver/mysql, mongo-driver, go-redis) are capable of producing
// -- and, unlike a per-call-site fix, closes the gap for a future 5th
// dynamic-secret backend too.
//
// The implementation lives in ports.RedactSensitive (ADR-109 step 3) so
// internal/core can sanitize a backend error before logging it
// (dynamic_secrets.go) without importing this package; this re-export keeps
// the pre-existing dynamic.RedactSensitive call sites (server/http/handlers/
// dynamic_secrets.go) and this package's own log_redaction_guard_test.go
// working unchanged. An earlier version of the userinfo pattern excluded '/'
// from the character class, which meant ANY password containing a literal
// '/' (plausible for a base64-shaped generated credential) was left
// completely unredacted rather than partially redacted -- found and fixed
// after adversarial verification reproduced it against a real
// postgres://user:base64pass/w+xyz==@host DSN; see ports.RedactSensitive's
// patterns for the current, fixed behavior.
func RedactSensitive(s string) string { return ports.RedactSensitive(s) }

// SanitizeErrorMessage returns err's Error() text with RedactSensitive
// applied, safe to pass to log.Printf/log.Println (or any other sink that
// isn't the deliberately-generic client-facing message). Use this in place of
// formatting a backend/driver error directly with %v/%s anywhere a
// dynamic-secret engine's error might reach a log call -- see the package
// comment on why raw driver errors from postgres/mysql/mongodb/redis must
// never be logged unsanitized. See RedactSensitive's doc comment for why this
// delegates to ports.SanitizeErrorMessage.
func SanitizeErrorMessage(err error) string { return ports.SanitizeErrorMessage(err) }
