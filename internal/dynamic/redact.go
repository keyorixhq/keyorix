package dynamic

import (
	"regexp"
	"strings"
)

// redactedPlaceholder replaces any credential fragment this file's patterns
// recognize.
const redactedPlaceholder = "***REDACTED***"

// dsnUserinfoPattern matches the userinfo component of a URL-style connection
// string -- scheme://user:password@host... -- as produced by postgres://,
// mysql://, mongodb://, redis://, rediss:// DSNs. It intentionally matches
// greedily up to the LAST '@' before the next '/' so a password containing an
// unescaped '@' doesn't leave a residual fragment.
var dsnUserinfoPattern = regexp.MustCompile(`://[^\s/]*@`)

// kvCredentialPattern matches key=value pairs whose key names a credential
// field, case-insensitively, in the ODBC/connection-string style
// ("Server=...;Uid=admin;Pwd=hunter2;") or a URL query string
// ("...&password=hunter2"). The value is everything up to the next
// delimiter (';', '&', whitespace) or end of string.
var kvCredentialPattern = regexp.MustCompile(`(?i)\b(password|pwd|passwd|secret|token|access_key_id|access_key|secret_access_key|session_token|api_key|apikey|auth)\s*=\s*[^;&\s]+`)

// RedactSensitive strips connection-string/DSN credential fragments (URL
// userinfo, ODBC/query-string key=value credential fields) from s. It is a
// defense-in-depth text filter, not a parser or a guarantee: it cannot prove
// no future backend or driver version ever echoes a credential in some other
// shape, but it removes every shape the drivers this package wraps today
// (pgx, go-sql-driver/mysql, mongo-driver, go-redis) are capable of producing
// -- and, unlike a per-call-site fix, closes the gap for a future 5th
// dynamic-secret backend too.
func RedactSensitive(s string) string {
	s = dsnUserinfoPattern.ReplaceAllString(s, "://"+redactedPlaceholder+"@")
	s = kvCredentialPattern.ReplaceAllStringFunc(s, func(m string) string {
		if idx := strings.IndexByte(m, '='); idx >= 0 {
			return m[:idx+1] + redactedPlaceholder
		}
		return m
	})
	return s
}

// SanitizeErrorMessage returns err's Error() text with RedactSensitive
// applied, safe to pass to log.Printf/log.Println (or any other sink that
// isn't the deliberately-generic client-facing message). Use this in place of
// formatting a backend/driver error directly with %v/%s anywhere a
// dynamic-secret engine's error might reach a log call -- see the package
// comment on why raw driver errors from postgres/mysql/mongodb/redis must
// never be logged unsanitized.
func SanitizeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return RedactSensitive(err.Error())
}
