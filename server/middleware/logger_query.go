package middleware

import "strings"

// queryValueKind is the value grammar an allowlisted parameter may carry. One
// shared shape for every key let Keyorix's own tokens (kx_pat_, kx_machine_) and
// any plain identifier through under e.g. ?format=, so each key gets the
// narrowest grammar its legitimate values need.
type queryValueKind uint8

const (
	kindDigits queryValueKind = iota + 1 // 1..20 ASCII digits: pagination, counts, numeric ids
	kindBool                             // true|false|1|0
	kindTime                             // date/RFC3339 shape, starts with a digit
	kindEnum                             // short lowercase enum, never a kx_ credential prefix
)

// loggableQueryKeys is the allowlist of query-parameter names whose VALUES may
// appear in the access log, each with the value grammar it is checked against.
// Everything else is logged as "[redacted]".
//
// Redaction is by default (allowlist), not by exception (denylist): a caller can
// put anything in a URL query, including a password, API key or token on a route
// that never asked for one, and a denylist of known-sensitive routes cannot see
// that. Keep this list to parameters that are pagination, sorting, boolean
// switches, enumerations and numeric/time identifiers. Never add a name that can
// carry a secret reference or name (ref, name, q, search), credential-like value
// (code, state, token, key, value, password), person identifier (username, email,
// ip, actor, external_id), opaque cursor, redirect target or free-form filter.
//
// What the value check does NOT cover: a short (<=32 chars) all-lowercase secret
// sent under an enum key still matches the enum grammar. Digits, bool and time
// keys cannot carry a credential-shaped value.
var loggableQueryKeys = map[string]queryValueKind{
	"page": kindDigits, "page_size": kindDigits, "pageSize": kindDigits, "limit": kindDigits,
	"offset": kindDigits, "startIndex": kindDigits, "count": kindDigits,
	"days": kindDigits, "lead_days": kindDigits,
	"project_id": kindDigits, "environment_id": kindDigits, "secret_id": kindDigits, "secretId": kindDigits,
	"parent_id": kindDigits, "after_id": kindDigits, "user_id": kindDigits,

	"since": kindTime, "until": kindTime, "start_time": kindTime, "end_time": kindTime, "expires_before": kindTime,

	"include_value": kindBool, "include_deleted": kindBool, "include_total": kindBool, "is_active": kindBool,
	"unread": kindBool, "unacknowledged": kindBool, "acknowledged": kindBool, "stale": kindBool, "full": kindBool,
	"force": kindBool, "dry_run": kindBool, "all": kindBool, "folder_only": kindBool,
	"show_shared_only": kindBool, "show_owned_only": kindBool,

	"sort_by": kindEnum, "sort_order": kindEnum, "format": kindEnum, "environment": kindEnum,
	"action": kindEnum, "actor_type": kindEnum, "type": kindEnum, "status": kindEnum, "severity": kindEnum,
	"classification": kindEnum, "alertType": kindEnum, "resource_type": kindEnum, "resource": kindEnum,
	"recipientType": kindEnum, "permission": kindEnum,
}

// sensitiveQueryKeys is a short fixed set of well-known credential/identity
// parameter names. Their VALUES are always redacted; the NAME is kept so the log
// still shows that such a parameter was sent. This is not a denylist of what to
// redact: any name in neither set is replaced entirely.
var sensitiveQueryKeys = map[string]struct{}{
	"password": {}, "passwd": {}, "token": {}, "access_token": {}, "refresh_token": {},
	"api_key": {}, "apikey": {}, "secret": {}, "code": {}, "state": {}, "key": {}, "value": {},
	"ref": {}, "name": {}, "q": {}, "search": {}, "username": {}, "email": {},
}

const redactedMark = "[redacted]"

// redactQueryParams rewrites a raw query string so only allowlisted parameter
// values survive. A parameter name is kept only when it is allowlisted or one of
// the fixed sensitiveQueryKeys (so the log still shows a credential was sent);
// every other name is replaced, because a bare token or odd key name can itself
// be the secret.
func redactQueryParams(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	parts := strings.Split(rawQuery, "&")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		key, val, hasEq := strings.Cut(p, "=")
		if !hasEq {
			out = append(out, redactedMark) // bare token: could be the credential itself
			continue
		}
		if kind, ok := loggableQueryKeys[key]; ok {
			// An allowlisted name is not enough: the value must also match the
			// key's own grammar, or a caller can smuggle a secret after it.
			if loggableQueryValue(kind, val) {
				out = append(out, p)
			} else {
				out = append(out, key+"="+redactedMark)
			}
			continue
		}
		// A key name outside the allowlist can itself be the credential
		// (?ghp_...=1), so only a fixed set of well-known sensitive names is
		// kept, to show that such a parameter was sent. Every other name is
		// replaced.
		if _, ok := sensitiveQueryKeys[key]; ok {
			out = append(out, key+"="+redactedMark)
		} else {
			out = append(out, redactedMark+"="+redactedMark)
		}
	}
	return strings.Join(out, "&")
}

const (
	maxLoggableDigits = 20
	maxLoggableTime   = 35
	maxLoggableEnum   = 32
)

// loggableQueryValue reports whether the raw (still percent-encoded) value of an
// allowlisted parameter matches the grammar of its kind. '%', ';', '/', '+', '&'
// and '=' are never accepted, so encoded or delimiter smuggling and path-like
// secret references fail closed (logged as "[redacted]").
func loggableQueryValue(kind queryValueKind, v string) bool {
	switch kind {
	case kindDigits:
		return len(v) >= 1 && len(v) <= maxLoggableDigits && allBytes(v, isDigit)
	case kindBool:
		return v == "true" || v == "false" || v == "1" || v == "0"
	case kindTime:
		return len(v) >= 1 && len(v) <= maxLoggableTime && isDigit(v[0]) &&
			allBytes(v, func(c byte) bool { return isDigit(c) || c == '-' || c == ':' || c == '.' || c == 'T' || c == 'Z' })
	case kindEnum:
		// No kx_ prefix: that is the start of every Keyorix credential.
		return len(v) >= 1 && len(v) <= maxLoggableEnum && !strings.HasPrefix(v, "kx_") &&
			allBytes(v, func(c byte) bool {
				return (c >= 'a' && c <= 'z') || isDigit(c) || c == '_' || c == '.' || c == ':' || c == '-'
			})
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func allBytes(v string, ok func(byte) bool) bool {
	for i := 0; i < len(v); i++ {
		if !ok(v[i]) {
			return false
		}
	}
	return true
}
