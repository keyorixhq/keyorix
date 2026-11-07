package middleware

import "strings"

// loggableQueryKeys is the allowlist of query-parameter names whose VALUES may
// appear in the access log. Everything else is logged as "[redacted]".
//
// Redaction is by default (allowlist), not by exception (denylist): a caller can
// put anything in a URL query, including a password, API key or token on a route
// that never asked for one, and a denylist of known-sensitive routes cannot see
// that. Keep this list to parameters that are pagination, sorting, boolean
// switches, enumerations and numeric/time identifiers. Never add a name that can
// carry a secret reference or name (ref, name, q, search), credential-like value
// (code, state, token, key, value, password), person identifier (username, email,
// ip, actor, external_id), opaque cursor, redirect target or free-form filter.
var loggableQueryKeys = map[string]struct{}{
	"page": {}, "page_size": {}, "pageSize": {}, "limit": {}, "offset": {}, "startIndex": {}, "count": {},
	"sort_by": {}, "sort_order": {}, "format": {}, "days": {}, "lead_days": {},
	"since": {}, "until": {}, "start_time": {}, "end_time": {}, "expires_before": {},
	"project_id": {}, "environment_id": {}, "environment": {}, "secret_id": {}, "secretId": {},
	"parent_id": {}, "after_id": {}, "user_id": {},
	"action": {}, "actor_type": {}, "type": {}, "status": {}, "severity": {},
	"classification": {}, "alertType": {}, "resource_type": {}, "resource": {},
	"recipientType": {}, "permission": {},
	"include_value": {}, "include_deleted": {}, "include_total": {}, "is_active": {},
	"unread": {}, "unacknowledged": {}, "acknowledged": {}, "stale": {}, "full": {},
	"force": {}, "dry_run": {}, "all": {}, "folder_only": {},
	"show_shared_only": {}, "show_owned_only": {},
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
		if _, ok := loggableQueryKeys[key]; ok {
			// An allowlisted name is not enough: the value must also have a
			// strict shape, or a caller can smuggle a secret after it.
			if loggableQueryValue(val) {
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

// maxLoggableQueryValue caps the length of a value that is logged verbatim.
const maxLoggableQueryValue = 64

// loggableQueryValue reports whether the raw (still percent-encoded) value of an
// allowlisted parameter may be logged: 1..64 characters of [A-Za-z0-9_.:-]. That
// rejects '%', ';', '/', '+', '&' and '=', so encoded or delimiter smuggling and
// path-like secret references fail closed (logged as "[redacted]").
func loggableQueryValue(v string) bool {
	if v == "" || len(v) > maxLoggableQueryValue {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}
