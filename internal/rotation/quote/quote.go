package quote

import (
	"fmt"
	"strings"
)

// QuoteIdentifier renders s as a double-quoted PostgreSQL identifier (internal quotes
// doubled), so a crafted role name cannot break out into SQL. This is layer TWO of
// defense in depth: layer ONE is core.validateRotationRef
// (internal/core/rotation_executor.go), which already rejects quotes/backslashes/
// semicolons (plus path/query metacharacters and control characters) in the ref at
// configuration time, before it is ever persisted. Keep both — this quoting must not be
// removed just because the earlier layer also covers it; this function is the only
// defense against a role name reaching this backend through any future write path.
func QuoteIdentifier(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// QuoteLiteral renders s as a single-quoted PostgreSQL string literal (internal quotes
// doubled). Relies on standard_conforming_strings (the default), so backslashes are
// literal. See QuoteIdentifier's comment above: this is layer TWO of defense in depth
// alongside core.validateRotationRef.
func QuoteLiteral(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
}

// QuoteMySQLString renders s as a single-quoted MySQL string literal with internal
// backslashes and single-quotes doubled — injection-safe under both the default and
// NO_BACKSLASH_ESCAPES sql_modes. This is layer TWO of defense in depth: layer ONE is
// core.validateRotationRef (internal/core/rotation_executor.go), which already rejects
// quotes/backslashes/semicolons (plus path/query metacharacters and control characters)
// in the ref at configuration time, before it is ever persisted. Keep both — this
// quoting must not be removed just because the earlier layer also covers it; this
// function is the only defense against a ref/host reaching this backend through any
// future write path.
func QuoteMySQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return "'" + s + "'"
}

// isAlnumByte reports whether b is an ASCII letter or digit. Anything else — '_', '-',
// '.', '/', ':', a quote, a space — counts as an explicit boundary between identifier
// segments for PrefixAllowed below.
func isAlnumByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// PrefixAllowed reports whether ref is permitted by an allowed-refs prefix allowlist: an
// empty list places no restriction; otherwise ref must equal one of the entries, or
// extend one at an explicit segment boundary — never merely share a prefix with one. A
// guardrail on top of the backend admin identity's own privileges.
//
// #G46: a raw strings.HasPrefix let an allowed_refs entry of "myapp" also admit
// "myapp2"/"myappadmin" — an unintended superset an operator who configured "myapp"
// (without a trailing delimiter) would not expect. The match must now land on an
// explicit boundary: either the configured prefix's own last character is already
// non-alphanumeric (the pre-existing convention of e.g. "app_" already relies on this —
// the operator's own choice already delimits it), or ref's very next character after the
// prefix is.
func PrefixAllowed(allowed []string, ref string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, p := range allowed {
		if p == "" {
			continue
		}
		if ref == p {
			return true
		}
		if !strings.HasPrefix(ref, p) {
			continue
		}
		if !isAlnumByte(p[len(p)-1]) {
			return true
		}
		if len(ref) > len(p) && !isAlnumByte(ref[len(p)]) {
			return true
		}
	}
	return false
}

// ValidateAzureRef checks ref against the Graph-path-safety and allowed_refs rules that
// AzureAppSecretExecutor.GenerateUpstream (internal/rotation/azure.go) applies before it
// ever reaches the Microsoft Graph client. Extracted so the invariant — a ref containing
// a path/query metacharacter is always rejected before any upstream call — can be fuzzed
// as a pure function; GenerateUpstream itself stays in package rotation because it also
// performs real Graph I/O once validation passes. name is the backend's name, used only
// to format the allowed_refs error the same way GenerateUpstream always has.
//
// ref is interpolated into the Graph URL path by GenerateUpstream; an app object id is a
// GUID, so reject any path/query metacharacter. Without this, a crafted ref that begins
// with an allowed prefix (e.g. "<allowed-guid>/../<victim-guid>") could path-traverse to
// a different application and defeat allowed_refs.
func ValidateAzureRef(name, ref string, allowedRefs []string) error {
	if ref == "" {
		return fmt.Errorf("azure-app: application object id (ref) is required")
	}
	if strings.ContainsAny(ref, "/?#%") {
		return fmt.Errorf("azure-app: invalid application object id %q (must be a bare GUID)", ref)
	}
	if len(allowedRefs) == 0 {
		return fmt.Errorf("azure-app: backend %q has no allowed_refs configured — refusing to rotate (fail-closed)", name)
	}
	if !PrefixAllowed(allowedRefs, ref) {
		return fmt.Errorf("azure-app: application %q is not permitted by this backend's allowed_refs", ref)
	}
	return nil
}
