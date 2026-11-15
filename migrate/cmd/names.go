package cmd

import (
	"strings"
	"unicode"
)

// sanitizeSecretName normalises a source path/key into a Keyorix secret name: path separators,
// spaces, and colons collapse to '-', control characters are dropped, repeated '-' collapse, and
// surrounding '-' and whitespace are trimmed. Ported from internal/cli/secret/source.go's sanitizeSecretName
// (old CLI) and hardened: keyorix-migrate cannot import it (docs/design-keyorix-migrate.md's
// module boundary), and a deterministic, matching name-derivation rule is required for idempotent
// re-runs to look up the same target name every time. Case is preserved (source names are often
// meaningful and case-sensitive).
//
// Two postconditions this function guarantees (campaign FINDING F1):
//   - the result carries NO control character (a Vault KV key or cloud secret name may contain
//     control bytes; they must never reach the create-secret API embedded in a name), and
//   - the function is a FIXED POINT: sanitizeSecretName(sanitizeSecretName(s)) == sanitizeSecretName(s),
//     so a re-run derives the identical name (idempotency, task oracle (d)).
//
// It MAY return "" for a degenerate input made entirely of separators/control characters (e.g.
// "---" or "\x00"). An empty name is never a valid Keyorix secret name, so the callers
// (cmd/vault.go, cmd/cloud_common.go) SKIP such an entry with a reported reason rather than
// sending an empty name to the API — see emptyDerivedNameSkipReason. The function does not invent
// a fallback name, which would make every degenerate source name collide on one target name.
func sanitizeSecretName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-").Replace(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	// Trim '-' AND Unicode whitespace together: the TrimSpace above runs before the strip, so a
	// non-ASCII space next to a dropped control byte or a trimmed '-' would otherwise reach the
	// edge only now and be removed by a second call (not a fixed point).
	return strings.TrimFunc(s, func(r rune) bool { return r == '-' || unicode.IsSpace(r) })
}

// emptyDerivedNameSkipReason is the Skip reason for a source item whose name/key normalises to an
// empty Keyorix secret name (it was made entirely of path separators and/or control characters).
// Reported, never silently dropped — an absent row is indistinguishable from an item that never
// existed (mirrors vaultsource's empty-value/empty-field-name skips).
const emptyDerivedNameSkipReason = "source name/key normalises to an empty Keyorix secret name (only separators or control characters) — not imported"
