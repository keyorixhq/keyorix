package cmd

import "strings"

// sanitizeSecretName normalises a source path/key into a Keyorix secret name: path
// separators, spaces, and colons collapse to '-', repeated '-' collapse, and surrounding '-'
// are trimmed. Ported from internal/cli/secret/source.go's sanitizeSecretName (old CLI) —
// keyorix-migrate cannot import it (docs/design-keyorix-migrate.md's module boundary), and a
// deterministic, matching name-derivation rule is required for idempotent re-runs to look up
// the same target name every time. Case is preserved (source names are often meaningful and
// case-sensitive).
func sanitizeSecretName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-").Replace(s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}
