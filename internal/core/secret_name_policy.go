// secret_name_policy.go — an optional, operator-configured naming convention for
// secrets: a regex the name must match and/or a maximum length, enforced at create
// time. Lets an org keep secret names consistent (e.g. UPPER_SNAKE, a team prefix).
// OFF by default, so existing installs are unaffected until they opt in. Distinct from
// the value gate ([[secret_value_policy]]); this governs the NAME, never the value.
package core

import (
	"fmt"
	"regexp"
	"unicode/utf8"
)

// SecretNamePolicy describes the naming convention applied to a secret's name on
// create. Pattern is an RE2 regular expression; operators should anchor it (^…$) for
// a whole-name match. Empty Pattern skips the regex check; MaxLength 0 skips the
// length check.
type SecretNamePolicy struct {
	Enabled   bool
	Pattern   string
	MaxLength int
}

// DefaultSecretNamePolicy returns the disabled (no-op) policy.
func DefaultSecretNamePolicy() SecretNamePolicy { return SecretNamePolicy{} }

// validateSecretName checks a name against the configured naming policy. Returns a
// non-nil error describing the violation; a disabled policy always passes. The regex
// is pre-compiled by SetSecretNamePolicy (c.secretNameRe).
func (c *KeyorixCore) validateSecretName(name string) error {
	p := c.secretNamePolicy
	if !p.Enabled {
		return nil
	}
	if p.MaxLength > 0 && utf8.RuneCountInString(name) > p.MaxLength {
		return fmt.Errorf("secret name exceeds the %d-character maximum", p.MaxLength)
	}
	if c.secretNameRe != nil && !c.secretNameRe.MatchString(name) {
		return fmt.Errorf("secret name does not match the required pattern %q", p.Pattern)
	}
	return nil
}

// compileNamePattern compiles a name-policy pattern, used by SetSecretNamePolicy and
// reusable for config validation. Returns nil regexp for an empty pattern.
//
// #389: the pattern is unconditionally wrapped in ^(?:…)$ rather than compiled as
// given. validateSecretName calls MatchString, which succeeds on ANY matching
// substring, not a whole-string match — an operator writing
// "[A-Za-z][A-Za-z0-9_-]*" intending "identifier-like names only" would, unanchored,
// accept virtually any string containing at least one such substring (e.g. a
// CSV-injection-shaped `=cmd|' /C calc'!A1`, or a name embedding control
// characters), silently defeating the exact protection several OTHER findings (the
// #328 CSV/Slack-injection family) depend on this policy to provide once "properly
// configured". Forcing the anchor here — instead of only advising it in a doc
// comment — closes that gap unconditionally; wrapping an already-anchored pattern
// (e.g. "^[A-Z_]+$") in an extra ^(?:...)$ is a no-op.
func compileNamePattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return nil, fmt.Errorf("invalid secret name pattern: %w", err)
	}
	return re, nil
}
