// secret_value_policy.go — an optional, operator-configured quality gate on the
// VALUES stored in secrets (distinct from the user-login PasswordPolicy in ADR-025).
// When enabled it rejects obviously-weak or placeholder secret values at create and
// rotate time, so a "changeme" never silently becomes a production credential. The
// policy is OFF by default, so existing installs are unaffected until they opt in.
package core

import (
	"fmt"
	"strings"
)

// SecretValuePolicy describes the quality rules applied to a secret's value on write.
type SecretValuePolicy struct {
	Enabled bool
	// MinLength rejects values shorter than this many bytes (0 = no minimum).
	MinLength int
	// RejectCommon rejects a built-in denylist of weak/placeholder values.
	RejectCommon bool
	// ExtraDenylist adds installation-specific rejected values (case-insensitive).
	ExtraDenylist []string
}

// DefaultSecretValuePolicy returns the disabled (no-op) policy.
func DefaultSecretValuePolicy() SecretValuePolicy { return SecretValuePolicy{} }

// commonWeakValues is a small built-in denylist of values that are never an
// acceptable secret. Keys are lower-cased and trimmed.
var commonWeakValues = map[string]bool{
	"": true, "changeme": true, "change-me": true, "changeit": true,
	"password": true, "passw0rd": true, "p@ssw0rd": true, "secret": true,
	"123456": true, "1234567": true, "12345678": true, "123456789": true,
	"qwerty": true, "admin": true, "root": true, "test": true, "letmein": true,
	"default": true, "example": true, "demo": true, "null": true, "none": true,
	"tbd": true, "todo": true, "xxx": true,
}

// Validate returns a non-nil error (describing the reason ONLY — never echoing the
// value) when value violates the policy. A disabled policy always passes.
func (p SecretValuePolicy) Validate(value []byte) error {
	if !p.Enabled {
		return nil
	}
	if p.MinLength > 0 && len(value) < p.MinLength {
		return fmt.Errorf("secret value is shorter than the %d-character minimum", p.MinLength)
	}
	norm := strings.ToLower(strings.TrimSpace(string(value)))
	if p.RejectCommon && commonWeakValues[norm] {
		return fmt.Errorf("secret value is a known weak or placeholder value")
	}
	for _, d := range p.ExtraDenylist {
		if strings.ToLower(strings.TrimSpace(d)) == norm {
			return fmt.Errorf("secret value is on the configured denylist")
		}
	}
	return nil
}
