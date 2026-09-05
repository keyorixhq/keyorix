// secret_size_policy.go — the always-on maximum-secret-value-size cap.
//
// Distinct in kind from secret_value_policy.go's SecretValuePolicy: that policy is
// an OPTIONAL quality gate (off by default, rejects weak/placeholder values) an
// operator opts into. This cap is a RESOURCE-PROTECTION limit and is on by
// default everywhere a KeyorixCore exists (CLI local mode included, not just the
// HTTP/gRPC server) — see DefaultMaxSecretSize below, set directly in
// NewKeyorixCore rather than left at a disabled zero value the way
// SecretValuePolicy's zero value is.
package core

import "fmt"

// DefaultMaxSecretSize mirrors internal/config.DefaultMaxSecretSize (64 KiB) —
// this package cannot import internal/config (config depends on nothing above
// it in the layering; core must not become a dependency of it), so the two
// constants are independently defined and kept in sync by
// TestDefaultMaxSecretSize_MatchesConfigDefault. This is the fallback used when
// a KeyorixCore is constructed without SetMaxSecretSize ever being called (every
// CLI local-mode command; see internal/cli/modes.go) — it must be a real,
// enforced value on its own, not a sentinel meaning "unlimited".
const DefaultMaxSecretSize = 65536

// SecretValueTooLargeError is returned when a secret value exceeds the
// configured (or default) maximum size. A typed error, not a plain
// fmt.Errorf, so the HTTP and gRPC transports can map it to a precise status
// (413 / ResourceExhausted) via errors.As instead of string-matching the
// message the way most of this package's other validation errors are mapped
// at the handler layer — worth the small inconsistency here because the
// message itself needs to name the exact limit, which a transport-layer
// string match can't reconstruct reliably.
type SecretValueTooLargeError struct {
	Size  int
	Limit int
}

func (e *SecretValueTooLargeError) Error() string {
	return fmt.Sprintf("secret value is %d bytes, which exceeds the configured maximum of %d bytes", e.Size, e.Limit)
}

// SetMaxSecretSize configures the maximum secret VALUE size (bytes) enforced on
// create/update/rotate. The server calls this at startup with the validated
// config value (internal/config.Config.Secrets.Limits.MaxSecretSize, already
// defaulted and ceiling-checked by Config.Validate). n <= 0 is treated as "not
// configured" and falls back to DefaultMaxSecretSize, matching Validate's own
// zero-means-default handling — this setter does not need to be called at all
// for the cap to be enforced; NewKeyorixCore already sets the default.
func (c *KeyorixCore) SetMaxSecretSize(n int) {
	if n <= 0 {
		n = DefaultMaxSecretSize
	}
	c.maxSecretSize = n
}

// checkSecretSize enforces the configured maximum secret VALUE size. Called from
// every write path that sets a secret's value (CreateSecret, UpdateSecret,
// RotateSecret) — never from a read or delete path: a secret already stored
// above the current cap (e.g. written before this existed, or before an
// operator lowered secrets.limits.max_secret_size) must remain fully readable
// and deletable. Only new writes are rejected.
func (c *KeyorixCore) checkSecretSize(value []byte) error {
	limit := c.maxSecretSize
	if limit <= 0 {
		// Defense in depth against a KeyorixCore constructed via a struct
		// literal rather than NewKeyorixCore (bypassing its default) — the
		// cap must never silently become "unlimited".
		limit = DefaultMaxSecretSize
	}
	if len(value) > limit {
		return &SecretValueTooLargeError{Size: len(value), Limit: limit}
	}
	return nil
}
