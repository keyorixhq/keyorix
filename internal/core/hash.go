// hash.go — shared token-hashing helper.
package core

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Hex returns the SHA-256 hex digest of a raw token — the stored, indexed form
// for both setup tokens (ADR-028) and personal access tokens (ADR-027). The plaintext
// token is never persisted; lookups are by this hash.
func sha256Hex(raw string) string {
	// codeql[go/weak-sensitive-data-hashing] -- raw is a high-entropy random
	// PAT/setup token, not a password; this is a deterministic lookup hash, not
	// credential storage, so a slow KDF would only slow legitimate lookups.
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
