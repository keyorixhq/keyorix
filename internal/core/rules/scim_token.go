package rules

import "fmt"

// MinSCIMTokenLength is the minimum length required for the configured SCIM
// bearer token (scim.token / KEYORIX_SCIM_TOKEN). Unlike a PAT or machine token
// (always server-generated, 32 random bytes — see pat.go/machine_token.go), the
// SCIM token is operator-supplied and had no strength floor at all: an operator
// could configure a short, guessable string and the provisioning endpoint would
// accept it, in constant time, forever. 20 chars from a typical token alphabet is
// already >=119 bits of entropy, well above what's brute-forceable over the
// network — the same bar DefaultPasswordPolicy sets for a human password (16
// chars, but with mandatory character-class mixing this token doesn't have; the
// higher floor compensates). Checked once at server startup (see
// server/http/router.go), not per-request, so a misconfigured install fails fast
// with a clear error instead of quietly running with a weak provisioning
// credential.
const MinSCIMTokenLength = 20

// ValidateSCIMTokenStrength rejects a configured SCIM bearer token shorter than
// MinSCIMTokenLength. An empty token is NOT an error here — SCIM being disabled or
// not yet configured is legitimate; server/middleware/scim.go's SCIMToken already
// fails every request closed on an empty token. This only guards against a
// too-short but non-empty token, which the constant-time compare would otherwise
// accept as configured.
func ValidateSCIMTokenStrength(token string) error {
	if token == "" {
		return nil
	}
	if len(token) < MinSCIMTokenLength {
		return fmt.Errorf("SCIM token is too short (%d chars, minimum %d) — configure a longer, high-entropy token via KEYORIX_SCIM_TOKEN", len(token), MinSCIMTokenLength)
	}
	return nil
}
