package handlers

import (
	"crypto/fips140"
	"testing"
)

// skipUnderFIPS140Only skips a test whose FIXTURE, not the code under test,
// uses a primitive Go's FIPS 140-only mode refuses (GODEBUG=fips140=only).
// The reason names what the fixture does and why production is not affected.
func skipUnderFIPS140Only(t *testing.T, reason string) {
	t.Helper()
	if fips140.Enforced() {
		t.Skip("fips140=only: " + reason)
	}
}
