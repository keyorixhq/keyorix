// Package uuidhostile fuzzes github.com/google/uuid's string parser.
//
// Reachability (traced, honest, WEAK): google/uuid is not imported by any
// first-party Keyorix package. It is pulled into the build only through
// go-webauthn/webauthn/protocol, reached from internal/webauthnrp, which parses
// attacker-supplied WebAuthn attestation objects. go-webauthn turns the 16-byte
// AAGUID in authenticator data into a uuid via uuid.FromBytes (the byte path),
// NOT uuid.Parse (the string path) — so the string parser fuzzed here is only
// indirectly reachable at best. google/uuid is a well-maintained Google library;
// this target is a low-yield robustness/round-trip tripwire, documented as such.
// The FromBytes path (the one the AAGUID actually takes) is covered by the
// deterministic TestFromBytesRoundTrip below.
package uuidhostile

import (
	"regexp"
	"testing"

	"github.com/google/uuid"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// canonicalRE is the STRICT RFC 4122 canonical textual form: 8-4-4-4-12 lower-
// or upper-case hex with hyphens, nothing else. uuid.Parse is a documented
// SUPERSET of this (it also accepts urn:uuid:, {braces}, and raw 32-hex), so a
// sound differential is one-directional: anything canonicalRE accepts, uuid.Parse
// MUST accept and round-trip. The reverse is NOT asserted (uuid's extra
// leniencies are by design — see the EXPECTED-DIFFERENCE note in the fuzz body).
var canonicalRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// FuzzUUIDParse checks three properties of uuid.Parse on an arbitrary string:
//
//   - no panic / bounded work (fuzzutil.Guard);
//   - round-trip identity: if Parse(s) succeeds, Parse(u.String()) succeeds and
//     yields the SAME 16 bytes — the string the library emits must re-parse to
//     the same value a verifier would compare;
//   - one-directional differential: every string the strict canonical regex
//     accepts, uuid.Parse must also accept (uuid is a superset). A canonical
//     string uuid.Parse REJECTS would be a real defect.
//
// What this does NOT verify: (1) it does not assert uuid.Parse REJECTS
// non-canonical forms — accepting raw-hex / urn / brace forms is documented,
// intended leniency (uuid's own doc says "Parse should not be used to validate
// strings"); (2) it does not fuzz the AAGUID byte path (uuid.FromBytes) that is
// the actually-reachable sink — TestFromBytesRoundTrip covers that
// deterministically; (3) it is self-consistency + a one-way differential vs a
// regex, not a differential against a second UUID implementation.
func FuzzUUIDParse(f *testing.F) {
	f.Add("123e4567-e89b-12d3-a456-426614174000")
	f.Add("urn:uuid:123e4567-e89b-12d3-a456-426614174000")
	f.Add("{123e4567-e89b-12d3-a456-426614174000}")
	f.Add("123e4567e89b12d3a456426614174000") // raw hex
	f.Add("00000000-0000-0000-0000-000000000000")
	f.Add("not-a-uuid")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		var u uuid.UUID
		var err error
		fuzzutil.Guard(t.Fatalf, "uuid.Parse", func() {
			u, err = uuid.Parse(s)
		})

		if canonicalRE.MatchString(s) && err != nil {
			t.Fatalf("strict-canonical string rejected by uuid.Parse: %q (%v)", s, err)
		}

		if err != nil {
			return // not a uuid in any accepted form; nothing to round-trip
		}

		ser := u.String()
		// The library's own output must be strictly canonical.
		if !canonicalRE.MatchString(ser) {
			t.Fatalf("uuid.String() produced a non-canonical form: %q (from %q)", ser, s)
		}
		var u2 uuid.UUID
		fuzzutil.Guard(t.Fatalf, "uuid.Parse(reparse)", func() {
			u2, err = uuid.Parse(ser)
		})
		if err != nil {
			t.Fatalf("round-trip: re-parse of %q (from %q) failed: %v", ser, s, err)
		}
		if u != u2 {
			t.Fatalf("round-trip byte drift: %q -> %v -> %v (ser=%q)", s, u, u2, ser)
		}
	})
}

// FuzzUUIDFromBytes is the actually-reachable path (AAGUID = 16 raw bytes).
// FromBytes must: error iff len != 16; on success, String() round-trips to the
// same 16 bytes. No panic on any length.
func FuzzUUIDFromBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add([]byte("0123456789abcdef")) // 16 bytes
	f.Add([]byte("short"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var u uuid.UUID
		var err error
		fuzzutil.Guard(t.Fatalf, "uuid.FromBytes", func() {
			u, err = uuid.FromBytes(b)
		})
		if len(b) != 16 {
			if err == nil {
				t.Fatalf("FromBytes accepted a %d-byte slice (must require exactly 16)", len(b))
			}
			return
		}
		if err != nil {
			t.Fatalf("FromBytes rejected a 16-byte slice: %v", err)
		}
		var u2 uuid.UUID
		fuzzutil.Guard(t.Fatalf, "uuid.Parse(FromBytes.String)", func() {
			u2, err = uuid.Parse(u.String())
		})
		if err != nil || u != u2 {
			t.Fatalf("FromBytes round-trip drift: bytes=%x str=%q reparse=%v err=%v", b, u.String(), u2, err)
		}
	})
}

// TestFromBytesRoundTrip is a deterministic pin on the AAGUID-shaped path.
func TestFromBytesRoundTrip(t *testing.T) {
	b := []byte{0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00}
	u, err := uuid.FromBytes(b)
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}
	if got := u.String(); got != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("unexpected canonical form: %q", got)
	}
}
