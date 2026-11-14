package libconformance

import (
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// FuzzCBORRoundTrip transfers the round-trip bug class (decode→encode→decode must
// be equal, OR the difference must be a NAMED class) to fxamacker/cbor/v2.
//
// The property asserted is value-level re-encode idempotence: once the first
// decode has NORMALIZED the input (collapsed indefinite lengths, dropped duplicate
// map keys, picked a canonical integer/float representation), re-encoding and
// re-decoding must reproduce the SAME value. v1 := decode(data); b := encode(v1);
// v2 := decode(b); require equal(v1, v2). This is the same stable-round-trip shape
// as FuzzManifestJSONRoundTripIsStable / FuzzEtreeRoundTripIdempotent. It is robust
// to Go map-iteration order because we compare decoded VALUES, not bytes.
//
// EXPECTED-DIFFERENCE classes (handled here, documented in the committed
// EXPECTED-DIFFERENCE.md table). Only a NEW class — one not named below — fails:
//   - NaN: float NaN != NaN under reflect.DeepEqual. Treated equal by nanAwareEqual.
//   - big.Int vs int64: a tag-2/3 bignum that fits in int64 may decode to a
//     different Go type on the second pass. nanAwareEqual compares big.Int /
//     int64 / uint64 by numeric value.
//   - The FIRST decode is the normalizer; indefinite-length, duplicate-map-key
//     (default DupMapKeyQuiet keeps the last value) and non-canonical integer
//     encodings are already collapsed in v1, so the property is stated on v1↔v2,
//     not data↔v1 (which is NOT round-trip-stable by design and intentionally
//     not asserted).
//   - E11 (datetime tag): CBOR tag 0 (RFC3339) / tag 1 (epoch) decode to a Go
//     time.Time, but the default EncMode re-encodes time.Time as an UNTAGGED Unix
//     number — so v1 is time.Time while v2 is an int/float of the same instant,
//     and the tag is dropped. FOUND BY FUZZING on input c130 (tag1(int -17)); this
//     is a documented fxamacker behavior, benign for Keyorix (go-webauthn uses no
//     datetime tags), and the reason an EXPECTED-DIFFERENCE table exists at all —
//     the harness surfaced a real disagreement class the author had not listed.
//     nanAwareEqual treats a time.Time and the Unix-number of the same instant as
//     equal; the reproducer is kept as a regression seed in testdata/fuzz.
//
// What this does NOT verify:
//   - It does NOT assert data↔v1 fidelity (that CBOR preserves the exact input
//     encoding). CBOR has many encodings for one value; Keyorix never relies on
//     byte-exact CBOR round-trip, so that is out of scope and would produce only
//     EXPECTED differences.
//   - It only exercises values that survive the FIRST decode. Inputs the default
//     DecMode rejects (over-deep, over-count, malformed) are skipped — their
//     safety is FuzzCBORBoundedWork's job, not this target's.
//   - It uses the default EncMode. A canonical/CTAP2 EncMode could expose ordering
//     differences this value-level comparison is blind to by construction.
func FuzzCBORRoundTrip(f *testing.F) {
	f.Add([]byte{0xa0})                               // empty map
	f.Add([]byte{0x80})                               // empty array
	f.Add([]byte{0x9f, 0x01, 0x02, 0x03, 0xff})       // indefinite array → definite
	f.Add([]byte{0xa2, 0x01, 0x02, 0x01, 0x03})       // duplicate map key 1
	f.Add([]byte{0xc2, 0x49, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}) // bignum 2^64
	f.Add([]byte{0xf9, 0x7e, 0x00})                   // NaN
	f.Add([]byte{0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0}) // +Inf
	f.Add([]byte{0xc1, 0x30})                         // E11: tag1(epoch) int -17 (fuzz-found datetime-tag class)
	f.Add([]byte{0xc0, 0x74, 0x32, 0x30, 0x32, 0x36, 0x2d, 0x30, 0x31, 0x2d, 0x30, 0x31, 0x54, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x5a}) // E11: tag0 RFC3339
	f.Add([]byte{0xc8, 0xfb, 0x7f, 0xf0, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30}) // E1: NaN inside tag 8 (fuzz-found)
	f.Add([]byte{0x63, 0x66, 0x6f, 0x6f})             // text "foo"
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var v1 any
		if err := cbor.Unmarshal(data, &v1); err != nil {
			return // not valid CBOR under the default caps; nothing to round-trip
		}
		b, err := cbor.Marshal(v1)
		if err != nil {
			// A value we just decoded must be re-encodable. If not, that is a
			// genuine asymmetry — surface it (it is not in the named table).
			t.Fatalf("ROUND-TRIP: decoded value is not re-encodable: %v (input %x)", err, data)
		}
		var v2 any
		if err := cbor.Unmarshal(b, &v2); err != nil {
			t.Fatalf("ROUND-TRIP: re-encoded bytes do not decode: %v (input %x, reenc %x)", err, data, b)
		}
		if !nanAwareEqual(v1, v2) {
			t.Fatalf("ROUND-TRIP: decode→encode→decode changed value (NEW class, not in EXPECTED-DIFFERENCE table)\n in:   %x\n v1:   %#v\n reenc: %x\n v2:   %#v", data, v1, b, v2)
		}
	})
}

// nanAwareEqual compares two decoded CBOR values, treating the EXPECTED-DIFFERENCE
// classes (NaN==NaN, numeric big.Int/int64/uint64 equality) as equal.
func nanAwareEqual(a, b any) bool {
	// Numeric cross-type equality (bignum may re-type across the round-trip).
	if an, aok := asBigInt(a); aok {
		if bn, bok := asBigInt(b); bok {
			return an.Cmp(bn) == 0
		}
		return false
	}
	// E11 datetime-tag class: tag-0/1 decode to time.Time, re-encode drops the
	// tag to an untagged Unix number. Compare by instant in either direction.
	if at, ok := a.(time.Time); ok {
		return sameInstant(at, b)
	}
	if bt, ok := b.(time.Time); ok {
		return sameInstant(bt, a)
	}
	switch av := a.(type) {
	case cbor.Tag:
		// Unknown tags decode to cbor.Tag{Number, Content}; the comparison must
		// recurse into Content so a NaN/bignum/nested EXPECTED-DIFFERENCE inside a
		// tag is handled like one at top level (found by fuzzing: c8fb... =
		// tag8(NaN), whose Content NaN tripped a bare reflect.DeepEqual).
		bv, ok := b.(cbor.Tag)
		if !ok {
			return false
		}
		return av.Number == bv.Number && nanAwareEqual(av.Content, bv.Content)
	case float64:
		bv, ok := b.(float64)
		if !ok {
			return false
		}
		if math.IsNaN(av) && math.IsNaN(bv) {
			return true
		}
		return av == bv
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !nanAwareEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[any]any:
		bv, ok := b.(map[any]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		// Set-match rather than direct key lookup: a KEY can itself be normalized
		// by the round-trip (a tag-1 datetime key becomes an int key — E11; a NaN
		// or bignum key re-types — E1/E2), so a Go `==` map lookup would miss it.
		// Pair each av entry with an unused bv entry whose key AND value are
		// nanAwareEqual. O(n²), fine for fuzz-sized maps. (Found by fuzzing:
		// a {tag1(-17): -17} map whose key re-encoded to the untagged int -17.)
		usedB := make([]bool, 0, len(bv))
		bEntries := make([]struct{ k, v any }, 0, len(bv))
		for k, v := range bv {
			bEntries = append(bEntries, struct{ k, v any }{k, v})
			usedB = append(usedB, false)
		}
		for ka, va := range av {
			matched := false
			for i, be := range bEntries {
				if usedB[i] {
					continue
				}
				if nanAwareEqual(ka, be.k) && nanAwareEqual(va, be.v) {
					usedB[i] = true
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
	}
}

// sameInstant implements the E11 datetime-tag EXPECTED-DIFFERENCE: a time.Time
// (from a tag-0/1 decode) equals the untagged Unix number the default EncMode
// produces on re-encode, when they denote the same second. The default EncMode
// encodes time.Time as integer Unix seconds (TimeUnix), so the counterpart is an
// int64/uint64; a float (fractional seconds) is also accepted by truncation.
func sameInstant(tt time.Time, other any) bool {
	switch o := other.(type) {
	case nil:
		// fxamacker encodes a ZERO time.Time as CBOR null, so it re-decodes to
		// nil. A tag-1 epoch of NaN/Inf also decodes to the zero time. Both ends
		// denote "no valid instant" (found by fuzzing: c1faffff3030 = tag1(NaN)).
		return tt.IsZero()
	case time.Time:
		return tt.Equal(o)
	case float64:
		return int64(o) == tt.Unix()
	default:
		if n, ok := asBigInt(other); ok {
			return n.Cmp(big.NewInt(tt.Unix())) == 0
		}
		return false
	}
}

// asBigInt coerces the integer-ish decoded CBOR types to *big.Int for numeric
// comparison. fxamacker decodes small ints to int64/uint64 and large bignums to
// big.Int, so a value that crosses that boundary between the two passes compares
// equal by magnitude rather than by Go type.
func asBigInt(v any) (*big.Int, bool) {
	switch x := v.(type) {
	case int64:
		return big.NewInt(x), true
	case uint64:
		return new(big.Int).SetUint64(x), true
	case big.Int:
		return &x, true
	case *big.Int:
		return x, true
	default:
		return nil, false
	}
}
