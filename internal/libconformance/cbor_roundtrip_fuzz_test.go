package libconformance

import (
	"math"
	"math/big"
	"reflect"
	"testing"

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
	switch av := a.(type) {
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
		for k, va := range av {
			vb, present := bv[k]
			if !present || !nanAwareEqual(va, vb) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
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
