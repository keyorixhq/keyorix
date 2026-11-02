package azurekms

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// testKEK32 is a KEK-sized (32-byte) stand-in, valid as an HMAC key in every Go
// FIPS mode.
const testKEK32 = "0123456789abcdef0123456789abcdef"

// FIPS-TAILS-2 item 3, red/green: Decrypt keyed the version MAC with the unwrap
// result before checking its length. A fake Key Vault returning a short result
// for a pinned, MAC'd envelope made crypto/hmac panic under
// GODEBUG=fips140=only, and in default mode got the integrity-check error
// instead of the wrong-length one. It is now refused with the provider's
// wrong-length error in both modes, before any HMAC.
func TestDecrypt_ShortUnwrapResultRefusedBeforeMAC(t *testing.T) {
	for _, n := range []int{0, 1, 13, 31, 33} {
		short := strings.Repeat("k", n)
		wrapped, err := json.Marshal(fakeWrapped{Version: "v1", Plaintext: []byte(short)})
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(envelope{Version: "v1", Ciphertext: wrapped, MAC: []byte{0x01}})
		if err != nil {
			t.Fatal(err)
		}
		c := newTestClient(&fakeKeys{currentVersion: "v1"}, "")

		var pt []byte
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("len %d: Decrypt panicked: %v", n, r)
				}
			}()
			pt, err = c.Decrypt(context.Background(), append([]byte(envelopeMagic), body...))
		}()
		if err == nil || !strings.Contains(err.Error(), "KEK must be 32 bytes") {
			t.Fatalf("len %d: want the wrong-length error, got pt=%q err=%v", n, pt, err)
		}
		if pt != nil {
			t.Fatalf("len %d: no key material may be returned with the error", n)
		}
	}
}
