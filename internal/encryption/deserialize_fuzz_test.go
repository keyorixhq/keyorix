package encryption

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzDeserializeEncryptedData fuzzes DeserializeEncryptedData, the JSON envelope
// parser that runs BEFORE any decryption on data read back from storage or a
// remote backend. FuzzDecrypt already covers the full decrypt path; this isolates
// the parse step so a malformed envelope is caught as a robustness failure here
// rather than only surfacing behind the KEK. The bytes are untrusted (a tampered
// or corrupted stored blob), so the parser must never panic and must never hand
// back a half-built struct alongside an error.
//
// Invariants: (a) never panics; (b) on error the returned pointer is nil (no
// partially-populated EncryptedData escapes); (c) on success the pointer is
// non-nil. Callers branch on err, so a non-nil struct with a non-nil error would
// be a partial-success trap.
func FuzzDeserializeEncryptedData(f *testing.F) {
	seeds := [][]byte{
		nil,
		[]byte(``),
		[]byte(`{}`),
		[]byte(`{"data":"","metadata":{}}`),
		[]byte(`{"data":"AQIDBA==","metadata":{}}`),
		[]byte(`{"data":123}`),          // wrong type for data
		[]byte(`{"data":"!!notb64!!"}`), // invalid base64 in a []byte field
		[]byte(`{"metadata":`),          // truncated
		[]byte(`[]`),                    // array, not object
		[]byte(`null`),                  // valid JSON null
		[]byte(`{"data":"AA==","metadata":{"algorithm":"aes-gcm","nonce":"AA=="}}`),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var got *EncryptedData
		var err error
		fuzzutil.Guard(t.Fatalf, "DeserializeEncryptedData", func() {
			got, err = DeserializeEncryptedData(data)
		})
		if err != nil {
			if got != nil {
				t.Fatalf("DeserializeEncryptedData returned an error but a non-nil pointer (partial success) for %q: err=%v", data, err)
			}
			return
		}
		if got == nil {
			t.Fatalf("DeserializeEncryptedData returned nil error but a nil pointer for %q", data)
		}
	})
}
