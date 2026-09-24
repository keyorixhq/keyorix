package auditverify

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParseExternalAnchorBundle fuzzes ParseExternalAnchorBundle against
// arbitrary bytes as the `--anchor` bundle JSON (design §3) -- the one
// externally-supplied artifact this package parses that a fuzzer can
// meaningfully mutate as raw bytes, distinct from the SQLite DB file already
// covered by FuzzAuditChainRowDecode in rowdecode_fuzz_test.go. Oracle,
// re-derived independently from ParseExternalAnchorBundle's own doc comment
// (anchor_bundle.go):
//
//  1. Never panics on any byte input, valid JSON or not.
//  2. Returns a non-nil error whenever the input is not valid JSON, OR when
//     it IS valid JSON but head_hash or signature is empty/missing -- the
//     function's own two explicit checks.
//  3. Whenever it returns a non-nil error, the returned bundle is always
//     nil -- buildVerifyAuditOptions (server/admin/audit_verify.go)
//     dereferences the bundle unconditionally on a nil error, so this
//     pairing must hold for every input.
//  4. On success, the returned bundle's HeadHash and Signature are never
//     empty.
func FuzzParseExternalAnchorBundle(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"chained_events":10,"head_id":5,"head_hash":"abc123","key_version":"v1","signature":"sig123"}`),
		[]byte(`{}`),
		[]byte(`{"head_hash":"","signature":"sig"}`),
		[]byte(`{"head_hash":"abc","signature":""}`),
		[]byte(`null`),
		[]byte(``),
		[]byte(`not json at all`),
		[]byte(`{"head_hash":"abc","signature":"sig","anchor_token":"not-base64!!"}`),
		[]byte(`{"head_id":-1}`),
		[]byte(`[]`),
		[]byte(`{"head_hash":123,"signature":"sig"}`), // wrong JSON type for a string field
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var bundle *ExternalAnchorBundle
		var err error
		fuzzutil.Guard(t.Fatalf, "ParseExternalAnchorBundle", func() {
			bundle, err = ParseExternalAnchorBundle(data)
		})

		if err != nil {
			if bundle != nil {
				t.Fatalf("ParseExternalAnchorBundle(%q) returned an error (%v) but a non-nil bundle: %+v", data, err, bundle)
			}
			return
		}
		if bundle == nil {
			t.Fatalf("ParseExternalAnchorBundle(%q) returned nil error and nil bundle", data)
		}
		if bundle.HeadHash == "" {
			t.Fatalf("ParseExternalAnchorBundle(%q) succeeded with an empty HeadHash", data)
		}
		if bundle.Signature == "" {
			t.Fatalf("ParseExternalAnchorBundle(%q) succeeded with an empty Signature", data)
		}
	})
}
