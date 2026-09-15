package core

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzDecodeSecretACLPerms fuzzes DecodeSecretACLPerms, which parses a secret
// ACL's stored permissions column into a grant list. It is the ACL counterpart
// to the PAT scope/CIDR decoders, but with the OPPOSITE safe direction: a PAT
// scope column is a *restriction* (empty = unrestricted, so a corrupt column must
// fail closed to a deny-all sentinel), whereas an ACL column is a *grant* (empty =
// grants nothing, so returning nil on a corrupt column already fails closed). The
// caller only ever widens access when len(perms) > 0 (secret_listing_query.go:573,
// secret_acl.go:227), so the security-critical property here is simply that a
// non-empty column which cannot be parsed must decode to an EMPTY list — it must
// never fabricate a permission the stored bytes did not contain.
//
// This re-derives the expected result independently from raw JSON and asserts:
// (a) Decode never panics/hangs; (b) an empty column ("" exactly — the function
// does not trim) decodes to nil; (c) a non-empty column that fails json.Unmarshal
// decodes to an empty list (no accidental grant); (d) a cleanly-parsing column
// mirrors json.Unmarshal, so every returned permission came from the column.
func FuzzDecodeSecretACLPerms(f *testing.F) {
	seeds := []string{
		"",
		"   ",
		`["secrets.read"]`,
		`["secrets.read","secrets.write"]`,
		`[]`,
		"null",
		`["secrets.read"`,      // truncated -> empty (no grant)
		`secrets.read`,         // bare string -> empty
		`{"perm":"read"}`,      // object, not array -> empty
		`[1,2]`,                // non-string array -> empty
		`["secrets.admin"]`,    // unknown perm (decoder does not validate names)
		`  ["secrets.read"]  `, // surrounding whitespace
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		var got []string
		fuzzutil.Guard(t.Fatalf, "DecodeSecretACLPerms", func() {
			got = DecodeSecretACLPerms(raw)
		})

		if raw == "" {
			if got != nil {
				t.Fatalf("DecodeSecretACLPerms(%q): empty column must decode to nil, got %#v", raw, got)
			}
			return
		}

		var parsed []string
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			// Grant list: an unparseable column must grant NOTHING (empty), never
			// invent a permission. (Fail-closed is empty here, not a sentinel.)
			if len(got) != 0 {
				t.Fatalf("ACL GRANT FABRICATION: unparseable column %q decoded to a non-empty grant %#v; must decode to empty", raw, got)
			}
			return
		}
		if !slices.Equal(got, parsed) {
			t.Fatalf("DecodeSecretACLPerms(%q) = %#v, want %#v (must mirror json.Unmarshal on a cleanly-parsing column)", raw, got, parsed)
		}
	})
}
