package oapiruntime

import (
	"testing"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

// MINIMAL REPRODUCER (issue #4797): upstream (*types.Email).UnmarshalJSON
// stores the unquoted local part of mail.ParseAddress(s).Address, and
// MarshalJSON re-parses that stored value, which fails for any quoted local
// part. A server-supplied "a b"@example.com is therefore accepted by the CLI
// but cannot be re-serialized, and "a@b"@x.com is stored as a@b@x.com.
//
// This test pins the upstream behaviour. It FAILS when upstream fixes the
// defect: then remove emailNeedsQuotedLocalPart from the Email oracle (so the
// round-trip is enforced without a tolerance) and delete this file.
func TestUpstreamEmailQuotedLocalPartDoesNotRoundTrip(t *testing.T) {
	cases := []struct {
		in     string
		stored string
	}{
		{`"\"a b\"@example.com"`, `a b@example.com`},
		{`"\"a@b\"@x.com"`, `a@b@x.com`},
	}
	for _, c := range cases {
		var e openapi_types.Email
		if err := e.UnmarshalJSON([]byte(c.in)); err != nil {
			t.Fatalf("UnmarshalJSON(%s): upstream behaviour changed, now rejects: %v", c.in, err)
		}
		if string(e) != c.stored {
			t.Fatalf("UnmarshalJSON(%s) stored %q, pinned %q: upstream behaviour changed", c.in, string(e), c.stored)
		}
		if _, err := e.MarshalJSON(); err == nil {
			t.Fatalf("MarshalJSON(%q) now succeeds: upstream fixed #4797, drop the tolerance and this test", string(e))
		}
		if !emailNeedsQuotedLocalPart(e) {
			t.Fatalf("emailNeedsQuotedLocalPart(%q) = false: the tolerance no longer matches the pinned class", string(e))
		}
	}
}

// The same root cause where MarshalJSON succeeds: a quoted local part with
// leading space is stored as " 0@0", which marshals as "0@0" (the space is
// trimmed on re-parse), so the round-trip changes the value. Found by the
// fuzzer in the first 20s run.
func TestUpstreamEmailQuotedSpaceLocalPartChangesValue(t *testing.T) {
	var e1 openapi_types.Email
	if err := e1.UnmarshalJSON([]byte(`"\" 0\"@0"`)); err != nil {
		t.Fatalf("upstream behaviour changed, now rejects: %v", err)
	}
	if string(e1) != " 0@0" {
		t.Fatalf("stored %q, pinned %q: upstream behaviour changed", string(e1), " 0@0")
	}
	b, err := e1.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON(%q): upstream behaviour changed: %v", string(e1), err)
	}
	var e2 openapi_types.Email
	if err := e2.UnmarshalJSON(b); err != nil {
		t.Fatalf("re-UnmarshalJSON(%s): %v", b, err)
	}
	if e1 == e2 {
		t.Fatalf("round-trip now preserves %q: upstream fixed #4797, drop the tolerance and this test", string(e1))
	}
	if !emailNeedsQuotedLocalPart(e1) {
		t.Fatalf("emailNeedsQuotedLocalPart(%q) = false: the tolerance no longer matches the pinned class", string(e1))
	}
}
