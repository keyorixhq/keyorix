package rules

import (
	"slices"
	"testing"
)

// TestDecodePAT_NonEmptyColumnThatNamesNothingFailsClosed closes the gap the
// #r124/#r125 fail-closed rule left open (REVIEW-COVERAGE-1). The rule is "an
// empty column means unrestricted; a NON-EMPTY column the token was created with
// must never widen it". EncodePATScopes/EncodePATCIDRs encode "no restriction"
// as "" and never emit `null` or `[]`, so a stored `null` or `[]` is the same
// corrupted/hand-edited/foreign-restored row as unparseable JSON -- but it
// parsed cleanly to an empty list, and patRestrictionFrom /
// server/middleware's `len(AllowedCIDRs) > 0` read an empty list as "no
// restriction": a scoped, IP-pinned PAT became an owner-equivalent token from
// any address.
func TestDecodePAT_NonEmptyColumnThatNamesNothingFailsClosed(t *testing.T) {
	for _, raw := range []string{"null", "[]", " null ", "[ ]", "\t[]\n", `[null]`, `[""]`, `["  "]`} {
		t.Run(raw, func(t *testing.T) {
			if got := DecodePATScopes(raw); !slices.Equal(got, PATScopeCorrupted) {
				t.Errorf("DecodePATScopes(%q) = %#v, want the PATScopeCorrupted sentinel (deny everything)", raw, got)
			}
			if got := DecodePATCIDRs(raw); !slices.Equal(got, PATCIDRCorrupted) {
				t.Errorf("DecodePATCIDRs(%q) = %#v, want the PATCIDRCorrupted sentinel (block every source IP)", raw, got)
			}
		})
	}
}

// The encoder never produces a column the decoder now treats as corrupted:
// every real allowlist round-trips, and "no restriction" stays "".
func TestPATCodec_RoundTripUnchanged(t *testing.T) {
	for _, scopes := range [][]string{nil, {}, {" ", ""}, {"secrets.read"}, {"secrets.read", "audit.read", "secrets.read"}} {
		enc, err := EncodePATScopes(scopes)
		if err != nil {
			t.Fatal(err)
		}
		dec := DecodePATScopes(enc)
		if enc == "" {
			if dec != nil {
				t.Errorf("scopes %q: empty encoding decoded to %#v, want nil", scopes, dec)
			}
			continue
		}
		if slices.Equal(dec, PATScopeCorrupted) {
			t.Errorf("scopes %q: encoder output %q decodes as corrupted", scopes, enc)
		}
	}
	for _, cidrs := range [][]string{nil, {""}, {"10.0.0.1"}, {"10.0.0.0/8", "2001:db8::/32"}} {
		enc, err := EncodePATCIDRs(cidrs)
		if err != nil {
			t.Fatal(err)
		}
		dec := DecodePATCIDRs(enc)
		if enc == "" {
			if dec != nil {
				t.Errorf("cidrs %q: empty encoding decoded to %#v, want nil", cidrs, dec)
			}
			continue
		}
		if slices.Equal(dec, PATCIDRCorrupted) {
			t.Errorf("cidrs %q: encoder output %q decodes as corrupted", cidrs, enc)
		}
	}
}

// TestDecodePATCIDRs_WhitespaceOnlyColumnFailsClosed: only the exact "" the encoder
// writes is "no restriction". A whitespace-only column is never written by
// EncodePATCIDRs, so it is the same corrupted or hand-edited row as `null` and must
// block every source IP, not drop the pin (REVIEW-3840-DEEP-1).
func TestDecodePATCIDRs_WhitespaceOnlyColumnFailsClosed(t *testing.T) {
	if got := DecodePATCIDRs(""); got != nil {
		t.Fatalf("DecodePATCIDRs(\"\") = %#v, want nil (no restriction)", got)
	}
	for _, raw := range []string{" ", "  ", "\n", "\t", " \r\n "} {
		if got := DecodePATCIDRs(raw); !slices.Equal(got, PATCIDRCorrupted) {
			t.Errorf("DecodePATCIDRs(%q) = %#v, want the PATCIDRCorrupted sentinel (block every source IP)", raw, got)
		}
	}
}

// TestDecodePATScopes_UnscopedByDesignVsWhitespaceCorrupted pins the line between
// the two "nothing in the column" cases. The legitimate one is the exact empty
// column: CreateOwnPAT stores EncodePATScopes' "" for "no allowlist" and the
// ADR-042 migration (createPersonalAccessTokens) adds the column with no default,
// so a pre-ADR-042 row reads back NULL -> "". Both mean "inherit the owner",
// by design. A whitespace-only column is never written by EncodePATScopes, so it
// is a corrupted or hand-edited row like `null`/`[]`, and decoding it as unscoped
// turned it into an owner-equivalent token (PAT-SCOPE-TAILS-1; the CIDR codec
// closed the same gap in #3840). It must decode to the deny-everything sentinel.
func TestDecodePATScopes_UnscopedByDesignVsWhitespaceCorrupted(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"exact_empty_column_is_unscoped_by_design", "", nil},
		{"whitespace_only_space_fails_closed", " ", PATScopeCorrupted},
		{"whitespace_only_spaces_fails_closed", "   ", PATScopeCorrupted},
		{"whitespace_only_newline_fails_closed", "\n", PATScopeCorrupted},
		{"whitespace_only_tab_fails_closed", "\t", PATScopeCorrupted},
		{"whitespace_only_mixed_fails_closed", " \r\n ", PATScopeCorrupted},
		{"literal_null_fails_closed", "null", PATScopeCorrupted},
		{"literal_empty_array_fails_closed", "[]", PATScopeCorrupted},
		{"padded_real_allowlist_still_parses", ` ["secrets.read"] `, []string{"secrets.read"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodePATScopes(tc.raw)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("DecodePATScopes(%q) = %#v, want nil (unscoped by design)", tc.raw, got)
				}
				return
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("DecodePATScopes(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}
