package rules

// PAT column codecs: the JSON encoding of a personal access token's scope
// allowlist and CIDR allowlist, and the fail-closed decoding of what storage
// hands back. Moved from core/pat.go (leaf package, see doc.go); core keeps
// thin wrappers.

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// EncodePATScopes normalises and JSON-encodes a permission allowlist for storage.
// Blank entries are dropped and duplicates removed; an all-blank/empty list
// encodes to "" so the token stays unrestricted (the back-compat default).
func EncodePATScopes(scopes []string) (string, error) {
	cleaned := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		cleaned = append(cleaned, s)
	}
	if len(cleaned) == 0 {
		return "", nil
	}
	b, err := json.Marshal(cleaned)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodePATScopes parses a stored scopes column back into a permission list.
// Only the exact empty column yields nil (unrestricted) — a PAT created without an
// explicit scope allowlist (EncodePATScopes writes "") or a pre-ADR-042 row (NULL,
// read back as "") inherits its owner's full permission set, so nil is the correct
// "no restriction" signal. A whitespace-only column is never written, so it is
// corrupted like any other (PAT-SCOPE-TAILS-1, the DecodePATCIDRs rule from #3840).
//
// A non-empty column that fails JSON parsing is treated as corrupted rather than
// unrestricted: the token was created WITH a scope restriction that is now
// unreadable, so we return a sentinel that patRestrictionFrom interprets as
// "deny everything" rather than accidentally widening a previously-restricted
// token to full owner access (#r124 PAT scope fail-open).
var PATScopeCorrupted = []string{"__corrupted__"}

func DecodePATScopes(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil || !namesSomething(out) {
		// Non-empty but unparseable: fail CLOSED — return a sentinel that no
		// real permission string will ever match, so the PAT is denied everywhere
		// rather than silently granted full owner access on a corrupted row.
		// Same for a column that parses but names nothing (`null`, `[]`, `[""]`):
		// EncodePATScopes writes "" for "no restriction" and never emits those,
		// and an empty list reads as "unrestricted" downstream
		// (TestDecodePAT_NonEmptyColumnThatNamesNothingFailsClosed).
		return PATScopeCorrupted
	}
	return out
}

// namesSomething reports whether a decoded allowlist is one the encoders could
// have written: at least one entry, and no blank entry (both encoders drop
// blanks and encode an empty result as "").
func namesSomething(list []string) bool {
	if len(list) == 0 {
		return false
	}
	for _, s := range list {
		if strings.TrimSpace(s) == "" {
			return false
		}
	}
	return true
}

// EncodePATCIDRs validates and JSON-encodes a CIDR allowlist for storage. Each entry must
// be a parseable CIDR (e.g. "10.0.0.0/8"); a bare IP is accepted and normalised to a /32
// or /128 host route. Blanks are dropped and duplicates removed; an empty result encodes to
// "" (no network restriction, the back-compat default).
func EncodePATCIDRs(cidrs []string) (string, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	cleaned := make([]string, 0, len(cidrs))
	seen := make(map[string]struct{}, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Accept a bare IP by promoting it to a host route, built from the parsed
		// address: "::ffff:1.2.3.4" has To4() != nil, and "::ffff:1.2.3.4/32" is the
		// IPv6 network ::/32 (#4520 sibling).
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					c = ip4.String() + "/32"
				} else {
					c = ip.String() + "/128"
				}
			}
		}
		canon, err := normalizeAllowlistCIDRForStorage(c)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q", c)
		}
		c = canon
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		cleaned = append(cleaned, c)
	}
	if len(cleaned) == 0 {
		return "", nil
	}
	b, err := json.Marshal(cleaned)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// PATCIDRCorrupted is returned by DecodePATCIDRs when the stored column is non-empty
// but fails JSON parsing — the token was created WITH a CIDR allowlist that is now
// unreadable. Returning nil would silently widen the token to global network access
// (#r125 PAT CIDR fail-open). The sentinel contains no valid CIDR, so IPInCIDRs
// will return false for any source IP, blocking all network access until the
// column is repaired or the token is re-issued.
var PATCIDRCorrupted = []string{"<corrupted>"}

// DecodePATCIDRs parses a stored CIDR allowlist back into a slice. Only the exact empty
// column EncodePATCIDRs writes yields nil (no restriction); a whitespace-only column is
// never written, so it is corrupted like any other. A non-empty column that fails JSON
// parsing returns a sentinel that blocks ALL source IPs rather than failing OPEN to
// global network access.
func DecodePATCIDRs(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil || !namesSomething(out) {
		// Non-empty but unparseable: fail CLOSED — return a sentinel that no real
		// CIDR will ever match, so the PAT is denied from all networks rather than
		// silently granted global network access on a corrupted row. Same for a
		// column that parses but names nothing (`null`, `[]`): the middleware's
		// `len(AllowedCIDRs) > 0` reads an empty list as "no network restriction".
		return PATCIDRCorrupted
	}
	return out
}

// ParseAllowlistCIDR parses one STORED CIDR allowlist entry (a PAT or
// machine-token network restriction), for matching. It differs from
// net.ParseCIDR only for an IPv4-mapped address (::ffff:a.b.c.d) written with a
// prefix below 96, which net.ParseCIDR reads as the IPv6 network ::/N.
// Before #4520's sibling fix, EncodePATCIDRs stored exactly "::ffff:a.b.c.d/32"
// for a bare "::ffff:a.b.c.d", so that one shape is read as the IPv4 host it was
// meant to be (a narrowing: the stored ::/32 never matched an IPv4 client). Any
// other mapped prefix below 96 is refused, so a reader skips it (fail closed):
// reading "::ffff:10.0.0.0/8" as 10.0.0.0/8 would WIDEN a stored row that, as
// ::/8, admitted no IPv4 client. Mapped prefixes from 96 up are ordinary IPv6
// networks over the mapped range and are kept. Other IPv6 forms with a dotted
// tail (NAT64 64:ff9b::a.b.c.d, ::a.b.c.d) are not IPv4-mapped and are unchanged.
func ParseAllowlistCIDR(c string) (*net.IPNet, error) {
	ip, n, ones, mapped, err := parseAllowlistEntry(c)
	if err != nil || !mapped || ones >= 96 {
		return n, err
	}
	if ones == 32 {
		return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, nil
	}
	return nil, fmt.Errorf("IPv4-mapped CIDR %q with prefix /%d is ambiguous", strings.TrimSpace(c), ones)
}

// normalizeAllowlistCIDRForStorage is the encoder's form of an entry: an
// IPv4-mapped entry with a prefix of 32 or less is stored as the IPv4 network it
// names (a new entry, so nothing stored is reinterpreted), a mapped prefix from
// 33 to 95 is refused, and every other entry is kept as written.
func normalizeAllowlistCIDRForStorage(c string) (string, error) {
	ip, _, ones, mapped, err := parseAllowlistEntry(c)
	if err != nil {
		return "", err
	}
	if !mapped || ones >= 96 {
		return strings.TrimSpace(c), nil
	}
	if ones <= 32 {
		return (&net.IPNet{IP: ip.To4().Mask(net.CIDRMask(ones, 32)), Mask: net.CIDRMask(ones, 32)}).String(), nil
	}
	return "", fmt.Errorf("IPv4-mapped CIDR %q has a prefix with no IPv4 meaning", strings.TrimSpace(c))
}

// parseAllowlistEntry parses an entry and reports whether its address is an
// IPv4-mapped address written in IPv6 form: the parsed address has an IPv4 form
// (To4) AND the text is IPv6 (holds ':'). Decided from the address, not the
// text alone, so NAT64 or IPv4-compatible dotted tails are not "mapped".
func parseAllowlistEntry(c string) (ip net.IP, n *net.IPNet, ones int, mapped bool, err error) {
	c = strings.TrimSpace(c)
	ip, n, err = net.ParseCIDR(c)
	if err != nil {
		return nil, nil, 0, false, err
	}
	addr, _, _ := strings.Cut(c, "/")
	ones, _ = n.Mask.Size()
	return ip, n, ones, ip.To4() != nil && strings.Contains(addr, ":"), nil
}
