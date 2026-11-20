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
		n, err := ParseAllowlistCIDR(c)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q", c)
		}
		if isIPv4MappedText(c) {
			c = n.String() // store the network it means, not the ambiguous text
		}
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

// ParseAllowlistCIDR parses one CIDR allowlist entry (a PAT or machine-token
// network restriction). It differs from net.ParseCIDR for an IPv4-mapped address
// written in IPv6 form: "::ffff:1.2.3.4/32" is, to net.ParseCIDR, the IPv6
// network ::/32 (it contains ::1 and not 1.2.3.4). Before #4520's sibling fix,
// EncodePATCIDRs stored exactly that text for a bare "::ffff:1.2.3.4", so a
// mapped address with a prefix of 32 or less is read as the IPv4 network it
// was meant to be (1.2.3.4/32). A mapped address with a prefix from 96 up is an
// ordinary IPv6 network over the mapped range and is kept; a prefix from 33 to
// 95 has no IPv4 meaning and is refused (a reader skips it: fail closed).
func ParseAllowlistCIDR(c string) (*net.IPNet, error) {
	c = strings.TrimSpace(c)
	ip, n, err := net.ParseCIDR(c)
	if err != nil {
		return nil, err
	}
	if !isIPv4MappedText(c) {
		return n, nil
	}
	ones, _ := n.Mask.Size()
	switch {
	case ones >= 96:
		return n, nil
	case ones <= 32:
		return &net.IPNet{IP: ip.To4().Mask(net.CIDRMask(ones, 32)), Mask: net.CIDRMask(ones, 32)}, nil
	default:
		return nil, fmt.Errorf("IPv4-mapped CIDR %q has a prefix with no IPv4 meaning", c)
	}
}

// isIPv4MappedText reports whether the address part of a CIDR entry is an IPv4
// address written in IPv6 form (it holds both ':' and '.').
func isIPv4MappedText(c string) bool {
	addr, _, _ := strings.Cut(strings.TrimSpace(c), "/")
	return strings.Contains(addr, ":") && strings.Contains(addr, ".")
}
