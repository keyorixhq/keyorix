package healthscan

import (
	"regexp"
	"strings"
)

// policyPathBlock is one `path "..." { capabilities = [...] }` stanza extracted from a raw ACL
// policy's HCL text.
type policyPathBlock struct {
	Path         string
	Capabilities []string
}

// pathBlockRE matches a Vault ACL policy's `path "<glob>" { ... }` stanza and captures its body.
// This is a deliberately tolerant, hand-rolled scanner — not a full HCL parser — matching this
// module's existing "small hand-rolled client, no SDK dependency" precedent (vaultsource's own
// doc comment) rather than adding an HCL parsing library for one narrow extraction task. It is
// good enough to find wildcard/sudo grants (checkWildcardSudoPolicies' whole job) and is proven
// against Vault's own documented example policies in policyparse_test.go — it is NOT a validator
// and does not need to be: a policy Vault itself rejected as malformed never reaches this scan.
// Known limitation, stated rather than silently accepted: the body match is non-greedy up to the
// FIRST "}", so a path stanza containing a nested brace (e.g. allowed_parameters = {...}) before
// its own closing brace can truncate early and miss a "capabilities" line that comes after it —
// acceptable for a "find the obviously dangerous grants" scan, not for anything claiming
// completeness.
var pathBlockRE = regexp.MustCompile(`(?s)path\s+"([^"]+)"\s*\{(.*?)\}`)
var capabilitiesRE = regexp.MustCompile(`capabilities\s*=\s*\[([^\]]*)\]`)
var capabilityItemRE = regexp.MustCompile(`"([^"]+)"`)

func parsePolicyHCL(raw string) []policyPathBlock {
	var blocks []policyPathBlock
	for _, m := range pathBlockRE.FindAllStringSubmatch(raw, -1) {
		path, body := m[1], m[2]
		var caps []string
		if cm := capabilitiesRE.FindStringSubmatch(body); cm != nil {
			for _, cim := range capabilityItemRE.FindAllStringSubmatch(cm[1], -1) {
				caps = append(caps, cim[1])
			}
		}
		blocks = append(blocks, policyPathBlock{Path: path, Capabilities: caps})
	}
	return blocks
}

// isWildcardSudoGrant reports whether b grants "sudo" (which alone bypasses all other capability
// restrictions on the path) or both "create" and "update" (full write) on a path this scan
// treats as dangerously broad: exactly "*", or any path starting "sys/*" — the two glob shapes
// SESSION-G2 item (g) names explicitly.
func isWildcardSudoGrant(b policyPathBlock) bool {
	broad := b.Path == "*" || strings.HasPrefix(b.Path, "sys/*")
	if !broad {
		return false
	}
	hasSudo, hasCreate, hasUpdate := false, false, false
	for _, capability := range b.Capabilities {
		switch capability {
		case "sudo":
			hasSudo = true
		case "create":
			hasCreate = true
		case "update":
			hasUpdate = true
		}
	}
	return hasSudo || (hasCreate && hasUpdate)
}
