package identity

import "testing"

// TestFoldWidthMappingAllowlistedOneDirectionOnly: the allowlisted width-compat-mapping
// key covers only Keyorix-distinct / RFC-same. The opposite direction (Keyorix-same /
// RFC-distinct) is an account-collision shape and must never share the allowlisted key.
func TestFoldWidthMappingAllowlistedOneDirectionOnly(t *testing.T) {
	allow := foldDiffAllow()
	// Both strings fold equal under NFKC+fold but not under NFC: the width mechanism.
	const a, b = "ＡＤＭＩＮ", "admin"
	if k := classifyFoldEqDiff(a, b, false); k != "width-compat-mapping" || !allow.allows(k) {
		t.Fatalf("Keyorix-distinct direction must keep the allowlisted key, got %q", k)
	}
	if k := classifyFoldEqDiff(a, b, true); k != "width-compat-mapping-keyorix-same" || allow.allows(k) {
		t.Fatalf("Keyorix-same direction must use a non-allowlisted key, got %q", k)
	}
}
