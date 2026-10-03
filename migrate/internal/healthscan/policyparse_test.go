package healthscan

import "testing"

func TestParsePolicyHCL_WildcardSudo(t *testing.T) {
	raw := `
path "sys/*" {
  capabilities = ["sudo", "read"]
}
path "secret/data/team-a/*" {
  capabilities = ["read", "list"]
}
`
	blocks := ParsePolicyHCL(raw)
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks, want 2", len(blocks))
	}
	var found bool
	for _, b := range blocks {
		if isWildcardSudoGrant(b) {
			found = true
			if b.Path != "sys/*" {
				t.Errorf("wildcard/sudo grant flagged wrong path %q", b.Path)
			}
		}
	}
	if !found {
		t.Fatal("expected the sys/* sudo grant to be flagged")
	}
}

func TestParsePolicyHCL_CreateUpdateOnStar(t *testing.T) {
	raw := `
path "*" {
  capabilities = ["create", "update"]
}
`
	blocks := ParsePolicyHCL(raw)
	if len(blocks) != 1 || !isWildcardSudoGrant(blocks[0]) {
		t.Fatalf("expected create+update on \"*\" to be flagged, got %+v", blocks)
	}
}

func TestIsWildcardSudoGrant_NarrowPathNotFlagged(t *testing.T) {
	b := PolicyPathBlock{Path: "secret/data/team-a/*", Capabilities: []string{"create", "update", "sudo"}}
	if isWildcardSudoGrant(b) {
		t.Fatal("a narrow, non-sys path should never be flagged regardless of capabilities")
	}
}

func TestIsWildcardSudoGrant_ReadOnlyWildcardNotFlagged(t *testing.T) {
	b := PolicyPathBlock{Path: "sys/*", Capabilities: []string{"read", "list"}}
	if isWildcardSudoGrant(b) {
		t.Fatal("read/list on sys/* is not a write/sudo grant and should not be flagged")
	}
}
