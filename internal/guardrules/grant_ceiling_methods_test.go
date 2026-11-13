package guardrules

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// TestGrantCeilingMethods_RealCore: the derivation finds the granting methods the
// transports are known to call (the population tripwire of the two family guards).
func TestGrantCeilingMethods_RealCore(t *testing.T) {
	g := Rollout(t) // repo-wide (it reads internal/core): docs/guard-rollout-contract.md rule 2
	got, err := GrantCeilingMethods(filepath.Join(srcpath.RepoRoot(), "internal", "core"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AssignUserRole", "AssignUserRoleWithExpiry", "AssignRoleToGroup", "AssignMachineRole",
		"AddProjectMember", "SetProjectMemberRole", "InviteMember", "CreateUserWithAssignments", "RestoreProject", "RestoreEnvironment"} {
		if !slices.Contains(got, want) {
			g.Errorf("%s must be derived as a granting method; got %v", want, got)
		}
	}
	for _, never := range []string{"GetProject", "ListSecrets", "RemoveUserRole"} {
		if slices.Contains(got, never) {
			g.Errorf("%s enforces no grant ceiling and must not be listed", never)
		}
	}
}

// TestGrantCeilingMethods_Calibration: a direct call, a one-hop call through an
// unexported receiver method, and nothing else (two hops, an unexported method
// itself, another type's method, a bare function of the same name on another
// receiver) are derived exactly as documented.
func TestGrantCeilingMethods_Calibration(t *testing.T) {
	dir := t.TempDir()
	src := `package core
type KeyorixCore struct{}
type Other struct{}
func (c *KeyorixCore) Direct() error { return c.requireGranterHoldsRolePermissions() }
func (c *KeyorixCore) OneHop() error { return c.helper() }
func (c *KeyorixCore) TwoHops() error { return c.helper2() }
func (c *KeyorixCore) Plain() error { return nil }
func (c *KeyorixCore) helper() error { return c.requireAuthorityForRole() }
func (c *KeyorixCore) helper2() error { return c.helper() }
func (c *KeyorixCore) requireGranterHoldsRolePermissions() error { return nil }
func (c *KeyorixCore) requireAuthorityForRole() error { return nil }
func (o *Other) Direct2() error { return o.requireGranterHoldsRolePermissions() }
func (o *Other) requireGranterHoldsRolePermissions() error { return nil }
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte("package core\nfunc (c *KeyorixCore) FromTest() error { return c.requireAuthorityForRole() }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := GrantCeilingMethods(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Direct", "OneHop"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
