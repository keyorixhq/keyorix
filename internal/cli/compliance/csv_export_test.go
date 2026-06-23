package compliance

import "testing"

func TestComplianceCSVCommandsRegistered(t *testing.T) {
	inv, _, err := ComplianceCmd.Find([]string{"inventory"})
	if err != nil || inv.Name() != "inventory" {
		t.Fatalf("inventory command not registered: %v", err)
	}
	for _, f := range []string{"project", "output"} {
		if inv.Flags().Lookup(f) == nil {
			t.Errorf("inventory missing --%s flag", f)
		}
	}

	ctrls, _, err := ComplianceCmd.Find([]string{"controls"})
	if err != nil {
		t.Fatalf("controls command missing: %v", err)
	}
	for _, f := range []string{"csv", "output"} {
		if ctrls.Flags().Lookup(f) == nil {
			t.Errorf("controls missing --%s flag", f)
		}
	}
}
