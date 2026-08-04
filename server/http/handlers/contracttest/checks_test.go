package contracttest

import "testing"

// TestOpenAPIRegistryPartition is the load-bearing check from ADR-074: every
// operation in openapi.yaml must land in exactly one of enforced,
// pending-with-reason, or out-of-scope-with-reason. Fails the build in
// either direction -- see CheckPartition.
func TestOpenAPIRegistryPartition(t *testing.T) {
	if err := CheckPartition(); err != nil {
		t.Fatal(err)
	}
}

// TestSpecLoadsAndValidates guards the harness's own precondition: if
// openapi.yaml stops parsing or fails OpenAPI validation, every test using
// AssertOpenAPIResponse would fail with the same underlying cause. This
// isolates that failure mode to one clearly-named test.
func TestSpecLoadsAndValidates(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}
	if spec == nil || router == nil {
		t.Fatal("contracttest: loadSpec succeeded but left spec or router nil")
	}
}

// TestEnforcedSetMatchesADR074 pins the exact enforced set Phase 1 decided
// on (ADR-074, "The honest enforced baseline is ~7, not 10") so a future
// change to openapi.yaml's schema coverage is visible here, not just via a
// silently growing/shrinking set.
func TestEnforcedSetMatchesADR074(t *testing.T) {
	want := map[string]bool{
		"authGetSetupToken":             true,
		"authLogin":                     true,
		"authRefresh":                   true,
		"healthCheck":                   true,
		"listSecretACLs":                true,
		"systemInit":                    true,
		"exportSecretAccessLog":         true,
		"exportAuditLogsCSV":            true,
		"exportAccessReviewCampaignCSV": true,
	}

	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}
	got := enforcedOperationIDs()

	for opID := range want {
		if !got[opID] {
			t.Errorf("expected %s to be enforced, it is not", opID)
		}
	}
	for opID := range got {
		if !want[opID] {
			t.Errorf("%s is enforced but not in ADR-074's expected set -- "+
				"update this test if that's an intentional new schema", opID)
		}
	}
}
