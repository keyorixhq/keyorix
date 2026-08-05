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

// TestExercisingTestsExist guards registry.go's exercisingTests map, itself
// a hand-maintained list, against naming a test function that has been
// renamed or deleted -- see CheckExercisingTestsExist's doc comment for why
// nothing else in this package would otherwise catch that.
func TestExercisingTestsExist(t *testing.T) {
	if err := CheckExercisingTestsExist(); err != nil {
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

// TestEnforcedSetMatchesADR074 pins the exact 9-operation enforced set
// (schema'd minus outOfScopeRegistry's prometheusMetrics -- see ADR-074's
// "honest enforced baseline" section for which of these 9 carry a real
// structured schema vs. a near-content-free `{type: string, format:
// binary}` one) so a future change to openapi.yaml's schema coverage is
// visible here, not just via a silently growing/shrinking set.
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
