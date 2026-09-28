package healthscan

import (
	"context"
	"testing"
)

func TestCheckPolicySprawl(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/policies/acl": `{"data":{"keys":["default","admin"]}}`,
	})
	res := checkPolicySprawl(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info for 2 policies, got %+v", res)
	}
}

func TestCheckWildcardSudoPolicies_FlagsOffender(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/policies/acl":          `{"data":{"keys":["default","god-mode"]}}`,
		"/v1/sys/policies/acl/default":  `{"data":{"name":"default","policy":"path \"secret/data/self\" { capabilities = [\"read\"] }"}}`,
		"/v1/sys/policies/acl/god-mode": `{"data":{"name":"god-mode","policy":"path \"*\" { capabilities = [\"sudo\"] }"}}`,
	})
	res := checkWildcardSudoPolicies(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityHigh {
		t.Fatalf("expected high severity for a sudo-on-* policy, got %+v", res)
	}
}

func TestCheckWildcardSudoPolicies_NoneFlagged(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/policies/acl":         `{"data":{"keys":["default"]}}`,
		"/v1/sys/policies/acl/default": `{"data":{"name":"default","policy":"path \"secret/data/self\" { capabilities = [\"read\"] }"}}`,
	})
	res := checkWildcardSudoPolicies(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info when nothing is flagged, got %+v", res)
	}
}
