package healthscan

import (
	"context"
	"strings"
	"testing"
)

func TestCheckTokenAccessorCount(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/auth/token/accessors": `{"data":{"keys":["a1","a2","a3"]}}`,
	})
	res := checkTokenAccessorCount(context.Background(), c)
	if res.Finding == nil || !strings.Contains(res.Finding.Evidence, "3 live token accessors") {
		t.Fatalf("expected a finding naming 3 accessors, got %+v", res)
	}
}

// TestCheckRootTokens_AlwaysNotChecked proves the deliberate structural limitation: this check
// never runs, regardless of what the (unused) fake server would answer — it's a read-only-client
// design boundary, not a permission gap.
func TestCheckRootTokens_AlwaysNotChecked(t *testing.T) {
	res := checkRootTokens(context.Background(), nil)
	if res.NotChecked == nil {
		t.Fatalf("expected NotChecked, got %+v", res)
	}
	if res.NotChecked.PolicyLine != "" {
		t.Errorf("expected no PolicyLine (no policy grant fixes this), got %q", res.NotChecked.PolicyLine)
	}
	if !strings.Contains(res.NotChecked.Reason, "POST") {
		t.Errorf("reason should explain the POST limitation, got %q", res.NotChecked.Reason)
	}
}
