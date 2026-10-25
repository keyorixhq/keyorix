package accessplan

import (
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// v0.96.x mapped a default-convention policy on one KV mount to its environment even when
// another mount's paths route there too. audit-access reports such a grant (current rules:
// cross-mount-scope); with nothing on the other mount it is not a finding.
func TestAuditWidenedGrants_CrossMount(t *testing.T) {
	in := BuildInput{
		Policies: []healthscan.Policy{{Name: "team-a-prod-ro", Blocks: []healthscan.PolicyPathBlock{block("secret/data/team-a/prod/*", "read")}}},
		AppRoles: []healthscan.AppRoleRoleConfig{{Mount: "approle", Name: "r", TokenPolicies: []string{"team-a-prod-ro"}}},
	}
	m := crossMountMapper(t, kvTree(map[string][]string{"kv1/": {"team-a/prod"}}))
	got := AuditWidenedGrants(in, m, "")
	if len(got) != 1 || got[0].Category != CategoryCrossMountScope || got[0].EnvironmentID != 11 {
		t.Fatalf("got %+v, want one cross-mount-scope finding on team-a/prod (env 11)", got)
	}
	m = crossMountMapper(t, kvTree(map[string][]string{"kv1/": {"team-a/dev"}}))
	if got := AuditWidenedGrants(in, m, ""); len(got) != 0 {
		t.Fatalf("got %+v, want none: kv1 holds nothing in team-a/prod", got)
	}
}
