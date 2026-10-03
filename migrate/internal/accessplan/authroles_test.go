package accessplan

import (
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

func TestBuildAppRoleItems_MachineIdentityPlusGrant(t *testing.T) {
	roles := []healthscan.AppRoleRoleConfig{{Mount: "auth/approle", Name: "ci-deploy", TokenPolicies: []string{"default", "team-a-ro"}}}
	policies := []healthscan.Policy{{Name: "team-a-ro", Blocks: []healthscan.PolicyPathBlock{block("secret/data/team-a/prod/db", "read")}}}
	items := BuildAppRoleItems(roles, policies, testPolicyMapper(t))

	var identities, grants int
	var machineName string
	for _, it := range items {
		switch it.Kind {
		case KindMachineIdentity:
			identities++
			if it.Outcome != Create || it.ProposedIdentityType != "service" {
				t.Fatalf("machine identity item = %+v, want Create/service", it)
			}
			machineName = it.ProposedName
		case KindMachineRoleGrant:
			grants++
			if it.Outcome != Create || it.ProposedMachineRef != machineName {
				t.Fatalf("grant item = %+v, want Create against machine %q", it, machineName)
			}
		}
	}
	if identities != 1 || grants != 1 {
		t.Fatalf("got %d identities, %d grants, want 1 and 1: %+v", identities, grants, items)
	}
}

func TestBuildAppRoleItems_DefaultPolicyNeverProducesUnmappable(t *testing.T) {
	roles := []healthscan.AppRoleRoleConfig{{Mount: "auth/approle", Name: "ci-deploy", TokenPolicies: []string{"default"}}}
	items := BuildAppRoleItems(roles, nil, testPolicyMapper(t))
	for _, it := range items {
		if it.Outcome == Unmappable {
			t.Fatalf("the built-in \"default\" policy must never surface as an Unmappable row: %+v", it)
		}
	}
}

func TestBuildKubernetesItems_ExactBinding(t *testing.T) {
	roles := []healthscan.KubernetesAuthRoleConfig{{
		Mount: "auth/kubernetes", Name: "prod-deploy",
		BoundServiceAccountNames:      []string{"deployer"},
		BoundServiceAccountNamespaces: []string{"prod"},
		TokenPolicies:                 []string{"team-a-ro"},
	}}
	policies := []healthscan.Policy{{Name: "team-a-ro", Blocks: []healthscan.PolicyPathBlock{block("secret/data/team-a/prod/db", "read")}}}
	items := BuildKubernetesItems(roles, policies, testPolicyMapper(t), "https://k8s.example.com")

	var binding *Item
	for i := range items {
		if items[i].Kind == KindOIDCBinding {
			binding = &items[i]
		}
	}
	if binding == nil || binding.Outcome != Create {
		t.Fatalf("items = %+v, want a Create OIDC binding", items)
	}
	if binding.ProposedOIDCSubject != "system:serviceaccount:prod:deployer" {
		t.Fatalf("subject = %q, want system:serviceaccount:prod:deployer", binding.ProposedOIDCSubject)
	}
}

func TestBuildKubernetesItems_NoIssuer_AllUnmappable(t *testing.T) {
	roles := []healthscan.KubernetesAuthRoleConfig{{
		Mount: "auth/kubernetes", Name: "prod-deploy",
		BoundServiceAccountNames:      []string{"deployer"},
		BoundServiceAccountNamespaces: []string{"prod"},
	}}
	items := BuildKubernetesItems(roles, nil, testPolicyMapper(t), "")
	if len(items) != 1 || items[0].Outcome != Unmappable {
		t.Fatalf("items = %+v, want exactly one Unmappable item when --k8s-issuer is empty", items)
	}
}

func TestBuildKubernetesItems_WildcardSA_Unmappable(t *testing.T) {
	roles := []healthscan.KubernetesAuthRoleConfig{{
		Mount: "auth/kubernetes", Name: "any-sa",
		BoundServiceAccountNames:      []string{"*"},
		BoundServiceAccountNamespaces: []string{"prod"},
	}}
	items := BuildKubernetesItems(roles, nil, testPolicyMapper(t), "https://k8s.example.com")
	if len(items) != 1 || items[0].Outcome != Unmappable || items[0].Category != CategoryWildcardIdentity {
		t.Fatalf("items = %+v, want one Unmappable/wildcard-identity item, nothing created for the wildcard", items)
	}
}

func TestBuildKubernetesItems_MultipleBoundSAs_OneIdentityEach(t *testing.T) {
	roles := []healthscan.KubernetesAuthRoleConfig{{
		Mount: "auth/kubernetes", Name: "multi",
		BoundServiceAccountNames:      []string{"a", "b"},
		BoundServiceAccountNamespaces: []string{"prod"},
		TokenPolicies:                 []string{"team-a-ro"},
	}}
	policies := []healthscan.Policy{{Name: "team-a-ro", Blocks: []healthscan.PolicyPathBlock{block("secret/data/team-a/prod/db", "read")}}}
	items := BuildKubernetesItems(roles, policies, testPolicyMapper(t), "https://k8s.example.com")
	var identities int
	for _, it := range items {
		if it.Kind == KindMachineIdentity {
			identities++
		}
	}
	if identities != 2 {
		t.Fatalf("got %d machine identities, want 2 (one per bound SA, round-down approximation)", identities)
	}
}

func TestBuildUserpassItems_AlwaysUnmappable(t *testing.T) {
	users := []healthscan.UserpassUserConfig{{Mount: "auth/userpass", Username: "alice", TokenPolicies: []string{"team-a-ro"}}}
	items := BuildUserpassItems(users)
	if len(items) != 1 || items[0].Outcome != Unmappable || items[0].Category != CategoryUserpass {
		t.Fatalf("items = %+v, want one Unmappable/userpass item", items)
	}
}
