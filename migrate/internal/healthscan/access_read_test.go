package healthscan

import (
	"context"
	"testing"
)

func TestListPolicies_ParsesEveryPolicy(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/policies/acl":         `{"data":{"keys":["default","ro"]}}`,
		"/v1/sys/policies/acl/default": `{"data":{"name":"default","policy":"path \"secret/data/self\" { capabilities = [\"read\"] }"}}`,
		"/v1/sys/policies/acl/ro":      `{"data":{"name":"ro","policy":"path \"secret/data/team-a/*\" { capabilities = [\"read\",\"list\"] }"}}`,
	})
	policies, unreadable, status, err := ListPolicies(context.Background(), c)
	if err != nil || status != StatusOK {
		t.Fatalf("ListPolicies() status=%d err=%v", status, err)
	}
	if len(unreadable) != 0 {
		t.Fatalf("unreadable = %v, want none", unreadable)
	}
	if len(policies) != 2 {
		t.Fatalf("got %d policies, want 2: %+v", len(policies), policies)
	}
	var ro *Policy
	for i := range policies {
		if policies[i].Name == "ro" {
			ro = &policies[i]
		}
	}
	if ro == nil {
		t.Fatal("policy \"ro\" not found")
	}
	if len(ro.Blocks) != 1 || ro.Blocks[0].Path != "secret/data/team-a/*" {
		t.Fatalf("ro.Blocks = %+v, want one block for secret/data/team-a/*", ro.Blocks)
	}
}

func TestListPolicies_DeniedList(t *testing.T) {
	c := fakeServerStatus(t, "/v1/sys/policies/acl", StatusForbidden, "")
	_, _, status, err := ListPolicies(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != StatusForbidden {
		t.Fatalf("status = %d, want %d", status, StatusForbidden)
	}
}

func TestListAuthMounts(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/auth": `{"data":{"token/":{"type":"token"},"approle/":{"type":"approle"},"k8s/":{"type":"kubernetes"}}}`,
	})
	mounts, status, err := ListAuthMounts(context.Background(), c)
	if err != nil || status != StatusOK {
		t.Fatalf("ListAuthMounts() status=%d err=%v", status, err)
	}
	if len(mounts) != 3 {
		t.Fatalf("got %d mounts, want 3: %+v", len(mounts), mounts)
	}
}

func TestListAppRoleRoleConfigs_ReadsTokenPolicies(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/auth":                    `{"data":{"approle/":{"type":"approle"}}}`,
		"/v1/auth/approle/role":           `{"data":{"keys":["ci-deploy"]}}`,
		"/v1/auth/approle/role/ci-deploy": `{"data":{"token_policies":["team-a-rw"],"token_ttl":3600,"secret_id_ttl":0,"secret_id_num_uses":0}}`,
	})
	configs, unreadable, truncated, status, err := ListAppRoleRoleConfigs(context.Background(), c)
	if err != nil || status != StatusOK {
		t.Fatalf("ListAppRoleRoleConfigs() status=%d err=%v", status, err)
	}
	if truncated || len(unreadable) != 0 {
		t.Fatalf("truncated=%v unreadable=%v, want neither", truncated, unreadable)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1: %+v", len(configs), configs)
	}
	got := configs[0]
	if got.Name != "ci-deploy" || len(got.TokenPolicies) != 1 || got.TokenPolicies[0] != "team-a-rw" {
		t.Fatalf("config = %+v, want name ci-deploy with token_policies [team-a-rw]", got)
	}
	if got.SecretIDTTL != 0 || got.SecretIDNumUses != 0 {
		t.Fatalf("config = %+v, want secret_id_ttl/num_uses carried through as 0", got)
	}
}

func TestListAppRoleRoleConfigs_NoAppRoleMount(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/auth": `{"data":{"token/":{"type":"token"}}}`})
	configs, _, _, status, err := ListAppRoleRoleConfigs(context.Background(), c)
	if err != nil || status != StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if len(configs) != 0 {
		t.Fatalf("got %d configs, want 0", len(configs))
	}
}

func TestListKubernetesAuthRoleConfigs_ReadsBoundServiceAccounts(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/auth":             `{"data":{"kubernetes/":{"type":"kubernetes"}}}`,
		"/v1/auth/kubernetes/role": `{"data":{"keys":["prod-deploy"]}}`,
		"/v1/auth/kubernetes/role/prod-deploy": `{"data":{
			"bound_service_account_names":["deployer"],
			"bound_service_account_namespaces":["prod"],
			"token_policies":["team-a-rw"],
			"token_ttl":1800
		}}`,
	})
	configs, unreadable, truncated, status, err := ListKubernetesAuthRoleConfigs(context.Background(), c)
	if err != nil || status != StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if truncated || len(unreadable) != 0 {
		t.Fatalf("truncated=%v unreadable=%v, want neither", truncated, unreadable)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1: %+v", len(configs), configs)
	}
	got := configs[0]
	if len(got.BoundServiceAccountNames) != 1 || got.BoundServiceAccountNames[0] != "deployer" {
		t.Fatalf("BoundServiceAccountNames = %v, want [deployer]", got.BoundServiceAccountNames)
	}
	if len(got.BoundServiceAccountNamespaces) != 1 || got.BoundServiceAccountNamespaces[0] != "prod" {
		t.Fatalf("BoundServiceAccountNamespaces = %v, want [prod]", got.BoundServiceAccountNamespaces)
	}
}

func TestListKubernetesAuthRoleConfigs_WildcardBinding(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/auth":             `{"data":{"kubernetes/":{"type":"kubernetes"}}}`,
		"/v1/auth/kubernetes/role": `{"data":{"keys":["any-sa"]}}`,
		"/v1/auth/kubernetes/role/any-sa": `{"data":{
			"bound_service_account_names":["*"],
			"bound_service_account_namespaces":["prod"],
			"token_policies":["team-a-rw"]
		}}`,
	})
	configs, _, _, status, err := ListKubernetesAuthRoleConfigs(context.Background(), c)
	if err != nil || status != StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if len(configs) != 1 || configs[0].BoundServiceAccountNames[0] != "*" {
		t.Fatalf("configs = %+v, want the wildcard carried through unmodified for accessplan to classify", configs)
	}
}

func TestListUserpassUsers_ReadsTokenPolicies(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/auth":                  `{"data":{"userpass/":{"type":"userpass"}}}`,
		"/v1/auth/userpass/users":       `{"data":{"keys":["alice"]}}`,
		"/v1/auth/userpass/users/alice": `{"data":{"token_policies":["team-a-rw"]}}`,
	})
	configs, unreadable, truncated, status, err := ListUserpassUsers(context.Background(), c)
	if err != nil || status != StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if truncated || len(unreadable) != 0 {
		t.Fatalf("truncated=%v unreadable=%v, want neither", truncated, unreadable)
	}
	if len(configs) != 1 || configs[0].Username != "alice" {
		t.Fatalf("configs = %+v, want one user \"alice\"", configs)
	}
}
