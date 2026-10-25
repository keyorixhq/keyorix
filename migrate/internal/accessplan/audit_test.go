package accessplan

import (
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// TestLegacyV096_MatchesShippedBehaviour pins legacyV096Grants to what v0.96.3 actually did:
// these are the expectations v0.96.3's own pathmapper_test.go / policies_test.go asserted
// (TestPathMapper_ExactProjectAndEnvironment, _KVv1Mount_NoInfixStripped,
// _Override_LongestPrefixWins, TestBuildPolicyItems_ExactReadGrant) plus the RD-SMT-SPIKE-1
// shapes. If this drifts, audit-access stops naming the grants those releases created.
func TestLegacyV096_MatchesShippedBehaviour(t *testing.T) {
	cases := []struct {
		overrides []string
		path      string
		caps      []string
		wantRole  string
		project   int
		env       int
	}{
		{nil, "secret/data/team-a/prod/db-password", []string{"read"}, "vault-migrated-read", 1, 11},
		{nil, "secret/data/team-a/prod/db", []string{"read", "list"}, "vault-migrated-read", 1, 11},
		{nil, "kv1/team-b/prod/x", []string{"read"}, "vault-migrated-read", 2, 20},
		{nil, "secret/data/team-a/*", []string{"read"}, "vault-migrated-read", 1, 0},
		{[]string{"secret/data/team-a=2:20", "secret/data/team-a/dev=1:10"}, "secret/data/team-a/dev/x", []string{"read"}, "vault-migrated-read", 1, 10},
		{[]string{"secret/data/team-a=2:20", "secret/data/team-a/dev=1:10"}, "secret/data/team-a/staging/x", []string{"read"}, "vault-migrated-read", 2, 20},
		{[]string{"secret/data=1:10"}, "secret/data/payments/*", []string{"read", "list"}, "vault-migrated-read", 1, 10},
		{[]string{"secret/data=1:10"}, "secret/data/mobile-app/*", []string{"read", "list", "create", "update"}, "vault-migrated-read-write", 1, 10},
		{nil, "secret/metadata/team-a/prod/*", []string{"list"}, "vault-migrated-read", 1, 11},
	}
	for _, c := range cases {
		got := legacyV096Grants([]healthscan.Policy{{Name: "p", Blocks: []healthscan.PolicyPathBlock{block(c.path, c.caps...)}}}, testMapper(t, c.overrides...))
		if len(got) != 1 || got[0].role != c.wantRole || got[0].project != c.project || got[0].env != c.env {
			t.Errorf("%v %s %v: legacy grants %+v, want %s at (%d,%d)", c.overrides, c.path, c.caps, got, c.wantRole, c.project, c.env)
		}
	}
	// v0.96.3 refused these too: sudo, templated, a deny overlapping the allow, a bare mount.
	for _, b := range [][]healthscan.PolicyPathBlock{
		{block("secret/data/team-a/prod/*", "sudo")},
		{block("secret/data/team-a/{{identity.entity.id}}/*", "read")},
		{block("secret/data/team-a/prod/*", "read"), block("secret/data/team-a/prod/x", "deny")},
		{block("secret/data/*", "read")},
	} {
		if got := legacyV096Grants([]healthscan.Policy{{Name: "p", Blocks: b}}, testMapper(t)); len(got) != 0 {
			t.Errorf("%v: legacy grants %+v, want none", b, got)
		}
	}
}

// demoBuildInput is scripts/demo/vault-migration-demo.sh's seed: its policies, AppRole roles
// and Kubernetes role, with --path-map secret/data=<from-vault>:<production> (ids 2 and 6, as
// in a fresh demo install).
func demoBuildInput() (BuildInput, []ProjectRef, map[int][]EnvironmentRef, []KVMountInfo, []string) {
	pol := func(name string, blocks ...healthscan.PolicyPathBlock) healthscan.Policy {
		return healthscan.Policy{Name: name, Blocks: blocks}
	}
	in := BuildInput{
		Policies: []healthscan.Policy{
			pol("payments-readonly", block("secret/data/payments/*", "read", "list")),
			pol("mobile-readwrite", block("secret/data/mobile-app/*", "read", "list", "create", "update")),
			pol("payments-deny-db", block("secret/data/payments/*", "read", "list"), block("secret/data/payments/db", "deny")),
			pol("all-secrets-readonly", block("secret/data/*", "read")),
		},
		AppRoles: []healthscan.AppRoleRoleConfig{
			{Mount: "approle", Name: "ci-payments-reader", TokenPolicies: []string{"payments-readonly"}},
			{Mount: "approle", Name: "finance-batch-job", TokenPolicies: []string{"payments-readonly", "payments-deny-db"}},
			{Mount: "approle", Name: "ci-audit-reader", TokenPolicies: []string{"all-secrets-readonly"}},
		},
		KubernetesRoles: []healthscan.KubernetesAuthRoleConfig{
			{Mount: "kubernetes", Name: "deployer", BoundServiceAccountNames: []string{"deployer"}, BoundServiceAccountNamespaces: []string{"prod"}, TokenPolicies: []string{"mobile-readwrite"}},
		},
	}
	projects := []ProjectRef{{ID: 1, Name: "default"}, {ID: 2, Name: "from-vault"}}
	envs := map[int][]EnvironmentRef{2: {{ID: 4, Name: "development"}, {ID: 5, Name: "staging"}, {ID: 6, Name: "production"}}}
	mounts := []KVMountInfo{{Path: "secret/", KVVersion: 2}, {Path: "kv1-legacy/", KVVersion: 1}}
	return in, projects, envs, mounts, []string{"secret/data=2:6"}
}

// On the migration demo's own data, the audit names exactly the two grants the SMT spike found
// wider than Vault, and nothing for the identities whose grants were correct (ci-audit-reader)
// or never created (finance-batch-job: deny overlap).
func TestAuditWidenedGrants_DemoData(t *testing.T) {
	in, projects, envs, mounts, pathMap := demoBuildInput()
	m, err := NewPathMapper(projects, envs, mounts, pathMap)
	if err != nil {
		t.Fatal(err)
	}
	got := AuditWidenedGrants(in, m, "https://k8s.demo.local")
	want := []WidenedGrant{
		{MachineName: "vault-approle-ci-payments-reader", ProjectID: 2, EnvironmentID: 6, RoleName: "vault-migrated-read",
			Permissions: []string{"secrets.read"}, SourceRef: "policy:payments-readonly path:secret/data/payments/*", Category: CategoryNarrowerThanScope},
		{MachineName: "vault-k8s-deployer-prod-deployer", ProjectID: 2, EnvironmentID: 6, RoleName: "vault-migrated-read-write",
			Permissions: []string{"secrets.read", "secrets.write"}, SourceRef: "policy:mobile-readwrite path:secret/data/mobile-app/*", Category: CategoryNarrowerThanScope},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d:\n%v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.MachineName != w.MachineName || g.ProjectID != w.ProjectID || g.EnvironmentID != w.EnvironmentID || g.RoleName != w.RoleName ||
			!slices.Equal(g.Permissions, w.Permissions) || g.SourceRef != w.SourceRef || g.Category != w.Category || g.Reason == "" || g.AlsoGrantedByCurrentRules {
			t.Errorf("finding %d = %+v\nwant %+v (with a reason)", i, g, w)
		}
	}
	// Without --k8s-issuer v0.96.x created no Kubernetes identity, so there is nothing to audit.
	if got := AuditWidenedGrants(in, m, ""); len(got) != 1 || got[0].MachineName != "vault-approle-ci-payments-reader" {
		t.Fatalf("no issuer: got %v, want only the AppRole finding", got)
	}
}

// A role whose narrow stanza widened to an environment that a correct stanza of the same role
// still grants is not a finding (the grant is legitimate); one widened to a second environment
// is, flagged AlsoGrantedByCurrentRules because the API cannot tell the two apart by name.
func TestAuditWidenedGrants_SharedRoleName(t *testing.T) {
	m := testMapper(t)
	in := BuildInput{
		Policies: []healthscan.Policy{{Name: "p", Blocks: []healthscan.PolicyPathBlock{
			block("secret/data/team-a/prod/*", "read"),
			block("secret/data/team-a/prod/db", "read"),
			block("secret/data/team-a/dev/db", "read"),
		}}},
		AppRoles: []healthscan.AppRoleRoleConfig{{Mount: "approle", Name: "r", TokenPolicies: []string{"p"}}},
	}
	got := AuditWidenedGrants(in, m, "")
	if len(got) != 1 || got[0].EnvironmentID != 10 || !got[0].AlsoGrantedByCurrentRules || got[0].SourceRef != "policy:p path:secret/data/team-a/dev/db" {
		t.Fatalf("got %+v, want one dev (env 10) finding flagged AlsoGrantedByCurrentRules", got)
	}
}
