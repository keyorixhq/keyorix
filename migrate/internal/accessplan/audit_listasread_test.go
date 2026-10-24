package accessplan

import (
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// The category literal (not the constant) so the red run against the pre-fix tree fails on the
// assertion, not on compilation.
const wantListAsReadCategory UnmappableCategory = "list-as-read"

// v0.96.x mapped "list" to secrets.read in every stanza, not only list-only ones. A write
// stanza that also lists ([create update list], [delete list]) still maps to a Create today,
// but without secrets.read: the legacy grant could read every value in the environment and
// audit-access must report it although the stanza is not refused today
// (REVIEW-3671-DEEP-1 finding 1).
func TestAuditWidenedGrants_ListInWriteStanza(t *testing.T) {
	cases := []struct {
		caps      []string
		wantRole  string
		wantPerms []string
	}{
		{[]string{"create", "update", "list"}, "vault-migrated-read-write", []string{"secrets.read", "secrets.write"}},
		{[]string{"delete", "list"}, "vault-migrated-delete-read", []string{"secrets.delete", "secrets.read"}},
	}
	for _, c := range cases {
		in := BuildInput{
			Policies: []healthscan.Policy{{Name: "ci-writer", Blocks: []healthscan.PolicyPathBlock{block("secret/data/team-a/prod/*", c.caps...)}}},
			AppRoles: []healthscan.AppRoleRoleConfig{{Mount: "approle", Name: "ci", TokenPolicies: []string{"ci-writer"}}},
		}
		got := AuditWidenedGrants(in, testMapper(t), "")
		if len(got) != 1 {
			t.Fatalf("%v: got %+v, want one finding for the legacy %s grant", c.caps, got, c.wantRole)
		}
		g := got[0]
		if g.MachineName != "vault-approle-ci" || g.RoleName != c.wantRole || !slices.Equal(g.Permissions, c.wantPerms) ||
			g.ProjectID != 1 || g.EnvironmentID != 11 || g.SourceRef != "policy:ci-writer path:secret/data/team-a/prod/*" ||
			g.Category != wantListAsReadCategory || !strings.Contains(g.Reason, "secrets.read") || g.AlsoGrantedByCurrentRules {
			t.Errorf("%v: finding %+v, want %s %v at (1,11) [%s] with a reason naming secrets.read", c.caps, g, c.wantRole, c.wantPerms, wantListAsReadCategory)
		}
	}
}

// The same role at the same scope granted by the current rules (here: a second stanza that
// really reads) is the legitimate grant, not a finding; a write stanza without "list" never
// differed from v0.96.x.
func TestAuditWidenedGrants_ListInWriteStanza_NotAFinding(t *testing.T) {
	for _, blocks := range [][]healthscan.PolicyPathBlock{
		{block("secret/data/team-a/prod/*", "create", "update", "list"), block("secret/data/team-a/prod/*", "read", "create", "update")},
		{block("secret/data/team-a/prod/*", "create", "update")},
		{block("secret/data/team-a/prod/*", "read", "list")},
	} {
		in := BuildInput{
			Policies: []healthscan.Policy{{Name: "p", Blocks: blocks}},
			AppRoles: []healthscan.AppRoleRoleConfig{{Mount: "approle", Name: "r", TokenPolicies: []string{"p"}}},
		}
		if got := AuditWidenedGrants(in, testMapper(t), ""); len(got) != 0 {
			t.Errorf("%v: got %+v, want no finding", blocks, got)
		}
	}
}
