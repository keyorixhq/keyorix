package accessreport

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
)

func impliedPlan() accessplan.Plan {
	return accessplan.Plan{Items: []accessplan.Item{
		{Kind: accessplan.KindRole, Outcome: accessplan.Create, SourceRef: "policy:n4-readonly path:secret/data/n4-team/*",
			SourcePolicy: "n4-readonly", ProposedName: "vault-migrated-read", ProposedProjectID: 1, ProposedEnvironmentID: 11,
			ProposedPermissions: []string{"secrets.read"},
			ImpliedAccess:       []string{accessplan.ImpliedListNames, accessplan.ImpliedReadVersionMetadata}},
		{Kind: accessplan.KindRole, Outcome: accessplan.Create, SourceRef: "policy:team-a-ro path:secret/data/team-a/prod/*",
			SourcePolicy: "team-a-ro", ProposedName: "vault-migrated-read", ProposedProjectID: 2, ProposedEnvironmentID: 21,
			ProposedPermissions: []string{"secrets.read"},
			CrossMountEvidence:  []string{"kv1/team-a/prod/: absent", "secret/team-a/prod/: policy mount"}},
	}}
}

// The JSON plan carries the implied access per item (machine-readable report) and the
// cross-mount evidence apply-access re-checks; both survive the plan file round trip.
func TestWriteJSON_ImpliedAccessAndCrossMountEvidenceRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, impliedPlan()); err != nil {
		t.Fatal(err)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(buf.String(), "\n", 2)[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["source_policy"] != "n4-readonly" || first["implied_access"] == nil {
		t.Fatalf("first JSON line %v lacks source_policy/implied_access", first)
	}
	back, err := ReadJSON(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Items) != 2 || !slices.Equal(back.Items[1].CrossMountEvidence, impliedPlan().Items[1].CrossMountEvidence) ||
		!slices.Equal(back.Items[0].ImpliedAccess, impliedPlan().Items[0].ImpliedAccess) {
		t.Fatalf("round trip lost fields: %+v", back.Items)
	}
}

func TestWriteMarkdownAndHTML_ListImpliedAccessPolicies(t *testing.T) {
	var md, page bytes.Buffer
	if err := WriteMarkdown(&md, impliedPlan(), "https://vault.example"); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(&page, impliedPlan(), "https://vault.example"); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"markdown": md.String(), "html": page.String()} {
		if !strings.Contains(out, "n4-readonly") || !strings.Contains(out, accessplan.ImpliedListNames) || !strings.Contains(out, accessplan.ImpliedReadVersionMetadata) {
			t.Fatalf("%s report does not list n4-readonly's implied access:\n%s", name, out)
		}
		if strings.Contains(out, "team-a-ro: ") {
			t.Fatalf("%s report lists team-a-ro, which implies nothing:\n%s", name, out)
		}
	}
}
