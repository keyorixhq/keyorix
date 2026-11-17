package accessreport

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
)

func samplePlan() accessplan.Plan {
	return accessplan.Plan{Items: []accessplan.Item{
		{Kind: accessplan.KindRole, Outcome: accessplan.Create, SourceRef: "policy:p path:x",
			ProposedName: "vault-migrated-read", ProposedProjectID: 1, ProposedEnvironmentID: 0,
			ProposedPermissions: []string{"secrets.read"}},
		{Kind: accessplan.KindRole, Outcome: accessplan.Unmappable, SourceRef: "policy:god path:*",
			Category: accessplan.CategorySudo, Reason: "grants sudo"},
		{Kind: accessplan.KindRole, Outcome: accessplan.Conflict, SourceRef: "policy:p2 path:y",
			ProposedName: "vault-migrated-write", ConflictReason: "hand-made role with this name"},
	}}
}

func TestWriteJSON_NeverEmptyAndNoCredentialLikeField(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, samplePlan()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	out := buf.String()
	if out == "" {
		t.Fatal("expected non-empty JSON output")
	}
	for _, forbidden := range []string{"token", "secret_id", "role_id", "password"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Fatalf("JSON report contains forbidden substring %q:\n%s", forbidden, out)
		}
	}
}

func TestWriteMarkdown_ContainsEveryOutcome(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, samplePlan(), "https://vault.example.com"); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"vault-migrated-read", "grants sudo", "hand-made role with this name", "global (every environment)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown report missing %q:\n%s", want, out)
		}
	}
}

func TestWriteHTML_EscapesAndWrites(t *testing.T) {
	plan := accessplan.Plan{Items: []accessplan.Item{
		{Kind: accessplan.KindRole, Outcome: accessplan.Unmappable, SourceRef: `policy:<script>alert(1)</script>`,
			Category: accessplan.CategorySudo, Reason: "x"},
	}}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, plan, "https://vault.example.com"); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("HTML report did not escape a source ref — XSS risk")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("expected the escaped form in output:\n%s", out)
	}
}

// TestReadJSON_RejectsUnrecognisedOutcome is the red/green proof for the LH-FUZZ-1 finding:
// encoding/json matches "outCome" to the Outcome field case-insensitively, and an unrecognised
// value like "0" used to be accepted silently — Apply's switch then drops it as if it were
// Skip/Conflict/Unmappable, instead of surfacing the corrupted line as an error.
func TestReadJSON_RejectsUnrecognisedOutcome(t *testing.T) {
	_, err := ReadJSON(strings.NewReader(`{"outCome":"0"}` + "\n"))
	if err == nil {
		t.Fatal("ReadJSON accepted an unrecognised outcome value without error")
	}
	if !strings.Contains(err.Error(), "line 1") || !strings.Contains(err.Error(), `"0"`) {
		t.Fatalf("error should name the line and the bad value, got: %v", err)
	}
}

// TestReadJSON_AcceptsValidOutcomesAndEmpty guards against isValidOutcome rejecting any of
// accessplan's real Outcome values, or the empty string (a Line whose "outcome" key is absent).
func TestReadJSON_AcceptsValidOutcomesAndEmpty(t *testing.T) {
	for _, o := range []accessplan.Outcome{accessplan.Create, accessplan.Skip, accessplan.Conflict, accessplan.Unmappable, ""} {
		if !isValidOutcome(o) {
			t.Fatalf("isValidOutcome(%q) = false, want true", o)
		}
	}
}
