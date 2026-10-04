package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/plan"
)

// TestValueTooLarge_HasItsOwnErrorKind is #2544's report-side guard: a value-too-large item —
// refused in the plan or rejected by the server at apply time — carries
// error_kind=value_too_large in the JSON report and a "toolarge" status in the human output,
// and the run summary calls the class out; a generic error carries neither.
func TestValueTooLarge_HasItsOwnErrorKind(t *testing.T) {
	planned := plan.Item{Entry: plan.Entry{Path: "vault:secret/huge", Name: "huge"}, Outcome: plan.Error, ValueTooLarge: true, Reason: "value too large: vault:secret/huge is 2000000 bytes"}
	generic := plan.Item{Entry: plan.Entry{Path: "vault:secret/x", Name: "x"}, Outcome: plan.Error, Reason: "look up \"x\": HTTP 500"}
	applied := plan.Result{Item: plan.Item{Entry: plan.Entry{Path: "vault:secret/big", Name: "big"}, Outcome: plan.Create}, Ran: true, Error: "value is 70000 bytes...", ValueTooLarge: true}
	appliedGeneric := plan.Result{Item: plan.Item{Entry: plan.Entry{Path: "vault:secret/y", Name: "y"}, Outcome: plan.Create}, Ran: true, Error: "boom"}

	var jsonOut, human bytes.Buffer
	w := New(&jsonOut, &human)
	for _, it := range []plan.Item{planned, generic} {
		if err := w.PlanLine(it); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []plan.Result{applied, appliedGeneric} {
		if err := w.ResultLine(r); err != nil {
			t.Fatal(err)
		}
	}

	var lines []Line
	dec := json.NewDecoder(&jsonOut)
	for dec.More() {
		var l Line
		if err := dec.Decode(&l); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, l)
	}
	wantKind := []string{ErrorKindValueTooLarge, "", ErrorKindValueTooLarge, ""}
	for i, l := range lines {
		if l.ErrorKind != wantKind[i] {
			t.Errorf("line %d (%s): error_kind = %q, want %q", i, l.Source, l.ErrorKind, wantKind[i])
		}
		if l.Outcome != string(plan.Error) {
			t.Errorf("line %d: outcome = %q, want error (the outcome enum is unchanged)", i, l.Outcome)
		}
	}
	humanLines := strings.Split(strings.TrimSpace(human.String()), "\n")
	wantStatus := []string{"toolarge", "error", "toolarge", "error"}
	for i, hl := range humanLines {
		if !strings.HasPrefix(hl, wantStatus[i]) {
			t.Errorf("human line %d = %q, want status %q", i, hl, wantStatus[i])
		}
	}
	if !strings.Contains(humanLines[0], "vault:secret/huge is 2000000 bytes") {
		t.Errorf("dry-run human line does not show the too-large reason: %q", humanLines[0])
	}

	notice := ValueTooLargeNotice([]plan.Item{planned, generic, applied.Item}, []plan.Result{{Item: planned}, applied, appliedGeneric})
	if !strings.HasPrefix(notice, "2 item(s)") {
		t.Errorf("notice = %q, want it to count 2 items", notice)
	}
	if n := ValueTooLargeNotice([]plan.Item{generic}, []plan.Result{appliedGeneric}); n != "" {
		t.Errorf("notice for generic errors only = %q, want empty", n)
	}
}
