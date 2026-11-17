package accessreport

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
)

// FuzzAccessReportReadJSON drives ReadJSON with hostile bytes.  ReadJSON is
// the read side of the JSON access-plan report format consumed by
// `migrate apply-access --plan <file>` (ADR-114 §"Apply phase").  The file
// is operator-controlled (and conceivably attacker-controlled if the report
// file is written to a shared location).  Any panic, unexpected error
// swallowing, or divergence between read and write would corrupt the apply
// phase silently.
//
// Oracles — all fatal (the code is in production and must hold today):
//
//	(a) NEVER-PANIC: ReadJSON does not panic on any input, however malformed.
//	(b) DETERMINISM: the same bytes always produce the same number of items
//	    (or the same error).
//	(c) WRITE→READ ROUND-TRIP: for any plan successfully produced by ReadJSON,
//	    WriteJSON followed by ReadJSON must yield the same number of items and
//	    the same Kind/Outcome/SourceRef for each item, in the same order.
//	(d) ITEM BOUNDS: the number of items returned is bounded by the number of
//	    newlines in the input plus one (each line is at most one JSON object),
//	    so the output size cannot exceed the input size.
//	(e) VALID OUTCOMES: every item whose Outcome field is non-empty must be
//	    one of the four recognised values (Create, Skip, Conflict, Unmappable).
//
// What this does NOT verify: that ReadJSON exhausts all items in a valid
// file (the item count oracle is an upper bound, not an exact match), that
// WriteJSON produces valid JSON accepted by external tools, nor that
// apply-access behaves correctly given the parsed plan.
func FuzzAccessReportReadJSON(f *testing.F) {
	// Seeds: valid single-object lines, multi-object, and garbage.
	f.Add(`{"kind":"secret","outcome":"create","source_ref":"kv/db-pass"}` + "\n")
	f.Add(`{"kind":"machine_identity","outcome":"skip","source_ref":"app/svc"}` + "\n")
	f.Add(`{"kind":"role","outcome":"conflict","source_ref":"policy/admin","conflict_reason":"exists"}` + "\n")
	f.Add(`{"kind":"secret","outcome":"unmappable","source_ref":"bad"}` + "\n")
	f.Add(`{"kind":"secret","outcome":"create","source_ref":"a"}` + "\n" +
		`{"kind":"machine_identity","outcome":"skip","source_ref":"b"}` + "\n")
	f.Add("")
	f.Add("\n\n\n")
	f.Add("not json at all\n")
	f.Add(`{}` + "\n")
	f.Add(`{"kind":"","outcome":""}` + "\n")
	f.Add(`{"kind":"secret","outcome":"create","source_ref":"a","provenance_key":"migrate.source-id: x"}` + "\n")
	f.Add(strings.Repeat(`{"kind":"secret","outcome":"create","source_ref":"x"}`+"\n", 50))

	// Known-valid outcomes for oracle (e).
	validOutcomes := map[accessplan.Outcome]bool{
		accessplan.Create:     true,
		accessplan.Skip:       true,
		accessplan.Conflict:   true,
		accessplan.Unmappable: true,
		"":                    true, // empty outcome is allowed (field may be absent in JSON)
	}

	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<20 { // 1 MiB is plenty for a fuzz corpus entry
			return
		}

		// Oracle (a): ReadJSON must not panic.
		var plan1 accessplan.Plan
		var err1 error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ReadJSON panicked on %q: %v", data, r)
				}
			}()
			plan1, err1 = ReadJSON(strings.NewReader(data))
		}()

		// Oracle (b): determinism.
		plan2, err2 := ReadJSON(strings.NewReader(data))
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("ReadJSON non-deterministic error: first=%v second=%v", err1, err2)
		}
		if err1 == nil && len(plan1.Items) != len(plan2.Items) {
			t.Fatalf("ReadJSON non-deterministic count: first=%d second=%d", len(plan1.Items), len(plan2.Items))
		}

		if err1 != nil {
			return // parse failure — no further oracles apply
		}

		// Oracle (d): item count bounded by newline count.
		newlines := strings.Count(data, "\n")
		if len(plan1.Items) > newlines+1 {
			t.Fatalf("ReadJSON: %d items from %d newlines (impossible)", len(plan1.Items), newlines)
		}

		// Oracle (e): known outcomes.
		for i, it := range plan1.Items {
			if !validOutcomes[it.Outcome] {
				t.Fatalf("ReadJSON: item[%d] has unrecognised outcome %q", i, it.Outcome)
			}
		}

		// Oracle (c): write→read round-trip.
		var buf bytes.Buffer
		if err := WriteJSON(&buf, plan1); err != nil {
			t.Fatalf("WriteJSON failed on a plan produced by ReadJSON: %v", err)
		}
		rtPlan, rtErr := ReadJSON(&buf)
		if rtErr != nil {
			t.Fatalf("ReadJSON round-trip failed: WriteJSON output is not re-readable: %v", rtErr)
		}
		if len(rtPlan.Items) != len(plan1.Items) {
			t.Fatalf("ReadJSON round-trip item count: got %d, want %d", len(rtPlan.Items), len(plan1.Items))
		}
		for i, orig := range plan1.Items {
			rt := rtPlan.Items[i]
			if orig.Kind != rt.Kind || orig.Outcome != rt.Outcome || orig.SourceRef != rt.SourceRef {
				t.Fatalf("ReadJSON round-trip item[%d] mismatch: orig={Kind:%q Outcome:%q SourceRef:%q} rt={Kind:%q Outcome:%q SourceRef:%q}",
					i, orig.Kind, orig.Outcome, orig.SourceRef, rt.Kind, rt.Outcome, rt.SourceRef)
			}
		}
	})
}
