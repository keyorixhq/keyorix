package authzdiff

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// legOut builds a present leg outcome for the explain() tests.
func legOut(o Outcome, detail string) *legOutcome { return &legOutcome{Outcome: o, Detail: detail} }

// TestExplainNeverWaivesTransportAllowOverModelDeny: no waiver absorbs a case
// where a present transport leg allows and the model denies (or has no
// decision). Such a case must stay "unexplained".
//
// The named rows are hand-built shapes next to each waiver. The exhaustive
// part then crosses every op, detail and target literal explain compares
// against (read from its source, so a new literal is covered automatically)
// with every principal, leg outcome and model decision, and fails on any
// forbidden case that gets a waiver. It also requires every waiver in
// waiverIDs to be returned somewhere in that space, so the enumeration cannot
// pass by never reaching a waiver.
func TestExplainNeverWaivesTransportAllowOverModelDeny(t *testing.T) {
	o2 := []string{"O2:allowed-but-model-denies:grpc"}
	rows := []struct {
		name string
		r    caseResult
	}{
		{"known-07 shape, gRPC allows", caseResult{
			caseKey: caseKey{Op: "secret.update", Principal: pkViewer, Target: "A"}, Model: Denied, Classes: o2,
			Legs: map[layer]*legOutcome{layerCore: legOut(Denied, "ErrPermissionDenied"), layerREST: legOut(Other, "Internal Server Error"), layerGRPC: legOut(Allowed, "")},
		}},
		{"known-08 shape, REST and gRPC allow", caseResult{
			caseKey: caseKey{Op: "secret.share", Principal: pkMachine, Target: "A"}, Model: Denied, Classes: o2,
			Legs: map[layer]*legOutcome{layerCore: legOut(Other, "untyped-error"), layerREST: legOut(Allowed, ""), layerGRPC: legOut(Allowed, "")},
		}},
		{"known-08 shape, REST allows, gRPC absent", caseResult{
			caseKey: caseKey{Op: "secret.tags", Principal: pkMachine, Target: "A"}, Model: Denied, Classes: o2,
			Legs: map[layer]*legOutcome{layerCore: legOut(Other, "untyped-error"), layerREST: legOut(Allowed, ""), layerGRPC: {NA: "no gRPC method"}},
		}},
		{"known-08 shape, gRPC allows, no model decision", caseResult{
			caseKey: caseKey{Op: "secret.move", Principal: pkMachine, Target: "A"}, Model: ModelNA, Classes: o2,
			Legs: map[layer]*legOutcome{layerCore: legOut(Other, "untyped-error"), layerREST: legOut(Denied, ""), layerGRPC: legOut(Allowed, "")},
		}},
		{"known-09 shape, gRPC allows", caseResult{
			caseKey: caseKey{Op: "secret.update", Principal: pkViewer, Target: "A"}, Model: Denied, Classes: o2,
			Legs: map[layer]*legOutcome{layerCore: legOut(Other, "untyped-error"), layerREST: legOut(Denied, ""), layerGRPC: legOut(Allowed, "")},
		}},
		{"known-04 shape, gRPC allows", caseResult{
			caseKey: caseKey{Op: "secret.update", Principal: pkViewer, Target: "A"}, Model: Denied, Classes: o2,
			Legs: map[layer]*legOutcome{layerCore: legOut(Allowed, ""), layerREST: legOut(Denied, ""), layerGRPC: legOut(Allowed, "")},
		}},
	}
	for _, row := range rows {
		if got := explain(&row.r); got != "unexplained" {
			t.Errorf("%s: explain = %q, want \"unexplained\"", row.name, got)
		}
	}

	ops, details := explainLiterals(t)
	ops = append(ops, "unlisted.op")
	details = append(details, "", "other-detail")
	var legOpts []*legOutcome
	legOpts = append(legOpts, &legOutcome{NA: "absent"}, legOut(Allowed, ""))
	for _, d := range details {
		legOpts = append(legOpts, legOut(Denied, d), legOut(Other, d))
	}

	allows := func(lo *legOutcome) bool { return lo.NA == "" && lo.Outcome == Allowed }
	reached := map[string]bool{}
	var forbidden, bad int
	r := &caseResult{Classes: o2, Legs: map[layer]*legOutcome{}}
	for _, op := range ops {
		for _, pk := range allPrincipalKinds {
			for _, target := range []string{"A", "B"} {
				for _, arg := range []byte{0, 1} {
					for _, model := range []Outcome{Allowed, Denied, ModelNA} {
						for _, ifActive := range []Outcome{Allowed, Denied} {
							for _, core := range legOpts {
								for _, rest := range legOpts {
									for _, grpc := range legOpts {
										r.Op, r.Principal, r.Target, r.Arg = op, pk, target, arg
										r.Model, r.ModelIfActive = model, ifActive
										r.Legs[layerCore], r.Legs[layerREST], r.Legs[layerGRPC] = core, rest, grpc
										got := explain(r)
										reached[got] = true
										if model == Allowed || (!allows(rest) && !allows(grpc)) {
											continue
										}
										forbidden++
										if got != "unexplained" {
											bad++
											if bad <= 10 {
												t.Errorf("explain = %q for a transport allow over a model deny: %s", got, r.line())
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if bad > 10 {
		t.Errorf("... %d such cases in total", bad)
	}
	if forbidden == 0 {
		t.Fatal("enumeration produced no case with a transport allow over a model deny")
	}
	for _, id := range waiverIDs {
		if !reached[id] {
			t.Errorf("enumeration never reaches waiver %s: extend the literal or outcome space", id)
		}
	}
	t.Logf("checked %d cases with a transport allow over a model deny", forbidden)
}

// explainLiterals returns the string literals in explain's source, split into
// op names (dotted lower-case) and everything else that is not a bucket name.
func explainLiterals(t *testing.T) (ops, details []string) {
	t.Helper()
	src, err := os.ReadFile("partition_test.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "\nfunc explain(")
	if start < 0 {
		t.Fatal("func explain not found in partition_test.go")
	}
	body = body[start:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatal("end of func explain not found")
	}
	body = body[:end]
	opName := regexp.MustCompile(`^[a-z]+(\.[a-z]+)+$`)
	for _, m := range regexp.MustCompile(`"([^"\\]*)"`).FindAllStringSubmatch(body, -1) {
		s := m[1]
		switch {
		case strings.HasPrefix(s, "known-") || s == "unexplained" || s == "":
		case opName.MatchString(s):
			if !slices.Contains(ops, s) {
				ops = append(ops, s)
			}
		default:
			if !slices.Contains(details, s) {
				details = append(details, s)
			}
		}
	}
	if len(ops) == 0 || len(details) == 0 {
		t.Fatalf("no literals parsed from explain (ops=%v details=%v)", ops, details)
	}
	return ops, details
}
