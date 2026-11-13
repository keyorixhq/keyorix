package authzdiff

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// explain assigns a flagged case to a known waiver ("known-NN"). Each waiver
// names an exact SHAPE — principal kind and every layer's outcome, and an op
// list where needed — so a case that merely resembles a waiver is NOT
// absorbed: it lands in "unexplained" and must be investigated. Waivers carry
// no descriptions here; they are tracked privately.
//
// Every waiver keeps one direction closed: none matches a case where a present
// transport leg (REST or gRPC) allows and the model denies (or has no
// decision). TestExplainNeverWaivesTransportAllowOverModelDeny checks this over
// every combination of the values explain compares against.
//
// The waiver families, what each matches, and what it does not detect:
//
//   - Core allows (known-02, known-03, known-04): the core leg allows, REST
//     denies and gRPC denies or is absent. A transport that allows never
//     matches. known-02 also requires a counterfactual model decision
//     (caseResult.ModelIfActive), so it absorbs only the exact condition it was
//     established on; known-03 is limited to two ops, one target and one
//     principal. Not detected: a core leg that allows while every present
//     transport denies (see below).
//   - Core returns an error the model does not map (known-08, known-09): core
//     returns an untyped error, and the model denies (known-09) or the case is
//     a machine principal on the listed ops (known-08). Not detected: on those
//     shapes, whether REST answers 400/500 instead of a typed deny; and for
//     known-08, a transport that denies or errors where the model allows (an
//     over-denial). A typed core refusal (ErrPermissionDenied) that REST
//     answers 400/500 is never waived: the former known-07 was fixed in the
//     four handlers it matched (TestCeilingRefusalIsForbiddenOnREST).
//
// The plants (plants_test.go) are exactly the shapes these waivers exclude:
// core+REST allow (plant 1), gRPC allows a non-group op (plant 2), REST allows
// what gRPC denies (plant 3), gRPC allows a group op to a principal without
// the op's write permission (plant 4) or without the route group's read
// permission (plant 5).
//
// Dead waivers: a full strict sweep (AUTHZDIFF_STRICT=1, no AUTHZDIFF_OPS)
// fails on any waiver in waiverIDs that matched zero cases, so a waiver whose
// condition was fixed is removed instead of silently absorbing a regression
// of that fix.
//
// What this partition does NOT detect: known-04 accepts "core allows, every
// present transport denies, the model denies". The removal of a core-level
// check (a defence-in-depth regression) is therefore invisible while both
// transports still gate the op; only a transport that stops gating surfaces.
//
// Returns "" for a case with nothing to explain.
func explain(r *caseResult) string {
	if !needsExplaining(r) {
		return ""
	}
	core, rest, grpc := r.Legs[layerCore], r.Legs[layerREST], r.Legs[layerGRPC]
	is := func(lo *legOutcome, o Outcome) bool { return lo != nil && lo.NA == "" && lo.Outcome == o }
	na := func(lo *legOutcome) bool { return lo == nil || lo.NA != "" }
	deniedOrNA := func(lo *legOutcome) bool { return na(lo) || is(lo, Denied) }
	restBadStatus := is(rest, Other) && (rest.Detail == "Internal Server Error" || rest.Detail == "Bad Request")
	pk := r.Principal
	modelDenies := r.Model == Denied || r.Model == ModelNA
	// transportAllowsDenied: a present transport leg allows what the model
	// denies. No waiver may match such a case.
	transportAllowsDenied := modelDenies && (is(rest, Allowed) || is(grpc, Allowed))

	switch {
	case pk == pkSuspended && r.ModelIfActive == Allowed && is(core, Allowed) && is(rest, Denied) && deniedOrNA(grpc):
		return "known-02"

	case (r.Op == "secret.update" || r.Op == "secret.delete") && r.Arg == 1 && r.Target == "A" &&
		pk == pkViewer && is(core, Allowed) && is(rest, Denied) && is(grpc, Denied):
		return "known-03"

	case is(core, Allowed) && is(rest, Denied) && deniedOrNA(grpc) && modelDenies:
		return "known-04"

	case pk == pkMachine && slices.Contains([]string{"secret.acl.grant", "secret.share", "accessrequest.create",
		"secret.certificate", "secret.tags", "secret.description", "secret.move", "secret.copy", "secret.extend.expiring"}, r.Op) &&
		is(core, Other) && core.Detail == "untyped-error" && !transportAllowsDenied:
		return "known-08"

	case is(core, Other) && core.Detail == "untyped-error" && (is(rest, Denied) || restBadStatus) && modelDenies && !transportAllowsDenied:
		return "known-09"
	}
	return "unexplained"
}

// waiverIDs is every bucket explain can return other than "unexplained".
// TestWaiverIDsMatchExplain keeps it in step with explain's source.
var waiverIDs = []string{"known-02", "known-03", "known-04", "known-08", "known-09"}

func needsExplaining(r *caseResult) bool {
	for _, c := range r.Classes {
		if strings.HasPrefix(c, "O1:") || strings.HasPrefix(c, "O2:") ||
			strings.HasPrefix(c, "mapping-gap:") || strings.HasPrefix(c, "other-outside-model:") {
			return true
		}
	}
	return false
}

// TestWaiverIDsMatchExplain: waiverIDs (the dead-waiver check's population)
// lists exactly the buckets explain returns, so a new waiver cannot escape the
// zero-match check by being left out of the list.
func TestWaiverIDsMatchExplain(t *testing.T) {
	src, err := os.ReadFile("partition_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range regexp.MustCompile(`return "(known-\d+)"`).FindAllStringSubmatch(string(src), -1) {
		got = append(got, m[1])
	}
	slices.Sort(got)
	want := slices.Sorted(slices.Values(waiverIDs))
	if !slices.Equal(got, want) {
		t.Errorf("explain returns %v, waiverIDs lists %v", got, want)
	}
}
