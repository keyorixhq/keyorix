package authzdiff

import (
	"slices"
	"strings"
)

// explain assigns a flagged case to a known waiver ("known-NN"). Each waiver
// names an exact SHAPE — principal kind and every layer's outcome, and an op
// list where needed — so a case that merely resembles a waiver is NOT
// absorbed: it lands in "unexplained" and must be investigated. Waivers carry
// no descriptions here; they are tracked privately.
//
// The waivers that match a shape rather than an op list keep the direction
// that matters closed: one that has the core leg allow needs EVERY present
// transport to deny, so a transport that allows can never match it; one that
// has a layer refuse needs the model to deny as well, so a case allowed
// everywhere can never match it. Two waivers also require a counterfactual
// model decision (caseResult.ModelSansGroupRead / ModelIfActive), so they
// absorb only the exact condition they were established on.
//
// The four plants (plants_test.go) are exactly the shapes these waivers
// exclude: core+REST allow (plant 1), gRPC allows a non-group op (plant 2),
// REST allows what gRPC denies (plant 3), gRPC allows a group op to a
// principal without the op's write permission (plant 4).
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

	switch {
	case slices.Contains([]string{"group.create", "group.update", "group.delete", "group.member.remove", "group.restore",
		"user.create", "user.create.assign", "user.update", "user.delete", "user.reissue.otp",
		"role.create", "role.update", "role.delete"}, r.Op) &&
		is(rest, Denied) && is(grpc, Allowed) && r.Model == Denied && r.ModelSansGroupRead == Allowed:
		return "known-01"

	case pk == pkSuspended && r.ModelIfActive == Allowed && is(core, Allowed) && is(rest, Denied) && deniedOrNA(grpc):
		return "known-02"

	case (r.Op == "secret.update" || r.Op == "secret.delete") && r.Arg == 1 && r.Target == "A" &&
		pk == pkViewer && is(core, Allowed) && is(rest, Denied) && is(grpc, Denied):
		return "known-03"

	case is(core, Allowed) && is(rest, Denied) && deniedOrNA(grpc) && modelDenies:
		return "known-04"

	case r.Op == "machine.token.issue" && pk == pkMachine &&
		is(core, Denied) && is(grpc, Denied) && is(rest, Other) && rest.Detail == "Internal Server Error":
		return "known-05"

	case (r.Op == "member.add" || r.Op == "member.setrole") && pk == pkMachine && r.Model == Allowed &&
		is(core, Denied) && (is(rest, Denied) || restBadStatus):
		return "known-06"

	case is(core, Denied) && core.Detail == "ErrPermissionDenied" && restBadStatus && modelDenies:
		return "known-07"

	case pk == pkMachine && slices.Contains([]string{"secret.acl.grant", "secret.share", "accessrequest.create",
		"secret.certificate", "secret.tags", "secret.description", "secret.move", "secret.copy", "secret.extend.expiring"}, r.Op) &&
		is(core, Other) && core.Detail == "untyped-error":
		return "known-08"

	case is(core, Other) && core.Detail == "untyped-error" && (is(rest, Denied) || restBadStatus) && modelDenies:
		return "known-09"
	}
	return "unexplained"
}

func needsExplaining(r *caseResult) bool {
	for _, c := range r.Classes {
		if strings.HasPrefix(c, "O1:") || strings.HasPrefix(c, "O2:") ||
			strings.HasPrefix(c, "mapping-gap:") || strings.HasPrefix(c, "other-outside-model:") {
			return true
		}
	}
	return false
}
