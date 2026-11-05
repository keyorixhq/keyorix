package authzdiff

import (
	"slices"
	"strings"
)

// explain partitions a flagged case into the known finding buckets of
// REPORT.md. Each rule names the exact SHAPE the finding was established on —
// principal kind and every layer's outcome, and an op list wherever the
// mechanism is op-specific — so a case that merely resembles a finding is NOT
// absorbed: it lands in "unexplained" and must be investigated.
//
// Phase 4 generalized four rules from an op list to a shape, because the
// generated principals and the new ops showed the same mechanism on more ops.
// Each generalization keeps the direction that matters closed:
//   - D2 (core looser than the transports) needs EVERY present transport to
//     deny, so a transport-level bypass can never match it;
//   - M1/M3 (refusal typing/mapping) need a refusal on some layer and the
//     model to deny, so an allowed-everywhere bypass can never match them;
//   - D1 stays limited to group ops, to REST-deny/gRPC-allow, and to a
//     principal whose only missing permission is users.read; D5 to a
//     suspended principal the model allows once active.
//
// The plants (plants_test.go) are exactly the shapes these rules exclude:
// core+REST allow (plant 1), gRPC allows a non-group op (plant 2), REST allows
// what gRPC denies (plant 3), gRPC allows a group op to a principal without
// the write permission (plant 4).
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
	// D1: gRPC group mutations do not require users.read (REST's route group does).
	// Only for a principal that holds everything else the op needs: the model
	// denies, and the model with users.read dropped allows. A principal missing
	// the write permission itself (users.write / roles.assign) is a real gRPC
	// bypass and stays unexplained (plant grpc-group-guard-removed).
	case slices.Contains([]string{"group.create", "group.update", "group.delete", "group.member.remove", "group.restore"}, r.Op) &&
		is(rest, Denied) && is(grpc, Allowed) && r.Model == Denied && r.ModelSansUsersRead == Allowed:
		return "D1"

	// D5: core does not check account state; both transports reject the
	// suspended account's credential (401 / Unauthenticated). Only where the
	// account state is the sole reason: the model allows the same principal
	// once active.
	case pk == pkSuspended && r.ModelIfActive == Allowed && is(core, Allowed) && is(rest, Denied) && deniedOrNA(grpc):
		return "D5"

	// (No D7 rule: the restricted-PAT ungated-write refusal, ADR-042 PAT-GUARD-3,
	// is REST-middleware-only, but every op it covers is "core refusal = none"
	// (intended difference ID-2), so the core leg never takes part and the case
	// never disagrees. A rule that nothing can reach is not kept.)

	// D4: ownership is a grant in core, unreachable through the transports.
	case (r.Op == "secret.update" || r.Op == "secret.delete") && r.Arg == 1 && r.Target == "A" &&
		pk == pkViewer && is(core, Allowed) && is(rest, Denied) && is(grpc, Denied):
		return "D4"

	// D2: core-direct looser than every transport (the base permission, or a
	// gate, is transport-only). Not exposed by any transport.
	case is(core, Allowed) && is(rest, Denied) && deniedOrNA(grpc) && modelDenies:
		return "D2"

	// D3: IssueMachineToken evaluates a machine actor as user 0.
	case r.Op == "machine.token.issue" && pk == pkMachine &&
		is(core, Denied) && is(grpc, Denied) && is(rest, Other) && rest.Detail == "Internal Server Error":
		return "D3"

	// D6: AddProjectMember / SetProjectMemberRole never tag a machine actor as
	// a self-granter, so a machine that holds every needed permission is
	// always refused by the FIX-1 ceiling (fails closed; REST may say 500).
	case (r.Op == "member.add" || r.Op == "member.setrole") && pk == pkMachine && r.Model == Allowed &&
		is(core, Denied) && (is(rest, Denied) || restBadStatus):
		return "D6"

	// M1: REST answers 500/400 for a typed core permission refusal.
	case is(core, Denied) && core.Detail == "ErrPermissionDenied" && restBadStatus && modelDenies:
		return "M1"

	// M2: machine actor reaches a user-only core method with UserID 0.
	case pk == pkMachine && slices.Contains([]string{"secret.acl.grant", "secret.share", "accessrequest.create"}, r.Op) &&
		is(core, Other) && core.Detail == "untyped-error":
		return "M2"

	// M3: untyped core refusal (no ErrPermissionDenied): TransitionMembership's
	// text refusal, errAdminAuthorityRequired (OIDC binding), and kin. REST
	// either refuses first (403) or maps the untyped text to 400/500.
	case is(core, Other) && core.Detail == "untyped-error" && (is(rest, Denied) || restBadStatus) && modelDenies:
		return "M3"
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
