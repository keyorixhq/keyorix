package authzdiff

import (
	"slices"
	"strings"
)

// explain partitions a flagged case into the known finding buckets of
// REPORT.md (D1-D3 disagreements, M1-M3 mapping defects). Each rule names the
// exact shape — op, principal kind, and every layer's outcome — that the
// finding was established on, so a case that merely resembles a finding is
// NOT absorbed: it lands in "unexplained" and must be investigated.
//
// Returns "" for a case with nothing to explain (no O1/O2/mapping class, or
// only intended/uncalibrated classes).
func explain(r *caseResult) string {
	if !needsExplaining(r) {
		return ""
	}
	core, rest, grpc := r.Legs[layerCore], r.Legs[layerREST], r.Legs[layerGRPC]
	is := func(lo *legOutcome, o Outcome) bool { return lo != nil && lo.NA == "" && lo.Outcome == o }
	na := func(lo *legOutcome) bool { return lo == nil || lo.NA != "" }
	pk := r.Principal

	switch {
	// D1: gRPC group mutations do not require users.read (REST does).
	case slices.Contains([]string{"group.create", "group.update", "group.delete", "group.member.remove"}, r.Op) &&
		pk == pkCustom && is(rest, Denied) && is(grpc, Allowed) && r.Model == Denied:
		return "D1"

	// D2: core-direct looser than every transport (base permission is transport-only).
	case r.Op == "secret.autorotate" && is(core, Allowed) && is(rest, Denied) && is(grpc, Denied):
		return "D2"
	case (r.Op == "group.member.add" || r.Op == "group.role.assign") &&
		is(core, Allowed) && is(rest, Denied) && (is(grpc, Denied) || na(grpc)) && r.Model == Denied:
		return "D2"

	// D4: ownership is a grant in core (EnforceSecretActionPermission: "owner, an
	// allowlisted share, an ACL or a role", permissions.go:112) but both transports
	// gate the route on project RBAC first, so an owner without secrets.write /
	// secrets.delete can never use it. Shape: viewer (owner of s1, project_viewer
	// only) updating/deleting s1 in A.
	case (r.Op == "secret.update" || r.Op == "secret.delete") && r.Arg == 1 && r.Target == "A" &&
		pk == pkViewer && is(core, Allowed) && is(rest, Denied) && is(grpc, Denied):
		return "D4"

	// D3: IssueMachineToken evaluates a machine actor as user 0 (all layers refuse; REST as 500).
	case r.Op == "machine.token.issue" && pk == pkMachine &&
		is(core, Denied) && is(grpc, Denied) && is(rest, Other) && rest.Detail == "Internal Server Error":
		return "D3"

	// M1: REST answers 500 for a typed core permission refusal.
	case slices.Contains([]string{"machine.role.assign", "invitation.create", "accessrequest.approve"}, r.Op) &&
		is(core, Denied) && core.Detail == "ErrPermissionDenied" && is(rest, Other) && rest.Detail == "Internal Server Error":
		return "M1"

	// M2: machine actors on ACL grant / share: UserID 0 reaches core as a missing actor.
	case pk == pkMachine && (r.Op == "secret.acl.grant" || r.Op == "secret.share") &&
		is(core, Other) && core.Detail == "untyped-error":
		return "M2"

	// M3: TransitionMembership refuses with an untyped error (REST gate refuses first).
	case r.Op == "membership.transition" && is(core, Other) && core.Detail == "untyped-error" && is(rest, Denied):
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
