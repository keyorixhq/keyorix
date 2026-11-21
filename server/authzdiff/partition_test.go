package authzdiff

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// explain assigns a flagged case to a known waiver ("known-NN"). Each waiver
// names an exact SHAPE — principal kind and every layer's outcome, and an op
// list where needed — so a case that merely resembles a waiver is NOT
// absorbed: it lands in "unexplained" and must be investigated. Each waiver's
// issue and expiry are in waivers below.
//
// Every waiver keeps one direction closed: none matches a case where a present
// transport leg (REST or gRPC) allows and the model denies (or has no
// decision). TestExplainNeverWaivesTransportAllowOverModelDeny checks this over
// every combination of the values explain compares against.
//
// The waiver families, what each matches, and what it does not detect:
//
//   - Core allows (known-04): the core leg allows, REST denies and gRPC
//     denies or is absent. A transport that allows never matches. Not
//     detected: a core leg that allows while every present transport denies
//     (see below). The former known-02 (core let a suspended actor act, #4159)
//     was fixed in core at every bound core-enforced op, the value reads
//     included (#4336; TestCoreRefusesSuspendedActor, which fails an op it has
//     no checked case for). The former known-03 (core let a secret's
//     owner update/delete it without secrets.write/secrets.delete, #4160) was
//     fixed in core (TestCoreOwnerWithoutPermissionIsRefused).
//   - An untyped core error is never waived. The former known-08 (machine
//     actors on nine human-only ops, #4162) and known-09 (untyped refusals on
//     secret.copy, membership.transition, share.update and break-glass, #4163)
//     were typed in core (TestCoreRefusalsAreTyped). A typed core refusal
//     (ErrPermissionDenied) that REST answers 400/500 is never waived either:
//     the former known-07 was fixed in the four handlers it matched
//     (TestCeilingRefusalIsForbiddenOnREST).
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
	modelDenies := r.Model == Denied || r.Model == ModelNA

	switch {
	case is(core, Allowed) && is(rest, Denied) && deniedOrNA(grpc) && modelDenies:
		return "known-04"

	// V5EXT5 known-12: mfa.activate, mfa.disable, mfa.recovery-codes.regenerate
	// for a principal that lacks the required MFA account state (pending enrollment
	// for activate; mfa_enabled=true for disable/regenerate). The router carries no
	// RBAC gate; refusal is a business-rule 400 Bad Request ("no pending MFA
	// enrolment" / "MFA is not enabled"), not an auth rejection, so REST returns
	// Other, not Denied. The model correctly says Denied. No gRPC surface;
	// coreEnforced=false for all three ops. The core leg returns a business-logic
	// error (not ErrPermissionDenied) for these; !is(core,Allowed) prevents this
	// from absorbing a hypothetical core-allows case.
	// TODO-ISSUE — file tracking issue; see report LEFTOVERS.
	case slices.Contains([]string{"mfa.activate", "mfa.disable", "mfa.recovery-codes.regenerate"}, r.Op) &&
		!is(core, Allowed) && restBadStatus && modelDenies && na(grpc):
		return "known-12"
	}
	return "unexplained"
}

// waivers is the known-open list: every bucket explain can return other than
// "unexplained", each with the issue that tracks it and an expiry. The nightly
// job fails on an expired row (TestAuthzDiffWaiversNotExpired); renewing one
// is a decision recorded on its issue, not a date bump.
var waivers = []struct{ id, issue, expires string }{
	{"known-04", "#4161", "2027-02-13"},
	{"known-12", "TODO-ISSUE", "2027-06-18"},
}

// waiverIDs is waivers' ids (the dead-waiver check's population).
// TestWaiverIDsMatchExplain keeps it in step with explain's source.
var waiverIDs = func() []string {
	ids := make([]string, len(waivers))
	for i, w := range waivers {
		ids[i] = w.id
	}
	return ids
}()

// TestAuthzDiffWaiversNotExpired: every waiver names an issue and a valid
// expiry; guardrules.CheckExpiry compares the date only in the nightly job
// (no calendar at PR time, docs/guard-rollout-contract.md).
func TestAuthzDiffWaiversNotExpired(t *testing.T) {
	// TODO-ISSUE is a valid placeholder when no tracking issue has been filed yet.
	issue := regexp.MustCompile(`^(#[0-9]+|TODO-ISSUE)$`)
	for _, w := range waivers {
		if !issue.MatchString(w.issue) {
			t.Errorf("waiver %s: issue %q is not #NNNN or TODO-ISSUE", w.id, w.issue)
		}
		guardrules.CheckExpiry(t, guardrules.Expiry{
			Source:  "server/authzdiff/partition_test.go waivers",
			Key:     w.id,
			Expires: w.expires,
			Note:    "authzdiff waiver, tracked in " + w.issue,
		})
	}
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
