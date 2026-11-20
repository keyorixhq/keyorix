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
	restBadStatus := (is(rest, Other) || is(rest, PreconditionFailed)) && (rest.Detail == "Internal Server Error" || rest.Detail == "Bad Request")
	pk := r.Principal
	modelDenies := r.Model == Denied || r.Model == ModelNA

	switch {
	case is(core, Allowed) && is(rest, Denied) && deniedOrNA(grpc) && modelDenies:
		return "known-04"

	// V5EXT3 known-10: a machine actor holds the router gate permission for
	// bulk.rename, bulk.suspend or resume.all; it passes the gate but the core
	// function rejects actorID=0, so REST answers 400/500. A business-rule
	// exclusion, not an authorization gate; the model (router gate only)
	// says "allowed". These ops have no gRPC surface.
	// Tracked: #4514.
	case pk == pkMachine && slices.Contains([]string{"bulk.rename", "bulk.suspend", "resume.all"}, r.Op) &&
		na(core) && restBadStatus && deniedOrNA(grpc):
		return "known-10"

	// V5EXT3 known-11: bulk.delete with secrets.delete but not secrets.read.
	// The router gate passes; BulkDeleteSecrets reads each item first and that
	// read needs secrets.read, so the item is refused (core item-refused, REST
	// 200 with an empty Deleted list). The model covers the gate, not the
	// per-item data-access prerequisite. No gRPC surface.
	// Tracked: #4515.
	case r.Op == "bulk.delete" && is(core, Denied) && core.Detail == "item-refused" &&
		is(rest, Denied) && rest.Detail == "2xx-item-refused" && deniedOrNA(grpc):
		return "known-11"

	// V5EXT7 known-12: mfa.enroll with a machine-token actor.
	// MFA enrollment is a user-only self-service operation; the REST endpoint
	// rejects machine-token requests with 400 Bad Request. The reference model
	// has no permission requirement for mfa.enroll (noMFARequired: true), so it
	// returns "allowed" for any principal that does not already have MFA enabled
	// — including machine identities. This is a model-coverage gap, not an
	// authorization defect: machine tokens cannot hold personal MFA by design.
	// No gRPC surface; core excludes machine actors via errNotAuthzLayer.
	// Tracked: TODO-ISSUE.
	case pk == pkMachine && r.Op == "mfa.enroll" &&
		na(core) && restBadStatus && deniedOrNA(grpc):
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
	{"known-10", "#4514", "2027-06-18"},
	{"known-11", "#4515", "2027-06-18"},
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
