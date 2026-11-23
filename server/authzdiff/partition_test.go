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
// No waiver is open. The former ones, and what closed them:
//
//   - known-04 (core allows, every present transport denies, #4161): core
//     performed no or a narrower check than the route gate. #4161 moved the
//     route gates into core (internal/core/authz_core_gate.go,
//     TestCoreGateParity_*); #4536 and #4559 closed the owner passes; the last
//     row, bulk.suspend for a viewer holding a per-secret ACL write, was closed
//     by core deciding secrets.write@project in SuspendProjectSecretsWithOptions
//     (TestSuspendProjectSecrets_ProjectGate). A dropped core check now fails a
//     strict sweep even while both transports still gate the op.
//   - known-02 (core let a suspended actor act, #4159) was fixed in core at
//     every bound core-enforced op, the value reads included (#4336;
//     TestCoreRefusesSuspendedActor, which fails an op it has no checked case
//     for). known-03 (core let a secret's owner update/delete it without
//     secrets.write/secrets.delete, #4160) was fixed in core
//     (TestCoreOwnerWithoutPermissionIsRefused).
//   - An untyped core error is never waived. The former known-08 (machine
//     actors on nine human-only ops, #4162) and known-09 (untyped refusals on
//     secret.copy, membership.transition, share.update and break-glass, #4163)
//     were typed in core (TestCoreRefusalsAreTyped). A typed core refusal
//     (ErrPermissionDenied) that REST answers 400/500 is never waived either:
//     the former known-07 was fixed in the four handlers it matched
//     (TestCeilingRefusalIsForbiddenOnREST).
//
// The plants (plants_test.go) are exactly the shapes a waiver must never
// absorb: core+REST allow (plant 1), gRPC allows a non-group op (plant 2), REST
// allows what gRPC denies (plant 3), gRPC allows a group op to a principal
// without the op's write permission (plant 4) or without the route group's read
// permission (plant 5), and a core-only over-allow (the reassign-owner plant).
//
// Dead waivers: a full strict sweep (AUTHZDIFF_STRICT=1, no AUTHZDIFF_OPS)
// fails on any waiver in waiverIDs that matched zero cases, so a waiver whose
// condition was fixed is removed instead of silently absorbing a regression
// of that fix.
//
// A new waiver is a case here returning "known-NN" plus its row in waivers
// (TestWaiverIDsMatchExplain keeps the two in step).
//
// Returns "" for a case with nothing to explain.
func explain(r *caseResult) string {
	if !needsExplaining(r) {
		return ""
	}
	return "unexplained"
}

// waivers is the known-open list: every bucket explain can return other than
// "unexplained", each with the issue that tracks it and an expiry. The nightly
// job fails on an expired row (TestAuthzDiffWaiversNotExpired); renewing one
// is a decision recorded on its issue, not a date bump.
var waivers = []struct{ id, issue, expires string }{}

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
	issue := regexp.MustCompile(`^#[0-9]+$`)
	for _, w := range waivers {
		if !issue.MatchString(w.issue) {
			t.Errorf("waiver %s: issue %q is not #NNNN", w.id, w.issue)
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
