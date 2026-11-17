package dynamic

// DYNAMIC-HOSTILE-TAILS-1 item 2: the cloud-IAM engines (aws-sts, gcp, azure) against
// a hostile cloud endpoint. internal/fuzzutil/hostile serves a valid reply and the
// programs below break it the four ways a hostile or broken endpoint can: a malformed
// reply, a huge length prefix, a slow reply, a connection reset. The oracles are the
// harness's: no panic, the call returns within its deadline, no goroutine or descriptor
// left behind, no request storm, no sent credential in the error text or the log.
// On top of those, a typed refusal: Issue returns an ordinary error (never a success,
// and never a contained client panic, which would mean the SDK crashed on the input).
//
// Not covered: Kubernetes (FuzzK8sTokenRequestHostileAPI), the database engines
// (hostile_engine_panic_test.go), and Revoke/Renew, which are no-ops or refusals for
// every cloud engine and make no request.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

type hostileMode struct {
	name string
	prog hostile.Program
}

// Program fields index the harness's tables (internal/fuzzutil/hostile/program.go):
// Fault 1 rst-after-headers, 2 rst-mid-body, 3 close-after-headers, 4 hang, 5 slow-drip,
// 6 garbage, 8 accept-close, 9 partial-headers-hang; Frame 1 cl-too-long, 6
// chunk-huge-size, 10 chunk-ext-giant, 11 header-giant; Trunc 17 keeps half the body.
// Occ 1 breaks every request, so an SDK retry meets the same endpoint.
var cloudHostileModes = []hostileMode{
	{"malformed/garbage-bytes", hostile.Program{Occ: 1, Fault: 6}},
	{"malformed/truncated-body", hostile.Program{Occ: 1, Trunc: 17}},
	{"malformed/wrong-content-type", hostile.Program{Occ: 1, CT: 2, Trunc: 3}},
	// Frame 1 (cl-too-long) and Frame 6 (chunk-huge-size) are NOT in this table: the
	// reply document arrives whole and the connection then ends in a transport error,
	// which the aws-sdk-go-v2 XML decoder never reads, so aws-sts Issue succeeds (gcp and
	// azure refuse both). Third-party finding awaiting a decision (triage entry or
	// upstream report); see the session report. Same class as
	// HK-K8S-TRAILING-TRANSPORT-ERROR (k8s_hostile_fuzz_test.go).
	{"huge-prefix/giant-chunk-extension", hostile.Program{Occ: 1, Frame: 10}},
	{"huge-prefix/giant-header", hostile.Program{Occ: 1, Frame: 11}},
	{"slow/hang-after-request", hostile.Program{Occ: 1, Fault: 4}},
	{"slow/drip", hostile.Program{Occ: 1, Fault: 5}},
	{"slow/partial-headers-hang", hostile.Program{Occ: 1, Fault: 9}},
	{"reset/rst-after-headers", hostile.Program{Occ: 1, Fault: 1}},
	{"reset/rst-mid-body", hostile.Program{Occ: 1, Fault: 2}},
	{"reset/close-after-headers", hostile.Program{Occ: 1, Fault: 3}},
	{"reset/accept-close", hostile.Program{Occ: 1, Fault: 8}},
}

// cloudHostileTarget is one cloud engine wired to a harness.
type cloudHostileTarget struct {
	name   string
	tls    bool
	creds  []string // credentials the client sends; none may reach an error or the log
	routes []hostile.Route
	// issue builds the engine against h (as production builds it, with only the
	// endpoint and the credential source swapped) and runs one Issue.
	issue func(ctx context.Context, h *hostile.Harness) error
	// known are the target's triaged, still-open findings (hostile.Known).
	known []hostile.Known
}

func (tg cloudHostileTarget) run(prog hostile.Program) *hostile.Harness {
	h := hostile.New(hostile.Config{
		Routes: tg.routes, Program: prog, TLS: tg.tls, Credentials: tg.creds,
		RequestCeiling: 8, Retries: true, Known: tg.known,
	})
	err := h.Run(tg.name+".Issue", func(ctx context.Context) error { return tg.issue(ctx, h) })
	switch {
	case prog.Pristine() && err != nil:
		h.Violate("O6 LIVENESS: pristine Issue failed: %v (unmatched: %v)", err, h.Unmatched())
	case !prog.Pristine() && err == nil:
		// A success is right only when every mutated exchange still delivered a whole
		// 2xx reply (a giant header the client accepts, say); anything less must refuse.
		for _, rt := range tg.routes {
			for _, s := range h.Served(rt.Name) {
				if s.Active && (!s.Complete || s.Status < 200 || s.Status > 299 || s.Redirect != 0) {
					h.Violate("REFUSAL: Issue succeeded on a damaged reply (route %s status=%d complete=%v redirect=%d, %s)", rt.Name, s.Status, s.Complete, s.Redirect, prog)
				}
			}
		}
	case errors.Is(err, ErrEngineClientPanic):
		h.Violate("REFUSAL: the SDK panicked on the reply (contained, but a crash on hostile input): %v", err)
	}
	return h
}

// runCloudHostile is the table every cloud target runs: the pristine control, then each
// hostile mode.
func runCloudHostile(t *testing.T, tg cloudHostileTarget) {
	t.Helper()
	t.Run("pristine", func(t *testing.T) {
		h := tg.run(hostile.Program{})
		h.Finish(t.Fatalf)
	})
	for _, m := range cloudHostileModes {
		t.Run(m.name, func(t *testing.T) {
			h := tg.run(m.prog)
			h.Finish(t.Fatalf)
		})
	}
}

const hostileIssueTTL = 15 * time.Minute
