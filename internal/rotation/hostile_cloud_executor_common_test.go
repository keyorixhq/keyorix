package rotation

// DYNAMIC-HOSTILE-TAILS-1 item 2, rotation side: the cloud executors (aws-iam, azure-app,
// gcp-service-account) against a hostile cloud endpoint, through internal/fuzzutil/hostile.
// Same programs and oracles as internal/dynamic/hostile_cloud_common_test.go: no panic, a
// return within the deadline, no goroutine or descriptor left behind, no request storm, no
// sent credential in the error text or the log, and a typed refusal (an ordinary error, not
// a contained client panic) for every reply that was not a whole 2xx.
//
// GenerateUpstream is a sequence (list, create, delete), so each program is applied to
// each route in turn. The executor is built through containExecutor, as NewManager does.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

type hostileMode struct {
	name string
	prog hostile.Program
}

// See internal/dynamic/hostile_cloud_common_test.go for the Program field encoding and
// for why Frame 1 (cl-too-long) and Frame 6 (chunk-huge-size) are not in this table.
var cloudHostileModes = []hostileMode{
	{"malformed/garbage-bytes", hostile.Program{Occ: 1, Fault: 6}},
	{"malformed/truncated-body", hostile.Program{Occ: 1, Trunc: 17}},
	{"malformed/wrong-content-type", hostile.Program{Occ: 1, CT: 2, Trunc: 3}},
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

type cloudExecutorTarget struct {
	name   string
	tls    bool
	creds  []string
	routes []hostile.Route
	// sequenced: one route answers every call by order (the harness cannot tell IAM's
	// query-protocol actions apart), so each program also runs with Occ=2 (the first call
	// valid, every later one hostile) to reach the steps after the first.
	sequenced bool
	// bodyless names routes whose valid reply is a bare 2xx with no body (Graph's 204):
	// a reset after the headers cannot be observed there, the client already holds a
	// whole reply, so a success on one is right.
	bodyless []string
	// build returns the executor wired to h (only the endpoint and the credential source
	// differ from production) and the ref to rotate.
	build func(ctx context.Context, h *hostile.Harness) (Executor, string)
}

func (tg cloudExecutorTarget) run(prog hostile.Program) *hostile.Harness {
	h := hostile.New(hostile.Config{
		Routes: tg.routes, Program: prog, TLS: tg.tls, Credentials: tg.creds,
		RequestCeiling: 10, Retries: true,
	})
	err := h.Run(tg.name+".GenerateUpstream", func(ctx context.Context) error {
		exec, ref := tg.build(ctx, h)
		gen, ok := containExecutor(exec).(GeneratingExecutor)
		if !ok {
			return fmt.Errorf("%s is not a GeneratingExecutor", tg.name)
		}
		_, err := gen.GenerateUpstream(ctx, ref)
		return err
	})
	switch {
	case prog.Pristine() && err != nil:
		h.Violate("O6 LIVENESS: pristine GenerateUpstream failed: %v (unmatched: %v)", err, h.Unmatched())
	case !prog.Pristine() && err == nil:
		for _, rt := range tg.routes {
			for _, s := range h.Served(rt.Name) {
				whole := s.Complete || slices.Contains(tg.bodyless, rt.Name) && s.Status >= 200 && s.Status <= 299
				if s.Active && (!whole || s.Status < 200 || s.Status > 299 || s.Redirect != 0) {
					h.Violate("REFUSAL: GenerateUpstream succeeded on a damaged reply (route %s status=%d complete=%v redirect=%d, %s)", rt.Name, s.Status, s.Complete, s.Redirect, prog)
				}
			}
		}
	case errors.Is(err, dynamic.ErrEngineClientPanic):
		h.Violate("REFUSAL: the client library panicked on the reply (contained, but a crash on hostile input): %v", err)
	}
	return h
}

func runCloudExecutorHostile(t *testing.T, tg cloudExecutorTarget) {
	t.Helper()
	t.Run("pristine", func(t *testing.T) {
		h := tg.run(hostile.Program{})
		h.Finish(t.Fatalf)
	})
	occs := []int{1}
	if tg.sequenced {
		occs = append(occs, 2)
	}
	for route := range tg.routes {
		for _, occ := range occs {
			for _, m := range cloudHostileModes {
				prog := m.prog
				prog.Route, prog.Occ = route, occ
				t.Run(fmt.Sprintf("%s/occ%d/%s", tg.routes[route].Name, occ, m.name), func(t *testing.T) {
					h := tg.run(prog)
					h.Finish(t.Fatalf)
				})
			}
		}
	}
}
