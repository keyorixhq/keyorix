package services

// audit_unavailable_mapping_guard_test.go — AUDIT-503-MAP-1, gRPC side of
// server/http/handlers/audit_unavailable_mapping_guard_test.go: every service
// method that calls a core method able to return core.ErrMutationAuditUnavailable
// maps it to codes.Unavailable (auditUnavailableStatus), instead of the generic
// Internal an audit-log outage used to fall through to.
//
// The reaching-method set is derived in internal/core
// (audit_unavailable_reach_registry_test.go) and read from its testdata file. The
// MAPPER set is derived here too: every function in this package whose body calls
// auditUnavailableStatus (mapRoleError, groupError, ...).
//
// It also flags a mapper whose body calls context.Background() or context.TODO()
// (INV-GRPCSVC-mapper-takes-rpc-ctx), whether or not the mapper takes a context.Context:
// the historical defect was `mapXError(err error)` handing coreErrorStatus a
// context.Background(), with no ctx parameter at all. What it does not see: a mapper that
// gets a root ctx from a helper or a package variable instead of calling context.Background()
// or context.TODO() itself.
//
// What it recognises: a call `X.core.M(...)` (services reach core through a core
// field) with M reaching, inside a top-level function; that function must call a
// mapper or auditUnavailableStatus itself, directly. It does not follow the error
// into a helper the RPC hands it to unless that helper is itself a mapper.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

const auditUnavailableReachingMethodsFile = "../../../internal/core/testdata/audit_unavailable_reaching_methods.txt"

// auditUnavailableMappingExempt names RPC functions ("file.go:Func") that call a
// reaching method without mapping the outage, each for a stated reason.
var auditUnavailableMappingExempt = map[string]string{}

func readAuditUnavailableReachingMethods(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(auditUnavailableReachingMethodsFile)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		out[strings.TrimSpace(line)] = true
	}
	if len(out) < 10 {
		t.Fatalf("%s lists %d methods: the derivation is broken", auditUnavailableReachingMethodsFile, len(out))
	}
	return out
}

func grpcAuditUnavailableMappingViolations(funcs []grpcFuncCalls, exempt map[string]string) (violations []string, seen int, mappers map[string]bool) {
	// coreErrorStatus (core_error_status.go) calls auditUnavailableStatus first, so a
	// function that calls it maps the outage too (the family mappers migrate onto it).
	mappers = map[string]bool{"auditUnavailableStatus": true, "coreErrorStatus": true}
	for _, f := range funcs {
		if f.calls["auditUnavailableStatus"] || f.calls["coreErrorStatus"] {
			mappers[f.name] = true
			// A mapper that roots a new ctx answers without the request's cancellation: a
			// canceled request is not recognised as an authorize outage and answers
			// Internal where REST answers 503 (GRPC-MAPPER-TAILS-1,
			// INV-GRPCSVC-mapper-takes-rpc-ctx). A mapper with no ctx parameter is flagged
			// too: that was the shape of the original defect; it must take the RPC ctx.
			if f.rootsCtx {
				violations = append(violations, f.file+":"+f.name+" roots a new ctx (context.Background()/TODO()): take the RPC ctx")
			}
		}
	}
	for _, f := range funcs {
		if len(f.reachingCalls) == 0 {
			continue
		}
		seen += len(f.reachingCalls)
		mapped := false
		for c := range f.calls {
			if mappers[c] {
				mapped = true
				break
			}
		}
		if _, ok := exempt[f.file+":"+f.name]; mapped || ok {
			continue
		}
		violations = append(violations, f.file+":"+f.name+" -> "+strings.Join(f.reachingCalls, ","))
	}
	slices.Sort(violations)
	return violations, seen, mappers
}

// TestEveryAuditUnavailableReachingRPCMapsTheOutage reports its findings through
// guardrules.Rollout: report-only on pull requests while
// docs/guard-rollout.d/TestEveryAuditUnavailableReachingRPCMapsTheOutage.tsv
// exists (docs/guard-rollout-contract.md rule 2). The population tripwires stay
// blocking.
func TestEveryAuditUnavailableReachingRPCMapsTheOutage(t *testing.T) {
	g := guardrules.Rollout(t)
	violations, seen, mappers := grpcAuditUnavailableMappingViolations(
		scanGRPCFuncs(t, ".", readAuditUnavailableReachingMethods(t)), auditUnavailableMappingExempt)
	// Population tripwires: the known mutation RPCs and mappers must be seen.
	if seen < 10 {
		t.Fatalf("saw only %d core calls of a reaching method: the scan is broken", seen)
	}
	if len(violations) > 0 {
		g.Errorf("these RPCs call a core method that can return ErrMutationAuditUnavailable without mapping it "+
			"to codes.Unavailable (auditUnavailableStatus, or a mapper that calls it), or add a reasoned exemption "+
			"to auditUnavailableMappingExempt:\n  %s", strings.Join(violations, "\n  "))
	}
	for _, m := range []string{"mapRoleError", "mapUserError"} {
		if !mappers[m] {
			t.Fatalf("mapper %s not derived: the scan is broken, or %s stopped mapping the audit outage", m, m)
		}
	}
}

// TestAuditUnavailableRPCMappingGuardCatchesAnUnmappedRPC is the guard's self-test.
func TestAuditUnavailableRPCMappingGuardCatchesAnUnmappedRPC(t *testing.T) {
	dir := t.TempDir()
	src := `package services
func mapX(err error) error { if e, ok := auditUnavailableStatus(err); ok { return e }; return err }
func (s *S) Bad()  error { return wrap(s.core.AssignUserRole()) }
func (s *S) Good() error { return mapX(s.core.AssignUserRole()) }
func (s *S) Skip() error { return wrap(s.core.AssignUserRole()) }
func mapY(ctx C, err error) error { return coreErrorStatus(ctx, err, o) }
func (s *S) ViaAdapter() error { return mapY(ctx, s.core.AssignUserRole()) }
func mapDrops(ctx context.Context, err error) error { return coreErrorStatus(context.Background(), err, o) }
func mapDropsTODO(ctx context.Context, err error) error { return coreErrorStatus(context.TODO(), err, o) }
func mapNoCtx(err error) error { return coreErrorStatus(context.Background(), err, o) }
func mapKeeps(ctx context.Context, err error) error { return coreErrorStatus(ctx, err, o) }
func mapNoCtxNoRoot(err error) error { if e, ok := auditUnavailableStatus(err); ok { return e }; return err }
func helperRoots() C { return context.Background() }
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, seen, mappers := grpcAuditUnavailableMappingViolations(
		scanGRPCFuncs(t, dir, map[string]bool{"AssignUserRole": true}), map[string]string{"synthetic.go:Skip": "test"})
	want := []string{
		"synthetic.go:Bad -> AssignUserRole",
		"synthetic.go:mapDrops roots a new ctx (context.Background()/TODO()): take the RPC ctx",
		"synthetic.go:mapDropsTODO roots a new ctx (context.Background()/TODO()): take the RPC ctx",
		"synthetic.go:mapNoCtx roots a new ctx (context.Background()/TODO()): take the RPC ctx",
	}
	// Green: mapKeeps (passes its ctx), mapNoCtxNoRoot (a mapper with no ctx that roots
	// none), helperRoots (roots a ctx but is not a mapper).
	if seen != 4 || !mappers["mapX"] || !mappers["mapY"] || !mappers["mapKeeps"] || !mappers["mapNoCtxNoRoot"] ||
		mappers["helperRoots"] || !slices.Equal(violations, want) {
		t.Fatalf("self-test: seen=%d mappers=%v violations=%v", seen, mappers, violations)
	}
}
