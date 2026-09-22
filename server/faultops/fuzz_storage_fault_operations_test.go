// fuzz_storage_fault_operations_test.go is FuzzStorageFaultOperations: fault
// injection at the storage-INTERFACE level (one layer above #1951's
// FuzzFaultInjectedOperations, which faults durability seams below it), across
// every operation in opCatalog, driven through the real REST/system/gRPC
// transports.
//
// SCOPE CUT (documented, not silent — see the STEP 0/REPORT): this MVP arms the
// fault for the op's WHOLE Drive() call (setup calls included), not only its
// final mutating request — STEP 1's original prefix/op/suffix split is
// follow-up work. It does not yet run a "rest of the sequence" fault-free
// afterward (single-operation fuzzing, not multi-op sequences) — a real gap for
// catching state corruption that only surfaces on a LATER op, called out
// explicitly rather than silently claimed as covered.
package faultops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
	resthandlers "github.com/keyorixhq/keyorix/server/http/handlers"
)

var errFuzzInjected = errors.New("fault-fuzz injected failure")

// drainAllBackgroundGoroutines deterministically waits for every in-flight goSafe
// goroutine across all three packages that duplicate the goSafe helper (handlers,
// grpc/services, core — see each package's own DrainBackgroundGoroutines doc
// comment; server/http/canary_secret_leakage_fuzz_test.go does the identical
// three-package drain for the same reason). A detached audit write dispatched by
// Setup or Execute (goSafe, fire-and-forget by design) is not synchronized with
// the caller's HTTP/gRPC response, so without draining it can land in the gap
// between a `before`/`refAfter` snapshot and the following `after` snapshot,
// producing a spurious AuditEvent-only diff blamed on the fault under test.
func drainAllBackgroundGoroutines() {
	resthandlers.DrainBackgroundGoroutines()
	grpcservices.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()
}

// storageInterfaceMethodNames returns every storage.Storage method name, sorted
// (reflect.Type.Method(i) already returns interface methods in that order) —
// derived at runtime from the interface itself, so it can never drift from the
// 418 faulty_storage_generated.go actually covers.
func storageInterfaceMethodNames() []string {
	t := reflect.TypeOf((*storage.Storage)(nil)).Elem()
	names := make([]string, t.NumMethod())
	for i := range names {
		names[i] = t.Method(i).Name
	}
	return names
}

// authzReadMethods back core.Authorize / permission resolution / scope
// discovery (confirmed by reading their doc comments in
// internal/core/storage/interface.go, not guessed — "Together they back
// core.Authorize"). Oracle (c): a fault on any of these must never let an
// operation SUCCEED — error or deny only, regardless of what the reference
// (fault-free) run would have done.
var authzReadMethods = map[string]bool{
	"GetUserRoleIDsAt":                true,
	"GetUserRoleIDsExact":             true,
	"GetUserGroupRoleIDsAt":           true,
	"RoleSetHasPermission":            true,
	"RoleSetBypassesPermissionChecks": true,
	"GetUserPermissions":              true,
	"GetUserGroupPermissions":         true,
	"IsProjectMember":                 true,
	"IsGroupProjectScoped":            true,
	"GetUserRoleScopes":               true,
	// GetSecretAncestors: found live, not from the original doc-comment sweep
	// — HasSecretACL (internal/core/secret_acl.go:189) walks it to check
	// folder-inherited per-secret ACL grants; a fault here must not let a
	// per-secret-ACL-gated operation through. Added after a fuzz burst hit it
	// on DeleteSecret's authz path — another instance of "enumeration only as
	// complete as the idioms it knows about" (CLAUDE.md).
	"GetSecretAncestors": true,
}

// nonLoadBearingAuthzReadExceptions narrowly exempts a SPECIFIC (op, method,
// NthCall) triple from oracle (c) — traced, not assumed. RULES' "acceptable-
// by-design (exclusion with justification; I review these)" category, same as
// bestEffortTables, but for oracle (c) rather than (a).
//
// REST DELETE /api/v1/secrets/{id}, GetSecretAncestors, NthCall=2: the
// handler (server/http/handlers/secrets_crud.go:DeleteSecret) makes TWO
// independent, separately-authorized calls for a non-machine caller:
//  1. The route's own RequireScopedSecretPermission middleware gate
//     (server/middleware/auth.go) calls AuthorizeSecretPrincipal ->
//     AuthorizeSecret -> HasSecretACL -> GetSecretAncestors as call #1, and
//     finishScopedPermissionRequest correctly fails closed
//     (`if err != nil || !allowed { forbiddenResponse... }`) on any error
//     from it. THIS is the real authorization gate.
//  2. AFTER that gate has already passed, the handler body redundantly
//     re-resolves the secret via GetSecretWithPermissionCheck purely "to
//     pre-fetch name and project for audit log" (the handler's own comment)
//     — its OWN internal AuthorizeSecret call is call #2 to
//     GetSecretAncestors. Its error is captured as prefetchErr and
//     deliberately NOT treated as fatal (`if prefetchErr == nil { ... }`,
//     no else branch that aborts) — the delete proceeds regardless, using a
//     generic "id=%d" audit description instead of the real secret name.
//
// A fault on call #1 correctly produces a 403 (confirmed by a fuzz run that
// found NO surviving violation at NthCall=1 for this op/method). Only
// call #2 — the redundant, audit-description-only prefetch — reaches this
// exemption. The real authorization decision is provably unaffected by this
// specific fault; only audit-log content quality degrades, the same
// documented tradeoff bestEffortTables already covers for the DIRECT
// LogAuditEvent/AddPasswordHistory cases. FLAG FOR REVIEW: this redundant
// prefetch-and-swallow pattern (duplicate authz call whose failure is
// silently tolerated) could plausibly recur at other call sites this sweep
// didn't specifically look for — worth a dedicated grep as follow-up, not
// done here.
//
// REST DELETE /api/v1/secrets/{id}, GetUserGroupRoleIDsAt, NthCall=2: the
// predicted recurrence from the FLAG FOR REVIEW note directly above, found by
// a later fuzz burst — same call #2 (the redundant GetSecretWithPermissionCheck
// prefetch), just caught inside CheckSecretPermission's RBAC fallback
// (permissions.go: AuthorizePrincipal -> Authorize -> scopedRoleIDs ->
// GetUserGroupRoleIDsAt) rather than the ACL-inheritance branch GetSecretAncestors
// sits in — same handler, same non-owner/non-share/non-ACL fallthrough, same
// prefetchErr-is-not-fatal handling. The real authorization gate is call #1
// (the route's RequireScopedSecretPermission middleware), traced fail-closed
// exactly as for the GetSecretAncestors entry above; only the audit-description
// prefetch is affected here too.
type nonLoadBearingException struct {
	op, method string
	nth        int
}

var nonLoadBearingAuthzReadExceptions = []nonLoadBearingException{
	{op: "REST DELETE /api/v1/secrets/{id}", method: "GetSecretAncestors", nth: 2},
	{op: "REST DELETE /api/v1/secrets/{id}", method: "GetUserGroupRoleIDsAt", nth: 2},
}

// multiStepAmbiguousCommitExceptions narrowly flags a traced instance of
// oracle (d) firing on the FIRST storage call of a multi-step create, NOT
// because it's decided safe (unlike bestEffortTables/nonLoadBearingAuthzRead,
// this is NOT auto-accepted as fine) but because forcing a decision here
// (fix vs. accept) needs a product call this task should not make
// unilaterally — see the doc comment below for the full trace. Every
// occurrence still logs loudly (t.Logf, not silently skipped) so it stays
// visible on every run.
//
// REST POST /api/v1/secrets/, CreateSecret, NthCall=1, KindEffectThenError:
// internal/core/secrets.go's CreateSecret is two storage calls —
// c.storage.CreateSecret (creates the SecretNode) then c.storeSecretVersion
// (creates version 1) — and ALREADY has explicit compensating cleanup for the
// SECOND call failing (`if err := c.storeSecretVersion(...); err != nil { ...
// c.storage.DeleteSecret(ctx, createdSecret.ID) ... }`, secrets.go). There is
// NO equivalent handling for the FIRST call: when c.storage.CreateSecret
// itself returns an error, CreateSecret returns immediately
// (`if err != nil { return nil, ... }`) — and if that error was itself
// ambiguous (the real effect committed, e.g. a network blip on the ack, which
// is exactly what KindEffectThenError models), the caller has NO ID to clean
// up, because CreateSecret's own return value on that path is (nil, err) —
// the created node's ID is never surfaced to it. The result: a real,
// orphaned SecretNode row with zero SecretVersion rows.
//
// This is NOT the same defect class as F3 (a swallowed error masking a
// failure) — the error here is NOT swallowed, it correctly propagates as a
// failure response. It is a narrower, classic ambiguous-commit gap inherent
// to any non-idempotent multi-step write without a correlation ID or
// two-phase commit, and fixing it properly (client-supplied idempotency key,
// or a reconciliation sweep for zero-version SecretNode rows) is a real
// design decision, not a small patch — left for product/engineering review,
// not decided here.
var multiStepAmbiguousCommitExceptions = []nonLoadBearingException{
	{op: "REST POST /api/v1/secrets/", method: "CreateSecret", nth: 1},
	// internal/core/users.go's CreateUser has the identical shape: an
	// ambiguous commit on c.storage.CreateUser (the FIRST call) returns
	// immediately, before ever reaching the best-effort AddPasswordHistory
	// and system_viewer AssignRole calls that follow — leaving a real,
	// orphaned User row with neither. Same root cause, same "needs a design
	// decision, not a small patch" conclusion as the CreateSecret entry above.
	{op: "REST POST /api/v1/users/", method: "CreateUser", nth: 1},
}

// opScopedBestEffortTables narrows bestEffortTables' method-only scope to a
// SPECIFIC (op, method) pair, for a storage method that is best-effort at ONE
// call site but load-bearing at others — unlike AddPasswordHistory/
// LogAuditEvent/CreateEnvironment (genuinely best-effort EVERYWHERE they are
// called), storage.AssignRole is load-bearing at
// internal/core/auth_bootstrap.go:322 (admin bootstrap) and
// internal/core/rbac_management.go's explicit assign-role paths (wired into
// opCatalog as "GRPC keyorix.v1.RoleService.AssignRole") — a blanket
// bestEffortTables entry keyed only by method name would ALSO suppress a
// genuine oracle (a) violation on those load-bearing call sites, since a
// swallowed AssignRole failure there produces the identical UserRole-only
// diff. Scoping to the specific op avoids that.
//
// REST POST /api/v1/users/, AssignRole: internal/core/users.go's CreateUser
// auto-assigns the system_viewer role (ADR-021, "a minimal install-wide
// baseline") as documented best-effort — `_ = c.storage.AssignRole(...)`,
// its own comment reads "Failure is non-fatal — the user is created
// regardless." Found live by the coverage-batch-6 smoke burst. Direction is
// security-benign: failure means the new user ends up with FEWER roles than
// the reference run (fail-closed, under-privileged), never more, so this is
// the same class of accepted tradeoff as bestEffortTables' other entries,
// just narrower in scope.
var opScopedBestEffortTables = []struct {
	op, method string
	tables     []string
}{
	{op: "REST POST /api/v1/users/", method: "AssignRole", tables: []string{"UserRole"}},
}

func opScopedAcceptableByDesign(op, method string, diff []string) bool {
	for _, e := range opScopedBestEffortTables {
		if e.op != op || e.method != method {
			continue
		}
		allowedSet := make(map[string]bool, len(e.tables))
		for _, t := range e.tables {
			allowedSet[t] = true
		}
		ok := true
		for _, d := range diff {
			if !allowedSet[d] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func multiStepFirstCallAmbiguousCommit(op, method string, nth int) bool {
	for _, e := range multiStepAmbiguousCommitExceptions {
		if e.op == op && e.method == method && e.nth == nth {
			return true
		}
	}
	return false
}

func nonLoadBearingAuthzRead(op, method string, nth int) bool {
	for _, e := range nonLoadBearingAuthzReadExceptions {
		if e.op == op && e.method == method && e.nth == nth {
			return true
		}
	}
	return false
}

// canaryFragments are substrings that must never appear in an error response
// body — the plaintext secret value this run wrote, standing in for "secret
// plaintext" (RULES oracle (e)); reused verbatim, not a new canary scheme.
var canaryFragments = []string{"fuzz-value", "fuzz-value-updated"}

type decodedFuzzOp struct {
	opIndex    int
	methodName string
	nthCall    int
	kind       faultstorage.FaultKind
}

func decodeFuzzOp(data []byte) (decodedFuzzOp, bool) {
	if len(opCatalog) == 0 {
		return decodedFuzzOp{}, false
	}
	methods := storageInterfaceMethodNames()
	if len(methods) == 0 {
		return decodedFuzzOp{}, false
	}
	b := func(i int) byte {
		if i < len(data) {
			return data[i]
		}
		return 0
	}
	opIdx := int(b(0)) % len(opCatalog)
	methodIdx := (int(b(1))<<8 | int(b(2))) % len(methods)
	nthCall := 1 + int(b(3))%5
	kinds := []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}
	kind := kinds[int(b(4))%len(kinds)]
	return decodedFuzzOp{
		opIndex:    opIdx,
		methodName: methods[methodIdx],
		nthCall:    nthCall,
		kind:       kind,
	}, true
}

func FuzzStorageFaultOperations(f *testing.F) {
	// Seeds: one per known bug class, plus one clean seed per oracle. Byte
	// layout: [opIndex, methodIdxHi, methodIdxLo, nthCall-1..4, kindSelector].
	seedFor := func(opKey, method string, nth int, kind byte) []byte {
		opIdx := -1
		for i, op := range opCatalog {
			if op.Key == opKey {
				opIdx = i
				break
			}
		}
		if opIdx < 0 {
			return nil
		}
		methods := storageInterfaceMethodNames()
		methodIdx := -1
		for i, m := range methods {
			if m == method {
				methodIdx = i
				break
			}
		}
		if methodIdx < 0 {
			return nil
		}
		return []byte{byte(opIdx), byte(methodIdx >> 8), byte(methodIdx), byte(nth - 1), kind}
	}

	// F3: fault RemovePermissionFromRole inside UpdateRole's replaceRolePermissions.
	if s := seedFor("REST PUT /api/v1/roles/{id}", "RemovePermissionFromRole", 1, 0); s != nil {
		f.Add(s)
	}
	// sweepFn-class: a panic mid-operation on an ordinary write.
	if s := seedFor("REST POST /api/v1/secrets/", "CreateSecret", 1, 1); s != nil {
		f.Add(s)
	}
	// authz drop-err-guard class: fault a permission-resolution read.
	if s := seedFor("GRPC keyorix.v1.RoleService.AssignRole", "GetUserRoleIDsAt", 1, 0); s != nil {
		f.Add(s)
	}
	// effect-then-error: a write whose real effect lands but is reported failed.
	if s := seedFor("REST DELETE /api/v1/secrets/{id}", "DeleteSecret", 1, 2); s != nil {
		f.Add(s)
	}
	// /system proxy bypass class.
	if s := seedFor("REST PUT /api/v1/system/machine-identities/{id}/transition", "TransitionMachineIdentityState", 1, 0); s != nil {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		runOneFuzzIteration(t, data)
	})
}

// runOneFuzzIteration is the fuzz body, factored out so replay_test.go's
// TestReplayStorageFaultInput can run the identical logic against one
// specific saved input outside of f.Fuzz.
func runOneFuzzIteration(t *testing.T, data []byte) {
	t.Helper()
	t.Log(traceFuzzOp(data)) // RULES: print the decoded operation/fault as a readable line, every run.

	decoded, ok := decodeFuzzOp(data)
	if !ok {
		t.Skip("empty catalog/method list")
	}
	op := opCatalog[decoded.opIndex]
	ctx := context.Background()

	// Reference: same operation, fully unfaulted, fresh world — the
	// expected post-state a legitimate success must match (oracle (a)).
	ref := newFaultWorld(t, nil)
	refResult, refErr := runOp(ctx, ref, op)
	if refErr != nil {
		t.Skipf("reference (fault-free) run itself errored — not a fault-injection finding: %v", refErr)
	}
	if !refResult.Success {
		t.Skipf("reference (fault-free) run itself failed — not a fault-injection finding: %s", refResult.Detail)
	}
	// Same goSafe race as below: runOp's Setup+Execute may have dispatched a
	// detached audit write that hasn't landed by the time we snapshot.
	drainAllBackgroundGoroutines()
	refAfter, err := snapshotDB(ref.db)
	if err != nil {
		t.Fatalf("snapshotting reference world: %v", err)
	}

	// Fault world: Setup runs UNFAULTED (spec nil at construction), so
	// NthCall below counts only Execute's own calls, and `before` reflects
	// post-setup state rather than the pristine pre-setup world.
	w := newFaultWorld(t, nil)
	var state any
	if op.Setup != nil {
		state, err = op.Setup(ctx, w)
		if err != nil {
			t.Skipf("setup itself errored — not a fault-injection finding: %v", err)
		}
	}
	// Setup drives a real handler (e.g. CreateSecret), which may dispatch its own
	// detached audit write via goSafe (server/http/handlers, server/grpc/services,
	// or internal/core all duplicate it) — fired after the response, not
	// synchronized with it. Without draining here, that goroutine can land AFTER
	// `before` is snapshotted but BEFORE `after` is, producing a spurious
	// AuditEvent-only diff attributed to the FAULTED call under test when it was
	// really Setup's own unrelated write landing late. drainAllBackgroundGoroutines
	// is the existing test-only hook built exactly for this (see its doc comment
	// and each package's own); a fixed sleep would only reduce, not eliminate, the
	// race.
	drainAllBackgroundGoroutines()
	before, err := snapshotDB(w.db)
	if err != nil {
		t.Fatalf("snapshotting pre-fault (post-setup) world: %v", err)
	}

	w.faulty.Arm(&faultstorage.FaultSpec{
		Method: decoded.methodName, NthCall: decoded.nthCall, Kind: decoded.kind, Err: errFuzzInjected,
	})

	var result opResult
	var execErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic escaped the transport layer entirely for op %q (fault %s/%d/%s) — "+
					"the real Recovery middleware/RecoveryInterceptor should have converted this to "+
					"a 500/codes.Internal response, not let it unwind past Execute(): %v",
					op.Key, decoded.methodName, decoded.nthCall, decoded.kind, r)
			}
		}()
		result, execErr = op.Execute(ctx, w, state)
	}()
	if execErr != nil {
		// A transport-level Go error (connection reset, JSON encode failure in
		// our own test helper, etc.) — not itself an oracle finding, but worth
		// surfacing since fault injection should never break the CALLER's own
		// ability to make the request in the first place.
		t.Fatalf("op.Execute returned a transport error (not an application error) for op %q, fault %s/%d/%s: %v",
			op.Key, decoded.methodName, decoded.nthCall, decoded.kind, execErr)
	}

	if !w.faulty.Fired() {
		// NthCall exceeded the real call count for this method during
		// Execute — not interesting for this input, matches a legitimate
		// corner of the search space rather than a bug.
		return
	}

	// Same reasoning as the drain after Setup above: Execute's own request may
	// have dispatched a detached goSafe audit write (on a path that succeeded
	// before the faulted call, or on a success response for `op`) that hasn't
	// landed yet.
	drainAllBackgroundGoroutines()
	after, err := snapshotDB(w.db)
	if err != nil {
		t.Fatalf("snapshotting post-fault world: %v", err)
	}

	checkOracles(t, oracleInput{
		op: op.Key, method: decoded.methodName, nth: decoded.nthCall, kind: decoded.kind,
		result: result, before: before, after: after, refAfter: refAfter,
	})
}

type oracleInput struct {
	op, method string
	nth        int
	kind       faultstorage.FaultKind
	result     opResult
	before     dbSnapshot
	after      dbSnapshot
	refAfter   dbSnapshot
}

// knownOpenTolerance narrowly fingerprints one already-filed, not-yet-fixed
// finding so the fuzzer doesn't fail on it forever — but never drops it from
// the input space (RULES): decodeFuzzOp can still select this exact
// (op, method, kind) triple, checkOracles still runs every other oracle
// against it, and only the ONE specific violation this finding predicts is
// downgraded from Errorf to Logf. A fix landing that makes this tolerance
// stop matching is the intended way to notice the finding is closed — remove
// the entry then, don't leave it tolerating a bug that no longer exists.
type knownOpenTolerance struct {
	op, method string
	kind       faultstorage.FaultKind
	findingDoc string
}

// F3a and F3b (docs/findings/2026-09-21-FINDING-role-update-permission-replace-swallows-storage-errors.md)
// were tolerated here and are now fixed — core.UpdateRole runs the role
// update, permission replace, and audit inside one storage.WithTransaction
// (internal/core/rbac_roles.go). The fuzzer is now the regression test for
// both; no entries needed unless a new finding is filed.
var knownOpenTolerances = []knownOpenTolerance{}

func matchingKnownOpen(in oracleInput) *knownOpenTolerance {
	for i, k := range knownOpenTolerances {
		if k.op == in.op && k.method == in.method && k.kind == in.kind {
			return &knownOpenTolerances[i]
		}
	}
	return nil
}

// bestEffortTables maps a storage method this codebase deliberately calls
// best-effort (error explicitly discarded with `_ =`, with a comment saying
// so — internal/core/account.go:222, users.go:184, users.go:284, all three
// read "Best-effort: <the primary operation> has already succeeded") to the
// ONLY table(s) its own effect touches. This is narrower than a KNOWN-OPEN
// tolerance: it's not an undiscovered bug being tracked toward a fix, it's an
// intentional, already-documented design tradeoff (ADR-025's no-reuse check
// legitimately misses a password whose history-seed write failed) —
// STEP 2's "acceptable-by-design (exclusion with justification)" category,
// flagged for review rather than silently accepted.
//
// FLAG FOR REVIEW: is the password-reuse policy gap this creates (a user
// whose initial-password history-seed failed can immediately "change" back
// to that same password without ADR-025 catching it) acceptable, or should
// AddPasswordHistory's callers actually fail the request? Left as documented
// existing behavior, not changed here — this task's scope is atomicity
// bugs with no acknowledged tradeoff (F3a/F3b), not re-litigating an already
// deliberate one.
var bestEffortTables = map[string][]string{
	"AddPasswordHistory": {"PasswordHistory"},
	// LogAuditEvent: internal/core/service.go's emitAudit (the SINGLE choke
	// point every c.Log*/writeAuditEvent* helper funnels through) calls
	// c.storage.LogAuditEvent and, on failure, its own comment says so
	// explicitly: "Surface it loudly instead of swallowing" — loudly means a
	// log.Printf("SECURITY: failed to persist audit event ...") line, NOT an
	// error return; every c.Log* audit helper (LogRoleUpdated,
	// LogPermissionAssigned, etc.) has a bare `error`-less signature, so this
	// is a repo-wide, architectural guarantee that an audit-write failure
	// never fails the primary operation it's recording — not something
	// specific to UpdateRole or any other single caller. FLAG FOR REVIEW: the
	// comment itself already names the accepted gap ("A failed chain-write is
	// an audit gap that VerifyAuditChain cannot detect") — a SEPARATE,
	// already-existing subsystem's job, not something this task should
	// re-litigate.
	"LogAuditEvent": {"AuditEvent"},
	// CreateEnvironment: CreateProject/CreateProjectWithEnvs (internal/core/catalog.go)
	// seed a new project's default/requested environments in a loop after the
	// project row itself already committed, and treat a per-environment
	// failure as non-fatal — found live by a fuzz burst, which ALSO caught
	// that the "non-fatal; log and continue" comment on both loops discarded
	// the error with a bare `_ = err` instead of actually logging it (fixed
	// same PR: both now log.Printf a Warning naming the project and the
	// environment that failed to seed). The underlying "proceed without the
	// environment" behavior itself is unchanged and is the actual tradeoff
	// flagged here — a project can end up missing one or more expected
	// environments with only a log line, no caller-visible signal. FLAG FOR
	// REVIEW: should CreateProject instead report which environments seeded
	// successfully in its response, or fail the whole create? Left as
	// existing (now-observable) behavior, not decided here.
	"CreateEnvironment": {"Environment"},
}

// acceptableByDesign reports whether every table in diff is accounted for by
// method's own documented best-effort scope — i.e. the ONLY divergence from
// the reference run is the exact, single side effect the code already says
// it's willing to lose.
func acceptableByDesign(method string, diff []string) bool {
	allowed, ok := bestEffortTables[method]
	if !ok || len(diff) == 0 {
		return false
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, t := range allowed {
		allowedSet[t] = true
	}
	for _, d := range diff {
		if !allowedSet[d] {
			return false
		}
	}
	return true
}

// checkOracles applies GOAL's (a)-(e). (b) is checked structurally by the
// panic-recovery wrapper around op.Drive in the caller — a panic that DID get
// caught and converted to a failure response reaches here as
// result.Success==false, exactly like any other injected error, and oracle (a)
// covers it: a panic converted to success would be caught by the "success but
// state doesn't match the reference" branch.
func checkOracles(t *testing.T, in oracleInput) {
	t.Helper()
	label := fmt.Sprintf("op=%s fault=%s#%d/%s", in.op, in.method, in.nth, in.kind)

	report := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if known := matchingKnownOpen(in); known != nil {
			t.Logf("KNOWN-OPEN (%s): %s", known.findingDoc, msg)
			return
		}
		t.Errorf("%s", msg)
	}

	// Oracle (c): fail-closed authz. Checked FIRST and independently of (a) —
	// a fail-open bug can leave state that coincidentally matches the
	// reference run (the write happens anyway), which (a) alone would not flag.
	if authzReadMethods[in.method] && in.kind != faultstorage.KindEffectThenError && in.result.Success &&
		!nonLoadBearingAuthzRead(in.op, in.method, in.nth) {
		report("%s: ORACLE (c) VIOLATION — a fault on an authz-resolution read produced a SUCCESSFUL "+
			"result instead of an error/deny: %s", label, in.result.Detail)
		return
	}

	// Oracle (e): error hygiene — no secret plaintext in an error body.
	if !in.result.Success {
		for _, frag := range canaryFragments {
			if strings.Contains(in.result.Detail, frag) {
				report("%s: ORACLE (e) VIOLATION — error response leaked secret plaintext %q: %s",
					label, frag, in.result.Detail)
				return
			}
		}
	}

	// Oracle (a): atomicity.
	switch {
	case in.result.Success:
		if in.after.Hash != in.refAfter.Hash {
			diff := diffTables(in.refAfter, in.after)
			if acceptableByDesign(in.method, diff) {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges only in %v, which %s explicitly documents "+
					"as best-effort/non-fatal (see acceptableByDesign's doc comment)", label, diff, in.method)
				return
			}
			if opScopedAcceptableByDesign(in.op, in.method, diff) {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges only in %v, which this op/method pair "+
					"explicitly documents as best-effort/non-fatal (see opScopedBestEffortTables' doc comment)",
					label, diff)
				return
			}
			// Generalized AuditEvent-only case: every traced instance of
			// "reported SUCCESS, only AuditEvent differs" has turned out to
			// be benign audit-content degradation (a best-effort enrichment
			// prefetch failing, or LogAuditEvent itself failing — both
			// already-documented repo-wide non-fatal-by-design patterns, see
			// bestEffortTables/acceptableByDesign above) — never a real
			// business-state inconsistency. This is safe to accept
			// UNCONDITIONALLY here (not per-method) specifically because
			// oracle (c) above already ran first and would have caught the
			// dangerous case (a fault on an authz-resolution read producing
			// a false success) before execution ever reaches this branch.
			if len(diff) == 1 && diff[0] == "AuditEvent" {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges only in AuditEvent — oracle (c) already "+
					"ruled out a fail-open authz cause, and every traced instance of this shape has been "+
					"benign audit-content degradation, not a business-state inconsistency", label)
				return
			}
			report("%s: ORACLE (a) VIOLATION — reported SUCCESS but final state does not match the "+
				"fault-free reference run's state (partial/incorrect commit). Differing tables: %v",
				label, diff)
		}
	case in.kind == faultstorage.KindEffectThenError:
		// (d): ambiguous by design — old or new state both acceptable, just not
		// a mix. AuditEvent is compared separately, not folded into this check:
		// it legitimately records the REPORTED outcome (an error), which
		// diverges from a real success's audit row even when the underlying
		// resource state matches the "new" (effect-applied) state exactly —
		// that is the GOAL's own "model audit instead of dropping it" case,
		// not a partial/mixed commit of application state.
		nonAuditBefore := hashExcluding(in.before, "AuditEvent")
		nonAuditAfter := hashExcluding(in.after, "AuditEvent")
		nonAuditRef := hashExcluding(in.refAfter, "AuditEvent")
		if nonAuditAfter != nonAuditBefore && nonAuditAfter != nonAuditRef {
			if multiStepFirstCallAmbiguousCommit(in.op, in.method, in.nth) {
				t.Logf("FLAG FOR REVIEW (not auto-fixed, not silently accepted): %s: state matches neither "+
					"old nor new — see multiStepFirstCallAmbiguousCommit's doc comment for the traced "+
					"explanation (an ambiguous commit on the FIRST call of a multi-step create, which the "+
					"caller has no ID to compensate for, unlike the SECOND call's already-existing cleanup)",
					label)
				return
			}
			report("%s: ORACLE (d) VIOLATION — effect-then-error state matches NEITHER the pre-fault "+
				"state nor the fault-free reference state (a genuine partial/mixed commit, not just an "+
				"ambiguous-but-consistent one). Differing tables vs before: %v; vs reference: %v",
				label, diffTables(in.before, in.after), diffTables(in.refAfter, in.after))
		}
	default:
		if in.after.Hash != in.before.Hash {
			report("%s: ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway "+
				"(partial commit). Differing tables: %v", label, diffTables(in.before, in.after))
		}
	}
}

func diffTables(before, after dbSnapshot) []string {
	var diffs []string
	for name, b := range before.Tables {
		a := after.Tables[name]
		if a.Hash != b.Hash {
			diffs = append(diffs, name)
		}
	}
	return diffs
}

// hashExcluding recomputes a snapshot's overall hash with the named table(s)
// left out entirely — used for oracle (d), where AuditEvent legitimately
// records the REPORTED outcome rather than the actual storage effect.
func hashExcluding(snap dbSnapshot, excludeTables ...string) string {
	exclude := make(map[string]bool, len(excludeTables))
	for _, t := range excludeTables {
		exclude[t] = true
	}
	var lines []string
	for name, ts := range snap.Tables {
		if exclude[name] {
			continue
		}
		lines = append(lines, name+":"+ts.Hash)
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}
