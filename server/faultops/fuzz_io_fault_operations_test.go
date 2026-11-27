package faultops

// fuzz_io_fault_operations_test.go: FuzzIOFaultOperations (FAULT-IO-1).
//
// FuzzStorageFaultOperations faults a storage METHOD (an error, a panic, an
// effect-then-error). This target faults a SQL STATEMENT or COMMIT beneath the
// storage layer (io_fault_pool_test.go), with the failure shapes a disk or a
// database connection really produces: ENOSPC, EIO, EIO after the write took
// effect, a dropped connection (a really terminated backend on PostgreSQL), a
// stalled write that hits its deadline, and a COMMIT whose acknowledgement is lost.
//
// The existing oracles (a)-(h) are reused unchanged through checkOraclesReporting:
// the faulted statement is attributed to the storage call it belongs to (method and
// ordinal), so every by-design rule and filed tolerance keeps meaning what it
// meant. A reported error maps to KindError, an outcome the caller cannot know to
// KindEffectThenError. What this adds beyond them, in the sound direction only:
//
//	R1 recovery: once the fault is lifted the audit chain still verifies, the
//	   connection pool is quiescent (no leaked or wedged connection), and the same
//	   operation can be run again without hanging, panicking or a transport error.
//	R2 a reported success keeps its audit event: success + no audit row at all, when
//	   the fault-free run of the same op writes one, is a lost audit event. Skipped
//	   when the faulted statement is itself an audit write (best-effort by design,
//	   see best_effort_tables_entry_logauditevent_test.go), for a sticky ENOSPC/EIO
//	   (it fails the audit write too) and for an op listed in knownUnauditedOperations.
//	R3 no canary (secret value) in any log line the operation wrote.
//	R4 a hang guard: the whole operation finishes within ioFaultInputDeadline.
//
// What it does NOT verify: the text of any error, a power cut or a torn page (that
// is scripts/powercut), a network partition between replicas, or the audit chain
// of a world whose faulted write was the audit row itself beyond "still verifies".
// A sticky ENOSPC/EIO also fails every later write (audit append, compensation,
// cleanup), so the single-fault state oracles are applied to it only for oracle (c)
// on a sticky EIO authz read; R1, R3 and R4 always are. They are not applied to a
// credential flow (login, MFA, WebAuthn, setup consume) at all: the #2880 by-design
// rows decide a faulted storage method, not a driver-level fault.
// A fault that lands on a different statement than predicted (a detached goroutine
// interleaving) is judged by the same oracles against the method it was attributed
// to; that costs precision, not soundness, because every oracle compares real state.

import (
	"context"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

const ioFaultInputDeadline = 30 * time.Second

type ioFaultInput struct {
	opIdx  int
	kind   ioFaultKind
	at     int
	sticky bool
}

// decodeIOFault: bytes 0-1 select the op, byte 2 the fault kind, byte 3 the
// 1-based statement (or COMMIT) ordinal within the operation, capped at 24, and
// bit 0 of byte 4 makes an ENOSPC/EIO fault sticky (see ioFault.sticky).
func decodeIOFault(data []byte) (ioFaultInput, bool) {
	if len(opCatalog) == 0 {
		return ioFaultInput{}, false
	}
	b := func(i int) int {
		if i < len(data) {
			return int(data[i])
		}
		return 0
	}
	return ioFaultInput{
		opIdx:  (b(0)<<8 | b(1)) % len(opCatalog),
		kind:   ioFaultKind(b(2) % int(numIOFaultKinds)),
		at:     1 + b(3)%24,
		sticky: b(4)&1 == 1,
	}, true
}

func ioSeed(opKey string, kind ioFaultKind, at int, sticky ...bool) []byte {
	var st byte
	if len(sticky) > 0 && sticky[0] {
		st = 1
	}
	for i, op := range opCatalog {
		if op.Key == opKey {
			return []byte{byte(i >> 8), byte(i), byte(kind), byte(at - 1), st}
		}
	}
	return nil
}

// ioFaultSeeds are chosen to reach real code: a multi-statement transactional
// write (secret create), an update, a delete and a role create, each with a
// statement fault in the transaction body and a COMMIT fault.
func ioFaultSeeds() [][]byte {
	var out [][]byte
	add := func(op string, k ioFaultKind, at int, sticky ...bool) {
		if s := ioSeed(op, k, at, sticky...); s != nil {
			out = append(out, s)
		}
	}
	add("REST POST /api/v1/secrets/", ioDiskFullBefore, 3)
	add("REST POST /api/v1/secrets/", ioDiskFullBefore, 1, true) // a full disk stays full
	add("REST POST /api/v1/secrets/", ioEIOBefore, 1, true)      // a failing disk fails every statement, fallback reads included
	add("REST POST /api/v1/secrets/", ioEIOAfter, 4)
	add("REST POST /api/v1/secrets/", ioConnDropBefore, 5)
	add("REST POST /api/v1/secrets/", ioSlowDeadline, 2)
	add("REST POST /api/v1/secrets/", ioCommitAckLost, 1)
	add("REST POST /api/v1/secrets/", ioCommitNeverArrived, 1)
	add("REST DELETE /api/v1/secrets/{id}", ioEIOBefore, 2)
	add("REST DELETE /api/v1/secrets/{id}", ioCommitAckLost, 1)
	add("REST PUT /api/v1/roles/{id}", ioDiskFullBefore, 4)
	add("REST PUT /api/v1/roles/{id}", ioCommitAckLost, 1)
	add("GRPC keyorix.v1.RoleService.CreateRole", ioEIOAfter, 3)
	// ops whose bookkeeping or audit sits in its own transaction after an external effect
	for _, op := range []string{
		"REST POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke",
		"REST POST /api/v1/dynamic-secrets/configs/{id}/revoke-all",
		"GRPC keyorix.v1.DynamicSecretService.RevokeLease",
		"GRPC keyorix.v1.DynamicSecretService.RevokeAllLeases",
		"REST POST /api/v1/projects/{id}/break-glass",
		"GRPC keyorix.v1.BreakGlassService.ActivateBreakGlass",
		"REST POST /api/v1/dynamic-secrets/configs/{id}/issue",
		"GRPC keyorix.v1.DynamicSecretService.IssueLease",
	} {
		for _, at := range []int{1, 2} {
			add(op, ioCommitNeverArrived, at)
			add(op, ioCommitAckLost, at)
		}
	}
	return out
}

func FuzzIOFaultOperations(f *testing.F) {
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatal(err)
	}
	for _, s := range ioFaultSeeds() {
		f.Add(s)
	}
	ref := buildReusableFaultWorld(f, nil)
	w := buildReusableFaultWorld(f, nil)
	pool := installIOFaultPool(f, w)
	f.Fuzz(func(t *testing.T, data []byte) {
		runIOFaultIteration(t, t, data, ref, w, pool, nil)
	})
}

// ioPlant is a deliberately planted defect, for the red proofs only.
type ioPlant struct {
	swallowWrites bool // report success for a write that hit a "before" fault
}

type ioOutcome struct {
	fired   bool
	attr    ioAttribution
	success bool
}

type ioExecOut struct {
	res      opResult
	err      error
	log      string
	panicked any
	timedOut bool
}

// execIOGuarded runs op.Execute with the log captured, a panic recovered and a
// deadline. A panic that escapes the transport layer is itself a finding.
func execIOGuarded(ctx context.Context, w *faultWorld, op operation, state any) ioExecOut {
	done := make(chan ioExecOut, 1)
	go func() {
		var out ioExecOut
		var buf lockedLogBuffer
		prev := log.Writer()
		log.SetOutput(&buf)
		defer func() {
			log.SetOutput(prev)
			out.log = buf.since(0)
			out.panicked = recover()
			done <- out
		}()
		out.res, out.err = op.Execute(ctx, w, state)
	}()
	select {
	case out := <-done:
		return out
	case <-time.After(ioFaultInputDeadline):
		return ioExecOut{timedOut: true}
	}
}

func runIOFaultIteration(t *testing.T, rep fuzzVerdict, data []byte, refW, w *faultWorld, pool *ioFaultPool, plant *ioPlant) ioOutcome {
	t.Helper()
	in, ok := decodeIOFault(data)
	if !ok {
		rep.Skip("empty op catalog")
	}
	op := opCatalog[in.opIdx]
	rep.Logf("input=%x -> op=%q io-fault=%s at=%d sticky=%v", data, op.Key, in.kind, in.at, in.sticky)
	ctx := context.Background()

	refW.resetForReuse(t, nil)
	refResult, refErr := runOp(ctx, refW, op)
	if refErr != nil || !refResult.Success {
		rep.Skipf("reference (fault-free) run itself failed, not a fault finding: %v %s", refErr, refResult.Detail)
	}
	drainAllBackgroundGoroutines()
	refAfter, err := snapshotDB(refW.db)
	if err != nil {
		rep.Fatalf("snapshotting reference world: %v", err)
	}

	w.resetForReuse(t, nil)
	var state any
	if op.Setup != nil {
		if state, err = op.Setup(ctx, w); err != nil {
			rep.Skipf("setup itself errored, not a fault finding: %v", err)
		}
	}
	drainAllBackgroundGoroutines()
	before, err := snapshotDB(w.db)
	if err != nil {
		rep.Fatalf("snapshotting pre-fault world: %v", err)
	}

	pool.swallow = plant != nil && plant.swallowWrites
	defer func() { pool.swallow = false }()
	pool.Arm(&ioFault{kind: in.kind, at: in.at, sticky: in.sticky})
	ex := execIOGuarded(ctx, w, op, state)
	fired, attr := pool.Fired()
	pool.Disarm()

	// R4: a hang is a finding whether or not the fault fired.
	if ex.timedOut {
		rep.Errorf("IO-FAULT R4 VIOLATION: op %q with %s at %d did not finish within %s (hang or wedged lock)", op.Key, in.kind, in.at, ioFaultInputDeadline)
		return ioOutcome{fired: fired, attr: attr}
	}
	if ex.panicked != nil {
		rep.Errorf("panic escaped the transport layer for op %q, io fault %s at %d: %v", op.Key, in.kind, in.at, ex.panicked)
		return ioOutcome{fired: fired, attr: attr}
	}
	if ex.err != nil {
		rep.Fatalf("op.Execute returned a transport error for op %q, io fault %s at %d: %v", op.Key, in.kind, in.at, ex.err)
	}
	out := ioOutcome{fired: fired, attr: attr, success: ex.res.Success}
	if !fired {
		return out // the op issues fewer statements than the ordinal: nothing to judge
	}

	drainAllBackgroundGoroutines()
	after, err := snapshotDB(w.db)
	if err != nil {
		rep.Fatalf("snapshotting post-fault world: %v", err)
	}
	label := fmt.Sprintf("op=%s io=%s@%d sticky=%v attributed=%s#%d", op.Key, in.kind, in.at, in.sticky, attr.method, attr.nth)

	rep.Logf("fired: %s success=%v stmt=%q", label, ex.res.Success, attr.sql)
	// Oracle (c) says a fault on an authz read must not yield a success. A ONE-SHOT
	// statement fault is legitimately absorbed by an in-method fallback
	// (ResolveUserPermissionAt answers through the classic reads when its combined
	// statement errors), so (c) is sound only for a sticky EIO, which fails the
	// fallback too. Otherwise the method name is neutralised for (c) alone; every
	// state oracle still runs.
	method := attr.method
	if authzReadMethods[method] && !(in.sticky && in.kind == ioEIOBefore) {
		method = "~" + method
	}
	// A sticky full or failing disk keeps failing every later write too: the op's own
	// audit append, and the compensation or cleanup writes (a released login-attempt
	// slot, a rolled-back step). The state oracles reason about ONE failing storage
	// call, so on such a run their verdict cannot be attributed to the faulted method
	// and they are not applied; what a sticky fault is for is oracle (c) on a sticky
	// EIO, which defeats the in-method fallback read, and R1, R3 and R4 (recovery,
	// canary, hang).
	stickyDisk := in.sticky && (in.kind == ioDiskFullBefore || in.kind == ioEIOBefore)
	// A credential flow (an op with a by-design row in oracleAByDesignErrors: login, MFA
	// verify, WebAuthn finish, setup consume). Those rows record the #2880 decision for
	// ONE faulted storage METHOD (a storage-level effect-then-error lands, an in-transaction
	// EIO-after or a lost COMMIT rolls the effect back), answered like a wrong credential.
	// What a driver-level fault of such a flow must answer is not decided, so the state
	// oracles are not applied to it (NEEDS DECISION, in the PR). R1, R3 and R4 are.
	credentialFlow := isCredentialFlowOp(op.Key)
	if credentialFlow {
		rep.Logf("%s: not judged by the state oracles: credential flow (no driver-level decision recorded)", label)
	}
	if !credentialFlow && (!stickyDisk || (in.kind == ioEIOBefore && authzReadMethods[attr.method])) {
		checkOraclesReporting(rep, oracleInput{
			op: op.Key, method: method, nth: attr.nth, kind: in.kind.storageKind(),
			result: ex.res, before: before, after: after, refAfter: refAfter, execLog: ex.log, world: w,
		})
	}

	// For a sticky disk fault the audit append of the op fails too, so "the faulted
	// statement is not an audit write" does not hold for R2.
	if !stickyDisk {
		for _, msg := range ioCheckSuccessHasAudit(op.Key, ex.res.Success, attr, before, after, refAfter) {
			rep.Errorf("%s: %s", label, msg)
		}
	}
	for _, msg := range ioCheckCanaryInLog(ex.log) {
		rep.Errorf("%s: %s", label, msg)
	}
	for _, msg := range ioCheckRecovery(ctx, w) {
		rep.Errorf("%s: %s", label, msg)
	}

	// R1, third part: the same operation again, fault lifted. It may succeed or
	// fail with an application error (the first attempt may have taken effect);
	// it must return, must not panic and must leave a quiescent pool.
	again := execIOGuarded(ctx, w, op, state)
	switch {
	case again.timedOut:
		rep.Errorf("%s: IO-FAULT R1 VIOLATION: the same operation hangs after the fault was lifted (wedged lock or connection)", label)
	case again.panicked != nil:
		rep.Errorf("%s: IO-FAULT R1 VIOLATION: the same operation panics after the fault was lifted: %v", label, again.panicked)
	case again.err != nil:
		rep.Errorf("%s: IO-FAULT R1 VIOLATION: the same operation returns a transport error after the fault was lifted: %v", label, again.err)
	default:
		drainAllBackgroundGoroutines()
		for _, msg := range ioCheckRecovery(ctx, w) {
			rep.Errorf("%s (after retry): %s", label, msg)
		}
		for _, msg := range ioCheckCanaryInLog(again.log) {
			rep.Errorf("%s (retry): %s", label, msg)
		}
	}
	return out
}

// isCredentialFlowOp reports whether op has a by-design row in oracleAByDesignErrors.
func isCredentialFlowOp(op string) bool {
	for _, e := range oracleAByDesignErrors {
		if e.op == op {
			return true
		}
	}
	return false
}

// ioCheckRecovery is R1: the audit chain verifies and the pool is quiescent.
func ioCheckRecovery(ctx context.Context, w *faultWorld) []string {
	var out []string
	v, err := w.core.VerifyAuditChain(ctx)
	switch {
	case err != nil:
		out = append(out, fmt.Sprintf("IO-FAULT R1 VIOLATION: VerifyAuditChain failed once the fault was lifted: %v", err))
	case !v.Valid:
		out = append(out, fmt.Sprintf("IO-FAULT R1 VIOLATION: the audit chain does not verify after the fault was lifted (first broken id=%v, chained=%d, unchained=%d)", v.FirstBrokenID, v.ChainedEvents, v.UnchainedEvents))
	}
	return append(out, ioCheckPoolQuiescent(w.db)...)
}

// ioCheckPoolQuiescent: no connection stays checked out once the operation and its
// detached goroutines are done. A leaked connection on a one-connection SQLite pool
// wedges the whole world; on PostgreSQL it eats the pool.
func ioCheckPoolQuiescent(db *gorm.DB) []string {
	sqlDB, err := db.DB()
	if err != nil {
		return []string{fmt.Sprintf("IO-FAULT R1 VIOLATION: no sql.DB behind the world: %v", err)}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		in := sqlDB.Stats().InUse
		if in == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return []string{fmt.Sprintf("IO-FAULT R1 VIOLATION: %d connection(s) still checked out 2s after the operation ended (leaked or wedged)", in)}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ioCheckSuccessHasAudit is R2.
func ioCheckSuccessHasAudit(opKey string, success bool, attr ioAttribution, before, after, refAfter dbSnapshot) []string {
	if !success || knownUnauditedOperations[opKey] || strings.Contains(strings.ToLower(attr.sql), "audit") || strings.Contains(attr.method, "Audit") {
		return nil
	}
	n := func(s dbSnapshot) int { return len(s.Tables["AuditEvent"].Rows) }
	if n(refAfter) > n(before) && n(after) <= n(before) {
		return []string{fmt.Sprintf("IO-FAULT R2 VIOLATION: the operation reported SUCCESS but wrote no audit event (the fault-free run writes %d, this run %d) although the faulted statement was %q, not an audit write",
			n(refAfter)-n(before), n(after)-n(before), attr.sql)}
	}
	return nil
}

// ioCheckCanaryInLog is R3. The error body is covered by oracle (e).
func ioCheckCanaryInLog(execLog string) []string {
	for _, frag := range canaryFragments {
		if strings.Contains(execLog, frag) {
			return []string{fmt.Sprintf("IO-FAULT R3 VIOLATION: a log line written during the operation contains the secret value %q", frag)}
		}
	}
	return nil
}
