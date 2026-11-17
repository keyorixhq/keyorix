package core

// FuzzScheduleInterleavings fuzzes the ORDER of concurrent operations on the
// core paths whose correctness depends on interleaving: PAT revoke vs validate,
// secret delete/update vs read, role grant/revoke vs authorize, and concurrent
// audit-chain appends. Unlike the existing stateful fuzzers, which run an
// operation sequence one op at a time, this one launches every selected
// operation in its own goroutine against ONE seeded store and lets the Go
// scheduler interleave them, nudged by a per-op runtime.Gosched() delay decoded
// from the fuzz input, and (in happens-before mode) by a start barrier that
// enforces a real "A returned before B started" edge.
//
// ORACLES (and, per the repo's "state what a mechanism does NOT verify" rule,
// what each explicitly does not check) are documented on each check* function
// below. The headline limits, true for every oracle here:
//
//   - SINGLE PROCESS ONLY. This harness drives one KeyorixCore over one
//     storage.Storage in one OS process. It exercises IN-PROCESS concurrency
//     (goroutines sharing one *gorm.DB, the in-process WithNamedLock table, the
//     audit flusher, the auth-cache invalidation callback). It does NOT and
//     cannot exercise the CROSS-REPLICA / multi-process races that Keyorix's
//     Postgres advisory locks and SELECT ... FOR UPDATE guard — those require
//     multiple independent *gorm.DB connections in separate processes (see the
//     repo's own standing lesson on this). A green run here is NOT evidence that
//     the cross-replica locks work; it is evidence the in-process path is
//     linearizable.
//   - On SQLite the pool is capped at one connection (a shared-schema
//     requirement of ":memory:"), so the DB layer itself serializes writers;
//     the teeth of the serial-equivalence oracle on SQLite are therefore in the
//     in-process core logic (named locks, cache invalidation, audit chaining),
//     not in DB-level write concurrency. Real DB-level write concurrency needs
//     the Postgres backend (KEYORIX_TEST_PG_DSN) — see the PG test alongside.
//
// The reference models in this file were pinned empirically against the real
// service before being written (double-revoke is idempotent-ok; delete of an
// already-deleted secret is not-found; grant of an already-held role is a
// conflict; revoke of an unheld role is not-found; secret reads/validate/
// authorize never emit an audit event; token and role mutations audit
// SYNCHRONOUSLY while secret create/update/delete audit via the ASYNC batched
// flusher). Any later change to those semantics must update the models here or
// this fuzzer will report false interleaving violations.

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ---------------------------------------------------------------------------
// Result classification
// ---------------------------------------------------------------------------

type resClass int

const (
	clUnknown    resClass = iota
	clOK                  // a write that succeeded, or a validate that authenticated
	clOKVal               // a read that returned a value (value carried in opResult.val)
	clNotFound            // positive "the target is not/no longer there"
	clConflict            // "already exists / already assigned"
	clRevoked             // PAT explicitly revoked
	clAuthzTrue           // authorize -> true
	clAuthzFalse          // authorize -> false
	clContention          // transient DB contention (serialization failure, lock timeout) — wildcard
	clError               // unexpected/unclassified error — the model never predicts this
)

func (c resClass) String() string {
	switch c {
	case clOK:
		return "ok"
	case clOKVal:
		return "okval"
	case clNotFound:
		return "notfound"
	case clConflict:
		return "conflict"
	case clRevoked:
		return "revoked"
	case clAuthzTrue:
		return "authz_true"
	case clAuthzFalse:
		return "authz_false"
	case clContention:
		return "contention"
	case clError:
		return "error"
	default:
		return "unknown"
	}
}

// looksLikeContention recognises the transient, retryable errors a real
// Postgres (or busy SQLite) connection pool can surface under write contention.
// Treating these as a wildcard in the serial-equivalence check keeps the oracle
// SOUND (a transient failure could legitimately occur in any serial position),
// at the cost of not asserting anything about an op that hit one. It does NOT
// cover application-level "denied/not-found/conflict" — those are real outcomes
// the model must explain.
func looksLikeContention(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, m := range []string{
		"database is locked", "database table is locked", "busy",
		"could not serialize", "serialization", "deadlock",
		"40001", "40p01", "context deadline exceeded", "canceling statement",
	} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func looksNotFound(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "not found") || strings.Contains(s, "not assigned")
}

// ---------------------------------------------------------------------------
// Program (decoded fuzz input)
// ---------------------------------------------------------------------------

const (
	dmPAT    = 0
	dmSecret = 1
	dmRole   = 2
	dmAudit  = 3
	dmCount  = 4
)

// op kinds (domain-scoped)
const (
	// PAT
	opValidate = iota
	opRevoke
	// Secret
	opRead
	opUpdate
	opDelete
	// Role
	opAuthorize
	opGrantRole
	opRevokeRole
	// Audit
	opAuditMutate
)

type schedOp struct {
	kind  int
	arg   int // update value index, or audit target index
	delay int // number of runtime.Gosched() before the real call
}

type schedProgram struct {
	domain int
	hb     bool // happens-before mode: ops[:split] fully return before ops[split:] start
	split  int
	ops    []schedOp
}

func b(data []byte, i int) byte {
	if i < len(data) {
		return data[i]
	}
	return 0
}

// decodeProgram turns fuzz bytes into a schedule. Deterministic and total
// (short/empty inputs decode to a valid minimal program).
func decodeProgram(data []byte) schedProgram {
	domain := int(b(data, 0)) % dmCount
	n := 2 + int(b(data, 1))%3 // 2..4
	hb := b(data, 2)&1 == 1
	ops := make([]schedOp, n)
	kinds := domainKinds(domain)
	for i := range ops {
		base := 3 + i*2
		ops[i] = schedOp{
			kind:  kinds[int(b(data, base))%len(kinds)],
			arg:   int(b(data, base+1)),
			delay: int(b(data, base)) % 8,
		}
	}
	split := 1
	if n > 1 {
		split = 1 + int(b(data, 3+n*2))%(n-1) // 1..n-1
	}
	return schedProgram{domain: domain, hb: hb, split: split, ops: ops}
}

func domainKinds(domain int) []int {
	switch domain {
	case dmPAT:
		return []int{opValidate, opRevoke}
	case dmSecret:
		return []int{opRead, opUpdate, opDelete}
	case dmRole:
		return []int{opAuthorize, opGrantRole, opRevokeRole}
	default: // dmAudit
		return []int{opAuditMutate}
	}
}

// ---------------------------------------------------------------------------
// World / fixture
// ---------------------------------------------------------------------------

type schedWorld struct {
	c       *KeyorixCore
	st      *store.LocalStorage
	db      *gorm.DB
	backend string
	adminID uint
	projID  uint
	envID   uint
	viewer  uint

	// uniq distinguishes fixtures created in the SAME store across reps (the
	// Postgres path reuses one bootstrapped store and seeds fresh entities per
	// rep instead of truncating tables). Empty for the fresh-per-iteration
	// SQLite fuzz loop.
	uniq string

	// per-domain fixture handles
	patPlain string
	patID    uint
	secretID uint
	carolID  uint
	auditPAT []patHandle // for dmAudit: one PAT per op
}

func (w *schedWorld) nm(base string) string { return base + w.uniq }

type patHandle struct {
	plain string
	id    uint
}

func mustBootstrap(tb testing.TB, db *gorm.DB, backend string) *schedWorld {
	tb.Helper()
	require.NoError(tb, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	require.NoError(tb, kxstorage.MigrateExisting(db))
	st := store.NewLocalStorage(db)
	c := NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")
	res, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(tb, err)
	w := &schedWorld{c: c, st: st, db: db, backend: backend, adminID: res.User.ID, projID: res.Project.ID}
	if len(res.Environments) > 0 {
		w.envID = res.Environments[0].ID
	}
	roles, err := st.ListRoles(context.Background())
	require.NoError(tb, err)
	for _, r := range roles {
		if r.Name == "viewer" {
			w.viewer = r.ID
		}
	}
	require.NotZero(tb, w.viewer)
	return w
}

func newSQLiteWorld(tb testing.TB) *schedWorld {
	tb.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(tb, err)
	sqlDB, err := db.DB()
	require.NoError(tb, err)
	sqlDB.SetMaxOpenConns(1)
	return mustBootstrap(tb, db, "sqlite")
}

// seedFixture builds the per-domain starting state. Returns the number of
// goroutine operations supported (for dmAudit we need one PAT per op).
func (w *schedWorld) seedFixture(ctx context.Context, prog schedProgram) {
	w.auditPAT = nil
	switch prog.domain {
	case dmPAT:
		pr, err := w.c.CreateOwnPAT(ctx, w.adminID, w.nm("pat-fixture"), nil, nil, 0, 0, nil)
		if err != nil {
			panic(fmt.Sprintf("seed PAT: %v", err))
		}
		w.patPlain, w.patID = pr.PlainToken, pr.Token.ID
	case dmSecret:
		sec, err := w.c.CreateSecret(ctx, &CreateSecretRequest{
			Name: w.nm("sched-secret"), Value: []byte("v0"), ProjectID: w.projID, EnvironmentID: w.envID,
			Type: "generic", CreatedBy: "admin", OwnerID: w.adminID,
		})
		if err != nil {
			panic(fmt.Sprintf("seed secret: %v", err))
		}
		w.secretID = sec.ID
	case dmRole:
		u, err := w.c.CreateUser(ctx, &CreateUserRequest{
			Username: w.nm("carol"), Email: w.nm("carol") + "@example.com",
			Password: "StrongPassphrase2026!", DisplayName: "C Person",
		})
		if err != nil {
			panic(fmt.Sprintf("seed user: %v", err))
		}
		w.carolID = u.ID
		if err := w.c.AssignUserRole(ctx, w.adminID, u.ID, w.viewer, Scope{}, false); err != nil {
			panic(fmt.Sprintf("seed grant: %v", err))
		}
	case dmAudit:
		for i := range prog.ops {
			pr, err := w.c.CreateOwnPAT(ctx, w.adminID, fmt.Sprintf("audit-pat-%s-%d", w.uniq, i), nil, nil, 0, 0, nil)
			if err != nil {
				panic(fmt.Sprintf("seed audit PAT: %v", err))
			}
			w.auditPAT = append(w.auditPAT, patHandle{pr.PlainToken, pr.Token.ID})
		}
	}
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

type opResult struct {
	class resClass
	val   string // for reads
	raw   error
}

// execOp runs one real operation and classifies the result.
func (w *schedWorld) execOp(ctx context.Context, prog schedProgram, idx int) opResult {
	o := prog.ops[idx]
	switch o.kind {
	case opValidate:
		_, _, _, _, err := w.c.ValidatePATToken(ctx, w.patPlain)
		switch {
		case err == nil:
			return opResult{class: clOK}
		case errors.Is(err, ErrPATRevoked):
			return opResult{class: clRevoked}
		case looksLikeContention(err):
			return opResult{class: clContention, raw: err}
		default:
			return opResult{class: clError, raw: err}
		}
	case opRevoke:
		_, err := w.c.RevokeOwnPAT(ctx, w.adminID, w.patID)
		return classifyWrite(err)
	case opRead:
		val, err := w.c.GetSecretValue(ctx, w.secretID)
		switch {
		case err == nil:
			return opResult{class: clOKVal, val: string(val)}
		case looksLikeContention(err):
			return opResult{class: clContention, raw: err}
		case looksNotFound(err):
			return opResult{class: clNotFound}
		default:
			return opResult{class: clError, raw: err}
		}
	case opUpdate:
		err := func() error {
			_, e := w.c.UpdateSecret(ctx, &UpdateSecretRequest{
				ID: w.secretID, Value: []byte(updateVal(o.arg)), UpdatedBy: "admin", UserID: w.adminID,
			})
			return e
		}()
		return classifyWrite(err)
	case opDelete:
		return classifyWrite(w.c.DeleteSecret(ctx, w.secretID))
	case opAuthorize:
		ok, err := w.c.Authorize(ctx, w.carolID, "secrets.read", Scope{})
		switch {
		case err != nil && looksLikeContention(err):
			return opResult{class: clContention, raw: err}
		case err != nil:
			return opResult{class: clError, raw: err}
		case ok:
			return opResult{class: clAuthzTrue}
		default:
			return opResult{class: clAuthzFalse}
		}
	case opGrantRole:
		err := w.c.AssignUserRole(ctx, w.adminID, w.carolID, w.viewer, Scope{}, false)
		return classifyWrite(err)
	case opRevokeRole:
		err := w.c.RemoveUserRole(ctx, w.adminID, w.carolID, w.viewer, Scope{})
		return classifyWrite(err)
	case opAuditMutate:
		h := w.auditPAT[idx]
		_, err := w.c.RevokeOwnPAT(ctx, w.adminID, h.id)
		return classifyWrite(err)
	}
	return opResult{class: clError, raw: fmt.Errorf("unknown op kind %d", o.kind)}
}

func classifyWrite(err error) opResult {
	switch {
	case err == nil:
		return opResult{class: clOK}
	case looksLikeContention(err):
		return opResult{class: clContention, raw: err}
	case strings.Contains(strings.ToLower(err.Error()), "already"):
		return opResult{class: clConflict}
	case looksNotFound(err) || isPositiveNotFound(err):
		return opResult{class: clNotFound}
	default:
		return opResult{class: clError, raw: err}
	}
}

func updateVal(arg int) string { return fmt.Sprintf("u%d", arg%4) }

// runSchedule launches every op in its own goroutine. In RACE mode all start
// together; in HB mode ops[:split] start, are awaited to full return, then
// ops[split:] start — a real happens-before edge. A 10s watchdog converts a
// hang into a test failure (oracle 4: no deadlock). Panics in op goroutines are
// captured and re-raised on the main goroutine (oracle 4: no panic).
func runSchedule(t *testing.T, w *schedWorld, prog schedProgram) []opResult {
	ctx := context.Background()
	n := len(prog.ops)
	results := make([]opResult, n)
	var panics []any
	var pmu sync.Mutex

	start := make([]chan struct{}, n)
	opDone := make([]chan struct{}, n) // closed by each goroutine AFTER it stores its result
	for i := range start {
		start[i] = make(chan struct{})
		opDone[i] = make(chan struct{})
	}
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range prog.ops {
		go func(idx int) {
			defer wg.Done()
			// opDone is closed on BOTH the normal and the panic path, so an HB
			// group-1 panic cannot wedge the group-2 release below.
			defer close(opDone[idx])
			defer func() {
				if r := recover(); r != nil {
					pmu.Lock()
					panics = append(panics, fmt.Sprintf("op %d (kind %d): %v", idx, prog.ops[idx].kind, r))
					pmu.Unlock()
				}
			}()
			<-start[idx]
			for k := 0; k < prog.ops[idx].delay; k++ {
				runtime.Gosched()
			}
			// The write to results[idx] happens-before close(opDone[idx]); every
			// reader either waits on opDone[idx] (HB sequencing) or on wg.Wait()
			// (final read), so there is no unsynchronised access to results.
			results[idx] = w.execOp(ctx, prog, idx)
		}(i)
	}

	done := make(chan struct{})
	go func() {
		if prog.hb && prog.domain != dmAudit {
			// Deterministic group sequencing: release group-1 starts, wait (via
			// their done channels — a real happens-before edge) until every
			// group-1 op has RETURNED, then release group 2.
			for i := 0; i < prog.split; i++ {
				close(start[i])
			}
			for i := 0; i < prog.split; i++ {
				<-opDone[i]
			}
			for i := prog.split; i < n; i++ {
				close(start[i])
			}
		} else {
			for i := range start {
				close(start[i])
			}
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("DEADLOCK: schedule did not complete in 10s (domain=%d hb=%v ops=%+v)", prog.domain, prog.hb, prog.ops)
	}

	pmu.Lock()
	defer pmu.Unlock()
	if len(panics) > 0 {
		t.Fatalf("PANIC in op goroutine(s): %v", panics)
	}
	return results
}

// ---------------------------------------------------------------------------
// Reference model + serial-equivalence oracle (oracle 1)
// ---------------------------------------------------------------------------

type modelState struct {
	// PAT
	revoked bool
	// Secret
	exists bool
	value  string
	// Role
	hasRole bool
}

func initialState(domain int) modelState {
	switch domain {
	case dmPAT:
		return modelState{revoked: false}
	case dmSecret:
		return modelState{exists: true, value: "v0"}
	case dmRole:
		return modelState{hasRole: true}
	}
	return modelState{}
}

// modelStep applies one op to the state and returns the result class it would
// produce in that position of a serial order. Faithful to the empirically
// pinned semantics (see file header).
func modelStep(domain int, s *modelState, o schedOp) opResult {
	switch o.kind {
	case opValidate:
		if s.revoked {
			return opResult{class: clRevoked}
		}
		return opResult{class: clOK}
	case opRevoke:
		s.revoked = true // idempotent-ok
		return opResult{class: clOK}
	case opRead:
		if s.exists {
			return opResult{class: clOKVal, val: s.value}
		}
		return opResult{class: clNotFound}
	case opUpdate:
		if s.exists {
			s.value = updateVal(o.arg)
			return opResult{class: clOK}
		}
		return opResult{class: clNotFound}
	case opDelete:
		if s.exists {
			s.exists = false
			return opResult{class: clOK}
		}
		return opResult{class: clNotFound}
	case opAuthorize:
		if s.hasRole {
			return opResult{class: clAuthzTrue}
		}
		return opResult{class: clAuthzFalse}
	case opGrantRole:
		if s.hasRole {
			return opResult{class: clConflict}
		}
		s.hasRole = true
		return opResult{class: clOK}
	case opRevokeRole:
		if s.hasRole {
			s.hasRole = false
			return opResult{class: clOK}
		}
		return opResult{class: clNotFound}
	}
	return opResult{class: clError}
}

// classMatches reports whether an observed op-result is consistent with a model
// prediction. clContention is a wildcard (matches anything); reads additionally
// require the value to match.
func classMatches(observed, model opResult) bool {
	if observed.class == clContention {
		return true
	}
	if observed.class != model.class {
		return false
	}
	if model.class == clOKVal {
		return observed.val == model.val
	}
	return true
}

// permutations yields every permutation of [0,n) honoring the HB constraint:
// in HB mode every index < split must precede every index >= split.
func permutations(n, split int, hb bool) [][]int {
	var out [][]int
	var rec func(cur []int, used []bool)
	rec = func(cur []int, used []bool) {
		if len(cur) == n {
			cp := make([]int, n)
			copy(cp, cur)
			out = append(out, cp)
			return
		}
		for i := range n {
			if used[i] {
				continue
			}
			if hb {
				// enforce: a group-2 index (>=split) may only be placed once all
				// group-1 indices (<split) are already in cur.
				if i >= split {
					ready := true
					for j := range split {
						if !used[j] {
							ready = false
							break
						}
					}
					if !ready {
						continue
					}
				}
			}
			used[i] = true
			rec(append(cur, i), used)
			used[i] = false
		}
	}
	rec(nil, make([]bool, n))
	return out
}

// checkSerialEquivalence (ORACLE 1) asserts the observed per-op result classes
// (and read values) and the observed final state are jointly reproducible by
// SOME serial order of the same operations from the same initial state,
// honoring any happens-before edge the schedule enforced.
//
// Does NOT verify: (a) anything about an op that returned clContention — those
// are wildcards, so a run in which every op contended proves nothing; (b)
// cross-replica ordering (single process only); (c) timing/fairness — only the
// final logical state and result classes, never latency; (d) the dmAudit
// domain, which uses independent targets and is checked by
// checkAuditCountAndChain instead.
func checkSerialEquivalence(prog schedProgram, observed []opResult, finalObserved modelState) error {
	if prog.domain == dmAudit {
		return nil
	}
	// A wholly-contended run carries no signal.
	anySignal := false
	for _, r := range observed {
		if r.class != clContention {
			anySignal = true
		}
		if r.class == clError {
			return fmt.Errorf("ORACLE1: op returned an UNCLASSIFIED error (model never predicts this): %v\nprog=%+v\nobserved=%s",
				r.raw, prog, fmtResults(observed))
		}
	}
	if !anySignal {
		return nil
	}
	n := len(prog.ops)
	for _, perm := range permutations(n, prog.split, prog.hb) {
		s := initialState(prog.domain)
		predicted := make([]opResult, n)
		for _, idx := range perm {
			predicted[idx] = modelStep(prog.domain, &s, prog.ops[idx])
		}
		if !allMatch(observed, predicted) {
			continue
		}
		if !finalStateMatches(prog.domain, s, finalObserved) {
			continue
		}
		return nil // witness found
	}
	return fmt.Errorf("ORACLE1 VIOLATION (non-serializable outcome): no serial order reproduces the observed results.\nprog=%+v\nobserved=%s\nfinal=%+v",
		prog, fmtResults(observed), finalObserved)
}

func allMatch(observed, predicted []opResult) bool {
	for i := range observed {
		if !classMatches(observed[i], predicted[i]) {
			return false
		}
	}
	return true
}

func finalStateMatches(domain int, model, observed modelState) bool {
	switch domain {
	case dmPAT:
		return model.revoked == observed.revoked
	case dmSecret:
		if model.exists != observed.exists {
			return false
		}
		if model.exists {
			return model.value == observed.value
		}
		return true
	case dmRole:
		return model.hasRole == observed.hasRole
	}
	return true
}

func fmtResults(rs []opResult) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = fmt.Sprintf("[%d]=%s(%q)", i, r.class, r.val)
	}
	return strings.Join(parts, " ")
}

// readFinalState reads the authoritative post-run state single-threaded.
func (w *schedWorld) readFinalState(ctx context.Context, domain int) modelState {
	switch domain {
	case dmPAT:
		_, _, _, _, err := w.c.ValidatePATToken(ctx, w.patPlain)
		return modelState{revoked: errors.Is(err, ErrPATRevoked)}
	case dmSecret:
		val, err := w.c.GetSecretValue(ctx, w.secretID)
		if err != nil {
			return modelState{exists: false}
		}
		return modelState{exists: true, value: string(val)}
	case dmRole:
		ok, _ := w.c.Authorize(ctx, w.carolID, "secrets.read", Scope{})
		return modelState{hasRole: ok}
	}
	return modelState{}
}

// ---------------------------------------------------------------------------
// Oracle 2: post-return visibility (revocation/deletion monotonicity)
// ---------------------------------------------------------------------------

// checkPostReturnVisibility (ORACLE 2) asserts that once a revoke/delete
// SUCCEEDED in group 1 (whose ops are guaranteed to have fully returned before
// any group-2 op started), no group-2 reader observes the pre-revoke/pre-delete
// value. Concretely: a revoked token never authenticates after Revoke returned;
// a deleted secret is never readable after Delete returned; a revoked role
// denies the next decision (when group 2 does not itself re-grant).
//
// Does NOT verify: visibility WITHOUT a happens-before edge (RACE mode is out of
// scope here — that is oracle 1's job); the non-monotone re-grant case for roles
// (if group 2 contains a grant, OR group 1 itself also contains a grant of the
// same role, the strict denial is intentionally skipped — a grant concurrent with
// the revoke in group 1 can commit last, legitimately leaving the role held, so
// authorize=true is then serializable and oracle 1, not oracle 2, is the judge);
// anything cross-process.
func checkPostReturnVisibility(prog schedProgram, observed []opResult) error {
	if !prog.hb || prog.domain == dmAudit {
		return nil
	}
	g1, g2 := prog.split, len(prog.ops)
	revokedG1, deletedG1, roleRevokedG1 := false, false, false
	for i := range g1 {
		if observed[i].class != clOK {
			continue
		}
		switch prog.ops[i].kind {
		case opRevoke:
			revokedG1 = true
		case opDelete:
			deletedG1 = true
		case opRevokeRole:
			roleRevokedG1 = true
		}
	}
	g2HasGrant := false
	for i := g1; i < g2; i++ {
		if prog.ops[i].kind == opGrantRole {
			g2HasGrant = true
		}
	}
	// A grantRole in group 1 is concurrent with the revokeRole(s) there (no HB
	// edge among group-1 ops): some legal serialization runs the grant last and
	// leaves the role HELD at the group-1/group-2 boundary. The role is therefore
	// not unambiguously revoked, so the strict "revoke denies the next decision"
	// assertion does not hold — oracle 1 (serial equivalence) already judges this
	// case. Mirror the g2HasGrant skip for the in-group-1 re-grant.
	g1HasGrant := false
	for i := range g1 {
		if prog.ops[i].kind == opGrantRole {
			g1HasGrant = true
		}
	}
	for i := g1; i < g2; i++ {
		o := observed[i]
		switch prog.ops[i].kind {
		case opValidate:
			if revokedG1 && o.class == clOK {
				return fmt.Errorf("ORACLE2 VIOLATION: PAT validated OK after a Revoke had returned.\nprog=%+v\nobserved=%s",
					prog, fmtResults(observed))
			}
		case opRead:
			if deletedG1 && o.class == clOKVal {
				return fmt.Errorf("ORACLE2 VIOLATION: secret read returned a value after a Delete had returned.\nprog=%+v\nobserved=%s",
					prog, fmtResults(observed))
			}
		case opUpdate:
			if deletedG1 && o.class == clOK {
				return fmt.Errorf("ORACLE2 VIOLATION: secret update succeeded after a Delete had returned.\nprog=%+v\nobserved=%s",
					prog, fmtResults(observed))
			}
		case opAuthorize:
			if roleRevokedG1 && !g1HasGrant && !g2HasGrant && o.class == clAuthzTrue {
				return fmt.Errorf("ORACLE2 VIOLATION: authorize=true after the role's Revoke had returned.\nprog=%+v\nobserved=%s",
					prog, fmtResults(observed))
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Oracle 3: audit chain integrity + per-op count
// ---------------------------------------------------------------------------

// drainAudit polls the chain until its chained-event count is stable across two
// reads (the audit flusher is asynchronous for some paths), bounded by the
// caller's watchdog budget. Returns the stable (chained, unchained, valid).
func (w *schedWorld) drainAudit(t *testing.T) (chained, unchained int64, valid bool) {
	ctx := context.Background()
	deadline := time.Now().Add(8 * time.Second)
	var last int64 = -1
	stableReads := 0
	for {
		v, err := w.st.VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		if v.ChainedEvents == last {
			stableReads++
			if stableReads >= 3 {
				return v.ChainedEvents, v.UnchainedEvents, v.Valid
			}
		} else {
			stableReads = 0
			last = v.ChainedEvents
		}
		if time.Now().After(deadline) {
			return v.ChainedEvents, v.UnchainedEvents, v.Valid
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// checkAuditChain (ORACLE 3, integrity half — ALWAYS ON) asserts the tamper-
// evidence hash chain still verifies after concurrent appends, and that no event
// escaped the chain (unchained count stays at its post-bootstrap baseline). This
// is the strong, red-proofable invariant: an append that bypasses the chain lock
// corrupts Valid or leaves an unchained row.
//
// Does NOT verify: the CONTENT of audit rows, actor attribution, or ordering
// relative to wall-clock — only that the SHA-256 prev/entry chain is intact.
func checkAuditChain(t *testing.T, w *schedWorld, baselineUnchained int64) (chainedNow int64, err error) {
	chained, unchained, valid := w.drainAudit(t)
	if !valid {
		return chained, fmt.Errorf("ORACLE3 VIOLATION: audit chain does not verify after concurrent appends")
	}
	if unchained != baselineUnchained {
		return chained, fmt.Errorf("ORACLE3 VIOLATION: %d event(s) escaped the hash chain (unchained baseline=%d now=%d)",
			unchained-baselineUnchained, baselineUnchained, unchained)
	}
	return chained, nil
}

// expectedSyncAudits counts the audit events a run is REQUIRED to have appended
// SYNCHRONOUSLY, from the observed result classes. Only the token/role mutations
// audit synchronously (verified empirically); secret create/update/delete audit
// via the async flusher and are therefore NOT counted here (documented gap).
func expectedSyncAudits(prog schedProgram, observed []opResult) (count int64, countable bool) {
	switch prog.domain {
	case dmPAT, dmRole, dmAudit:
		// synchronously audited domains: counted below
	default:
		return 0, false
	}
	for i, r := range observed {
		if r.class == clContention {
			return 0, false // ambiguous: can't assert an exact count
		}
		k := prog.ops[i].kind
		switch {
		case k == opRevoke && r.class == clOK:
			count++
		case k == opAuditMutate && r.class == clOK:
			count++
		case k == opGrantRole && r.class == clOK:
			count++
		case k == opRevokeRole && r.class == clOK:
			count++
		}
	}
	return count, true
}

// checkAuditCountAndChain (ORACLE 3, count half — token/role/audit domains only)
// asserts exactly one new chained event per successful synchronously-audited
// operation. For the secret domain only the integrity half runs (see
// expectedSyncAudits).
func checkAuditCountAndChain(t *testing.T, w *schedWorld, prog schedProgram, observed []opResult, baselineChained, baselineUnchained int64) error {
	chainedNow, err := checkAuditChain(t, w, baselineUnchained)
	if err != nil {
		return err
	}
	want, countable := expectedSyncAudits(prog, observed)
	if !countable {
		return nil
	}
	got := chainedNow - baselineChained
	if got != want {
		return fmt.Errorf("ORACLE3 VIOLATION: expected exactly %d new audit event(s) (one per successful op) but chain gained %d.\nprog=%+v\nobserved=%s",
			want, got, prog, fmtResults(observed))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Fuzz target
// ---------------------------------------------------------------------------

func seedCorpus(f *testing.F) {
	// A spread of domains, op counts, HB on/off. The decoder is total, so any
	// bytes are valid; these just prime coverage.
	seeds := [][]byte{
		{dmPAT, 1, 1, 0, 0, 1, 2, 0},           // validate || revoke (RACE)
		{dmPAT, 1, 0, 1, 0, 0, 1, 0},           // revoke -> validate (HB)
		{dmSecret, 2, 1, 1, 1, 2, 2, 0, 1, 0},  // update(1) || delete (RACE)
		{dmSecret, 2, 0, 4, 0, 1, 0, 0, 2},     // delete -> read (HB)
		{dmSecret, 1, 1, 1, 1, 1, 2},           // update || update
		{dmRole, 1, 1, 2, 0, 0, 1, 0},          // authorize || revoke (RACE)
		{dmRole, 1, 0, 2, 0, 0, 0, 0},          // revoke -> authorize (HB)
		{dmRole, 2, 1, 1, 0, 2, 0, 0, 0, 0, 0}, // grant || revoke
		{dmAudit, 2, 0, 0, 0, 0, 0, 0, 0},      // 4 concurrent audited revokes
		{dmAudit, 1, 0, 0, 0, 0, 0},            // 3 concurrent audited revokes
	}
	for _, s := range seeds {
		f.Add(s)
	}
}

func FuzzScheduleInterleavings(f *testing.F) {
	// Pin CPU parallelism low on this shared host even if the operator forgot
	// -cpu; GOMAXPROCS is process-global but the host wants <=2 here anyway.
	if runtime.GOMAXPROCS(0) > 2 {
		runtime.GOMAXPROCS(2)
	}
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		prog := decodeProgram(data)
		w := newSQLiteWorld(t)
		defer func() { _ = w.st.Close() }()
		runAndCheck(t, w, prog)
	})
}

// runAndCheck seeds the per-domain fixture (single-threaded), runs the
// concurrent schedule, then applies all four oracles. Shared by the SQLite fuzz
// loop and the Postgres replay test. The caller sets w.uniq when reusing one
// store across reps.
func runAndCheck(t *testing.T, w *schedWorld, prog schedProgram) {
	ctx := context.Background()
	w.seedFixture(ctx, prog)
	// Baseline audit counts AFTER the (single-threaded, deterministic) fixture,
	// so only the concurrent schedule's own events are counted.
	baseC, baseU, _ := w.drainAudit(t)

	observed := runSchedule(t, w, prog) // oracle 4 (deadlock/panic) inside
	final := w.readFinalState(ctx, prog.domain)

	if err := checkSerialEquivalence(prog, observed, final); err != nil { // oracle 1
		t.Fatal(err)
	}
	if err := checkPostReturnVisibility(prog, observed); err != nil { // oracle 2
		t.Fatal(err)
	}
	if err := checkAuditCountAndChain(t, w, prog, observed, baseC, baseU); err != nil { // oracle 3
		t.Fatal(err)
	}
}
