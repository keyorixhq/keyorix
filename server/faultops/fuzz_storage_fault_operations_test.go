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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
	resthandlers "github.com/keyorixhq/keyorix/server/http/handlers"
	"github.com/stretchr/testify/assert"
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
// Empty as of 2026-09-23 (docs/findings/2026-09-23-FINDING-redundant-authz-prefetch.md):
// both entries this list ever held (REST DELETE /api/v1/secrets/{id},
// GetSecretAncestors/GetUserGroupRoleIDsAt, both NthCall=2) were the SAME root
// cause — DeleteSecret's audit-only prefetch called GetSecretWithPermissionCheck
// a second time after the route's RequireScopedSecretPermission middleware had
// already authorized the request, so CheckSecretPermission ran twice per
// request and a fault on that harmless second run looked like a fail-open
// oracle (c) violation. The fix replaced that (and its gRPC DeleteSecret and
// GetSecretVersions siblings) with a plain, unauthorized GetSecret — matching
// the pattern every OTHER audit-only prefetch in this codebase already used
// (UpdateSecret's pre-diff fetch, DeleteFolder, REST GetSecretVersions).
// CheckSecretPermission now runs exactly once per DeleteSecret request, so
// NthCall=2 never occurs for either method on this op — both exceptions are
// unreachable, not merely inactive, and were deleted rather than kept around
// unused. If a similar shape recurs, add a fresh entry with its own trace, not
// by reviving these.
type nonLoadBearingException struct {
	op, method string
	nth        int
}

var nonLoadBearingAuthzReadExceptions = []nonLoadBearingException{}

// multiStepAmbiguousCommitExceptions narrowly flags a traced instance of
// oracle (d) firing on the FIRST storage call of a multi-step create, NOT
// because it's decided safe (unlike bestEffortTables/nonLoadBearingAuthzRead,
// this is NOT auto-accepted as fine) but because forcing a decision here
// (fix vs. accept) needs a product call this task should not make
// unilaterally.
//
// Empty as of fix/create-ops-atomicity
// (docs/findings/2026-09-23-FINDING-create-ops-ambiguous-commit-mixed-state.md):
// both entries this list ever held — CreateSecret and CreateUser, NthCall=1 —
// are now fixed by wrapping each operation's full multi-step sequence in one
// storage.WithTransaction, closing the MIXED-STATE half of the gap (a fault
// now rolls back cleanly to old state, or the real effect lands as full new
// state — never a mix). The AMBIGUOUS-RESPONSE half (the client still can't
// tell "failed" apart from "succeeded, ack lost") is intentionally NOT closed
// by this list being empty — see the deferred, unnumbered ADR outline
// (docs/adr-draft-request-idempotency-for-create-operations.md) for that.
// FuzzStorageFaultOperations is the regression test for both fixed sites now;
// if this list gains an entry again, add a docs/findings-style trace exactly
// like the one this replaces, not a bare tuple.
var multiStepAmbiguousCommitExceptions = []nonLoadBearingException{}

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
//
// REST POST /api/v1/users/, GetRoleByName: an incomplete-enumeration sibling
// of the entry directly above, found live triaging the
// fix/breakglass-revoke-atomicity PR's own out-of-scope fuzz observation
// (2026-09-23). CreateUser's non-fatal system_viewer grant
// (internal/core/users.go, inside the savepoint at the WithTransaction call
// around line 201) makes TWO storage calls before either can fail —
// GetRoleByName THEN AssignRole — and the entry above only named the second
// one. Faulting GetRoleByName produces the byte-for-byte identical
// UserRole-only divergence (role lookup fails, so AssignRole is never even
// reached, but the user is still created and the failure is still logged) —
// same code path, same accepted tradeoff, just a different one of its two
// calls. Confirmed this scoping is still safe, not a blanket suppression:
// GetRoleByName is called exactly once during CreateUser (the only
// opCatalog["CreateUser"] entry point for this op), and this codebase's
// OTHER two GetRoleByName call sites (CreateUserWithAssignments,
// resolveProjectRoleGrant) are unreachable from plain CreateUser, so this
// entry cannot mask a fault on a load-bearing GetRoleByName call the way a
// method-only bestEffortTables entry would risk.
//
// REST POST /api/v1/projects, WithTransaction: CreateProject
// (internal/core/catalog.go) wraps the project-row create and its default-
// environment seeding in one outer WithTransaction, with EACH environment
// seeded via its own NESTED tx.WithTransaction (a SAVEPOINT) — deliberately,
// per that function's own extensive comment: a per-environment seeding
// failure is caught, logged ("created without its environment ...:
// %v"), and non-fatal by design, so the project itself still commits. Found
// live: FuzzStorageFaultOperations op="REST POST /api/v1/projects"
// fault=WithTransaction#4/error (CI, PR #2252) — NthCall=4 lands on one of
// the per-environment SAVEPOINT calls (call #1 is the outer wrap; #2+ are
// one per defaultEnvironmentNames entry), producing exactly the documented
// "committed project, missing one environment" state and nothing else. Not a
// blanket suppression of WithTransaction faults for this op: a fault on call
// #1 (the OUTER transaction) rolls back the whole create and the op reports
// FAILURE, never reaching this success-branch check at all — only an INNER,
// per-environment SAVEPOINT fault can produce a reported SUCCESS with an
// Environment-only diff, and that is precisely the case this function's own
// comment already documents as accepted. minNthCall: 2 makes this explicit
// rather than relying only on the implicit "call #1 always fails the op"
// argument above (coordinator review, PR #2252 split-out): a fault on call #1
// is asserted to report FAILURE elsewhere in this function (the `in.result.
// Success` branch above never reaches this check on that path), but pinning
// the restriction here too means a regression in that assumption gets caught
// by TestOpScopedAcceptableByDesign_ProjectWithTransaction_RequiresNthCallTwo
// directly, not silently masked by this exemption.
//
// AuditEvent joined this entry's tables (item 4 of the UX-fixes batch,
// alongside CreateEnvironment's identical addition above): the per-
// environment seed failure this entry already accepted now also writes an
// EventProjectEnvironmentSeedFailed row, closing the "no caller-visible
// signal" half of the original gap — the missing environment is still
// non-fatal by design, but it is now DISCOVERABLE via the audit trail
// instead of only a server log line.
//
// requireLogSubstring (session-M follow-up, inbox/CORE.md's "2026-09-30
// session-m" entry): minNthCall alone rules out the OUTER transaction fault,
// but says nothing about WHETHER the per-environment seeding actually hit the
// documented best-effort path — a diff of exactly [Environment] with
// NthCall>=2 is also the shape a SILENT bug (env seeding skipped with no
// warning logged) would produce, and that shape must not be waved through
// just because it resembles the accepted tradeoff. Requiring the warning
// substring to actually appear in the op's own captured log output (see
// execLog on oracleInput, populated from stdlib log output captured around
// op.Execute) ties the exemption to evidence the known, reviewed code path
// fired, not to the table-diff shape alone. Silent missing envs stay a
// violation.
//
// #2406: unlike every other entry here, these 4 are consulted from the
// default: (plain-error) branch of checkOracles' oracle (a), not just the
// success branch -- core.RevokeLease performs an EXTERNAL, irreversible
// side effect (engine.Revoke drops the credential on the real target) that
// cannot be tied to the SAME transaction as its own bookkeeping writes.
// Once that drop succeeds, the lease row MUST end up marked "revoked" --
// claiming otherwise (leaving it "active") would be a worse lie in the
// other direction, implying a dead credential is still live. If the
// FOLLOW-ON audit write then fails, RevokeLease correctly returns an error
// (closing #2406: callers must not see a clean, unconditional success) --
// but the DynamicSecretLease/AuditEvent state has still legitimately moved
// relative to before the call, exactly the shape the default: branch's
// blanket "error implies zero state change" assumption doesn't hold for.
// See RevokeLease's own #2406 doc comment (dynamic_secrets.go) for the
// full design. All 4 entries reach the identical core.RevokeLease /
// RevokeLeasesForConfig code path.
var opScopedBestEffortTables = []struct {
	op, method string
	tables     []string
	// minNthCall restricts this exemption to fault injections at or after this
	// 1-indexed call number; 0 means unrestricted (every pre-existing entry's
	// behavior, unchanged).
	minNthCall int
	// requireLogSubstring, when non-empty, additionally requires this exact
	// substring to appear in the op's captured log output (execLog) for this
	// exemption to apply. Empty (the zero value, every pre-existing entry)
	// means no log-evidence check — unchanged behavior for those entries.
	requireLogSubstring string
}{
	{op: "REST POST /api/v1/users/", method: "AssignRole", tables: []string{"UserRole"}},
	{op: "REST POST /api/v1/users/", method: "GetRoleByName", tables: []string{"UserRole"}},
	// REST POST /api/v1/auth/mfa/disable, DeleteSessionsForUserExcept:
	// DisableMFA's own comment ("Best-effort: disable must not fail on a
	// cleanup error.") explicitly discards deleteSessionsForUserAndEvict's
	// error after MFA is already flipped off and the secret/recovery codes
	// already deleted (internal/core/mfa.go, `_ =
	// c.deleteSessionsForUserAndEvict(ctx, userID, 0, "")`) — the security
	// downgrade purging sessions is the control; a purge failure here must
	// not report an already-successful MFA disable as failed. Found live by
	// FuzzStorageFaultOperations (this PR's own newly-wired op). Scoped to
	// this op, not a blanket bestEffortTables entry keyed by method name,
	// since DeleteSessionsForUserExcept IS load-bearing at other call sites
	// (RevokeUserSessions propagates its error as "failed to revoke
	// sessions").
	{op: "REST POST /api/v1/auth/mfa/disable", method: "DeleteSessionsForUserExcept", tables: []string{"Session"}},
	{
		op: "REST POST /api/v1/projects", method: "WithTransaction", tables: []string{"Environment", "AuditEvent"},
		minNthCall:          2,
		requireLogSubstring: "created without its environment",
	},
	// MigrateUserToMachine (internal/core/migrate_user_to_machine.go) deliberately
	// returns the already-created machine identity ALONGSIDE a non-nil error when
	// GetRolePermissions fails after the identity row committed — the function's
	// own doc comment (lines 64-67) says so explicitly: "The identity exists;
	// report the partial state..." rather than attempt a compensating delete.
	// This is the default-branch (reported-error) analogue of bestEffortTables'
	// AddPasswordHistory entry: a documented, intentional "committed anyway, told
	// the caller" tradeoff, not a bug. Found live: FuzzStorageFaultOperations
	// (REST POST /api/v1/projects/{id}/machine-identities/migrate-from-user,
	// fault=GetRolePermissions#1/error), Session CR round 2.
	{op: "REST POST /api/v1/projects/{id}/machine-identities/migrate-from-user", method: "GetRolePermissions", tables: []string{"AuditEvent", "MachineIdentity"}},
	// FIX-2 (#2812): the SECOND fault that lands on that same documented branch.
	// SuspendUser's own storage write is SetAccountState, so faulting it at call
	// #1 reaches the identical `return m, fmt.Errorf("machine identity %d
	// created but failed to suspend source user %d: ...")` line the entry above
	// exists for -- same op, same tradeoff, same two tables, different method on
	// the way in. Found live by FuzzStorageFaultOperations (shard 0) on PR #2804,
	// a PR with zero production-code changes, and confirmed pre-existing on
	// origin/main @ cbb9863e via REPLAY_HEX=3b6362.
	//
	// Deliberately an opScopedBestEffortTables entry, NOT a knownOpenTolerances
	// one: a tolerance asserts "open bug, expires on <date>", and this is not a
	// bug. The user row is never half-written -- the entire diff is the identity
	// the code chose to keep, and the error names its ID so the caller can
	// finish the job. Oracle (a) permits "nothing committed OR the caller needs
	// no new ID to clean anything up" (#2449's own wording); this satisfies the
	// second clause and fails the oracle only because the oracle cannot
	// recognise an informative partial success. Scoped to these two tables, so
	// the oracle still fails if anything ELSE diverges -- a genuinely
	// half-applied suspension (a User/Session/AuditCheckpoint row) would still
	// be caught, which is the property worth keeping.
	//
	// #2812 stays open for the broader #2549 question (whether to build a
	// general declared-exemption mechanism that also asserts the error text
	// still carries the recoverable ID); this entry stops CI failing on a
	// documented behaviour in the meantime.
	{op: "REST POST /api/v1/projects/{id}/machine-identities/migrate-from-user", method: "SetAccountState", tables: []string{"AuditEvent", "MachineIdentity"}},
	{op: "REST POST /api/v1/dynamic-secrets/configs/{id}/revoke-all", method: "LogAuditEvent", tables: []string{"DynamicSecretLease", "AuditEvent"}},
	{op: "REST POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke", method: "LogAuditEvent", tables: []string{"DynamicSecretLease", "AuditEvent"}},
	{op: "GRPC keyorix.v1.DynamicSecretService.RevokeLease", method: "LogAuditEvent", tables: []string{"DynamicSecretLease", "AuditEvent"}},
	{op: "GRPC keyorix.v1.DynamicSecretService.RevokeAllLeases", method: "LogAuditEvent", tables: []string{"DynamicSecretLease", "AuditEvent"}},
}

func opScopedAcceptableByDesign(op, method string, nth int, diff []string, execLog string) bool {
	for _, e := range opScopedBestEffortTables {
		if e.op != op || e.method != method {
			continue
		}
		if e.minNthCall > 0 && nth < e.minNthCall {
			continue
		}
		if e.requireLogSubstring != "" && !strings.Contains(execLog, e.requireLogSubstring) {
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

// effectThenErrorExtraExclusions narrows oracle (d)'s outcomeLogTables
// exclusion further for a SPECIFIC (op, method) pair whose effect-then-error
// mixed-state diff includes an already-documented, already-best-effort
// DOWNSTREAM side effect of the faulted call -- not a load-bearing part of
// the primary mutation. Unlike outcomeLogTables (which is a blanket,
// method-independent exclusion), each entry here names the exact call site
// so a future genuinely-load-bearing table added to the same op/method pair
// is not silently swallowed by a too-broad exclusion.
//
// GRPC keyorix.v1.UserService.CreateUser, CreateUserWithRoleGrants: found live
// by FuzzStorageFaultOperations, op="GRPC keyorix.v1.UserService.CreateUser"
// fault=CreateUserWithRoleGrants#1/effect-then-error -- ORACLE (d) VIOLATION,
// differing tables vs before: [User UserRole] (both match the real, committed
// NEW state -- CreateUserWithRoleGrants already wraps the user row and every
// role-grant row in one storage.WithTransaction, internal/storage/store/
// local_users.go:84, so there is no partial-role-grants scenario here); vs
// reference: [AuditEvent PasswordHistory] (AuditEvent already excluded by
// outcomeLogTables above; PasswordHistory is the remaining divergence).
// internal/core/users.go's own comment names PasswordHistory's seed as
// "Best-effort password-history seed, after the atomic create (ADR-025)",
// and bestEffortTables["AddPasswordHistory"] = {"PasswordHistory"} already
// documents this exact tradeoff for oracle (a) -- this entry extends the
// SAME already-accepted tradeoff to oracle (d) rather than asserting a new
// one. Coordinator review requested on this exclusion specifically (Session
// CR round 2 PR body) per the "never widen a carve-out without flagging it"
// rule -- not silently assumed correct.
//
// #2410/#2406: the four GRPC/REST revoke-lease routes under
// fault=LogAuditEvent#1/effect-then-error use `columns`, not `tables` --
// found live, CI input cf013c0032 on GRPC RevokeAllLeases: ORACLE (d)
// VIOLATION, differing tables vs before AND vs reference: [AuditEvent
// DynamicSecretLease]. AuditEvent is already excluded by outcomeLogTables.
// Unlike CreateUserWithRoleGrants's PasswordHistory above, DynamicSecretLease
// is NOT fully divergent -- core.RevokeLease (dynamic_secrets.go) always marks
// the lease `revoked` (the external credential drop already happened and is
// irreversible), and ONLY when the follow-on audit write then fails does it
// additionally stamp DynamicSecretLease.RevokeError with that failure's own
// message, in the SAME row update -- see RevokeLease's own #2406 doc comment.
// The reference (fault-free) run never sets RevokeError, so that is the ONE
// column that legitimately differs; every other DynamicSecretLease column
// (Revoked, RevokedAt, LeaseID, ...) must still match both the pre-fault AND
// reference state exactly. A whole-table exclusion here (the `tables` field)
// would also hide a lease left "active" when it should be "revoked" -- the
// exact mixed-state bug oracle (d) exists to catch -- so this must be
// column-scoped. See TestEffectThenErrorColumnExclusion_RedOnOtherColumnChange
// in this file's own test for the direct proof that a change to any OTHER
// DynamicSecretLease column is still caught.
var effectThenErrorExtraExclusions = []struct {
	op, method string
	tables     []string
	// columns narrows one table to a column-level exclusion instead of
	// removing it from the comparison entirely (see hashExcludingColumns):
	// key is the table name, value is the column(s) stripped from every row
	// of that table before it's hashed. A table named here does NOT also need
	// to be named in `tables` -- the two are independent, applied together.
	columns map[string][]string
}{
	{op: "GRPC keyorix.v1.UserService.CreateUser", method: "CreateUserWithRoleGrants", tables: []string{"PasswordHistory"}},
	{op: "REST POST /api/v1/dynamic-secrets/configs/{id}/revoke-all", method: "LogAuditEvent", columns: map[string][]string{"DynamicSecretLease": {"RevokeError"}}},
	{op: "REST POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke", method: "LogAuditEvent", columns: map[string][]string{"DynamicSecretLease": {"RevokeError"}}},
	{op: "GRPC keyorix.v1.DynamicSecretService.RevokeLease", method: "LogAuditEvent", columns: map[string][]string{"DynamicSecretLease": {"RevokeError"}}},
	{op: "GRPC keyorix.v1.DynamicSecretService.RevokeAllLeases", method: "LogAuditEvent", columns: map[string][]string{"DynamicSecretLease": {"RevokeError"}}},
}

func effectThenErrorExtraExcludedTables(op, method string) []string {
	for _, e := range effectThenErrorExtraExclusions {
		if e.op == op && e.method == method {
			return e.tables
		}
	}
	return nil
}

func effectThenErrorExtraExcludedColumns(op, method string) map[string][]string {
	for _, e := range effectThenErrorExtraExclusions {
		if e.op == op && e.method == method {
			return e.columns
		}
	}
	return nil
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
	// Oracle false-positive regression (TokenPrefix): a fired fault that the op
	// tolerates by design (here the auth middleware's documented skip-on-error
	// account-state re-read) reports success, so oracle (a) compares against the
	// independently-bootstrapped reference world -- whose setup minted its own
	// random machine token. TokenPrefix must be presence-only, like TokenHash.
	if s := seedFor("REST DELETE /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}", "GetUser", 1, 0); s != nil {
		f.Add(s)
	}
	// #2354: a post-commit GetRole read-back faulted with an error after
	// CreateRole's transaction had already committed the Role, RolePermission
	// and AuditEvent rows -- oracle (a) violation (REPLAY_HEX=58e803). Same
	// class as F3 above but on the create path, not update.
	if s := seedFor("GRPC keyorix.v1.RoleService.CreateRole", "GetRole", 1, 0); s != nil {
		f.Add(s)
	}
	// Per-worker world reuse (M5): each `go test -fuzz` worker is a separate
	// OS process (see world_reuse_test.go's doc comment), so building ref/w
	// ONCE here, before f.Fuzz, is naturally scoped to one worker -- no
	// cross-worker contention. resetForReuse restores each world to the same
	// logical starting state a fresh newFaultWorld(t, nil) would produce
	// before every input, without rebuilding the DB schema or HTTP/gRPC
	// servers from scratch each time. Proven equivalent to the pre-reuse
	// fresh-per-input behaviour by TestWorldReuseSoundness, whose own
	// red-proof (TestWorldReuseSoundness_CatchesPlantedStateLeak) confirms
	// the comparison actually fails on a planted state-leak bug.
	ref := buildReusableFaultWorld(f, nil)
	w := buildReusableFaultWorld(f, nil)
	f.Fuzz(func(t *testing.T, data []byte) {
		runOneFuzzIterationWithWorlds(t, data, ref, w, nil)
	})
}

// runOneFuzzIteration is the fuzz body, factored out so replay_test.go's
// TestReplayStorageFaultInput can run the identical logic against one
// specific saved input outside of f.Fuzz.
func runOneFuzzIteration(t *testing.T, data []byte) {
	t.Helper()
	runOneFuzzIterationWithWorlds(t, data, nil, nil, nil)
}

// runOneFuzzIterationWithWorlds is runOneFuzzIteration with the world pair
// pluggable: reusedRef/reusedW nil (every existing caller) builds a fresh
// world exactly as before -- zero behaviour change. Non-nil (Session M's
// world-reuse soundness gate, world_reuse_soundness_test.go, and the
// reuse-enabled fuzz loop once the gate passes) resets the given world
// in place via resetForReuse instead of building a new one.
func runOneFuzzIterationWithWorlds(t *testing.T, data []byte, reusedRef, reusedW *faultWorld, observe func(oracleInput)) {
	t.Helper()
	runOneFuzzIterationReporting(t, t, data, reusedRef, reusedW, observe)
}

// runOneFuzzIterationReporting is runOneFuzzIterationWithWorlds with the VERDICT
// reporting split out from the *testing.T that owns the test's resources.
//
// rep receives everything the harness concludes about this iteration — the
// decoded-op trace line, a skip when the fault-free reference run or Setup
// errored, a fatal when a snapshot failed, and every oracle violation. t is
// still the real *testing.T and is used only for building worlds (TempDir,
// Cleanup, and newFaultWorld's own Fatalf on infrastructure failure), which must
// take the whole test down rather than be recorded as one row's inconclusive
// result.
//
// Every normal caller passes t for both, so nothing changes for them. The one
// caller that does not is driveFaultCase, which passes a driveSink — see
// drive_sink_test.go for why routing Skip/Fatal through the caller's own
// *testing.T made both staleness checks pass while checking nothing.
func runOneFuzzIterationReporting(t *testing.T, rep fuzzVerdict, data []byte, reusedRef, reusedW *faultWorld, observe func(oracleInput)) {
	t.Helper()
	rep.Log(traceFuzzOp(data)) // RULES: print the decoded operation/fault as a readable line, every run.

	decoded, ok := decodeFuzzOp(data)
	if !ok {
		rep.Skip("empty catalog/method list")
	}
	op := opCatalog[decoded.opIndex]
	ctx := context.Background()

	// Reference: same operation, fully unfaulted, fresh world — the
	// expected post-state a legitimate success must match (oracle (a)).
	ref := reusedRef
	if ref == nil {
		ref = newFaultWorld(t, nil)
	} else {
		ref.resetForReuse(t, nil)
	}
	refResult, refErr := runOp(ctx, ref, op)
	if refErr != nil {
		rep.Skipf("reference (fault-free) run itself errored — not a fault-injection finding: %v", refErr)
	}
	if !refResult.Success {
		rep.Skipf("reference (fault-free) run itself failed — not a fault-injection finding: %s", refResult.Detail)
	}
	// Same goSafe race as below: runOp's Setup+Execute may have dispatched a
	// detached audit write that hasn't landed by the time we snapshot.
	drainAllBackgroundGoroutines()
	refAfter, err := snapshotDB(ref.db)
	if err != nil {
		rep.Fatalf("snapshotting reference world: %v", err)
	}

	// Fault world: Setup runs UNFAULTED (spec nil at construction), so
	// NthCall below counts only Execute's own calls, and `before` reflects
	// post-setup state rather than the pristine pre-setup world.
	w := reusedW
	if w == nil {
		w = newFaultWorld(t, nil)
	} else {
		w.resetForReuse(t, nil)
	}
	var state any
	if op.Setup != nil {
		state, err = op.Setup(ctx, w)
		if err != nil {
			rep.Skipf("setup itself errored — not a fault-injection finding: %v", err)
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
		rep.Fatalf("snapshotting pre-fault (post-setup) world: %v", err)
	}

	w.faulty.Arm(&faultstorage.FaultSpec{
		Method: decoded.methodName, NthCall: decoded.nthCall, Kind: decoded.kind, Err: errFuzzInjected,
	})

	var result opResult
	var execErr error
	var execLog string
	func() {
		// Capture the standard logger's output for the duration of Execute only
		// — narrowly scoped to "this iteration", per opScopedBestEffortTables'
		// requireLogSubstring: evidence must come from THIS call, not from
		// Setup or an earlier/later iteration's output. Same redirect pattern
		// as internal/core's captureLog helper (audit_write_failure_test.go).
		var logBuf bytes.Buffer
		prevOut := log.Writer()
		log.SetOutput(&logBuf)
		defer func() {
			log.SetOutput(prevOut)
			execLog = logBuf.String()
			if r := recover(); r != nil {
				rep.Errorf("panic escaped the transport layer entirely for op %q (fault %s/%d/%s) — "+
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
		rep.Fatalf("op.Execute returned a transport error (not an application error) for op %q, fault %s/%d/%s: %v",
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
		rep.Fatalf("snapshotting post-fault world: %v", err)
	}

	oi := oracleInput{
		op: op.Key, method: decoded.methodName, nth: decoded.nthCall, kind: decoded.kind,
		result: result, before: before, after: after, refAfter: refAfter, execLog: execLog,
	}
	if observe != nil {
		observe(oi)
	}
	checkOraclesReporting(rep, oi)
}

type oracleInput struct {
	op, method string
	nth        int
	kind       faultstorage.FaultKind
	result     opResult
	before     dbSnapshot
	after      dbSnapshot
	refAfter   dbSnapshot
	// execLog is everything the standard logger wrote during op.Execute for
	// this iteration — used by opScopedAcceptableByDesign's requireLogSubstring
	// check (evidence that a best-effort code path actually fired, not just
	// that the table diff resembles it).
	execLog string
}

// knownOpenTolerance narrowly fingerprints one already-filed, not-yet-fixed
// finding so the fuzzer doesn't fail on it forever — but never drops it from
// the input space (RULES): decodeFuzzOp can still select this exact
// (op, method, kind) triple, checkOracles still runs every other oracle
// against it, and only the ONE specific violation this finding predicts is
// downgraded from Errorf to Logf. A fix landing that makes this tolerance
// stop matching is the intended way to notice the finding is closed — remove
// the entry then, don't leave it tolerating a bug that no longer exists.
//
// issue and expires are REQUIRED on every entry (docs/adr-069-testing-strategy.md's
// QUARANTINE convention: an issue reference plus an explicit expiry date, so a
// tolerance is visible and bounded, not a silent permanent carve-out). issue is a
// GitHub issue reference ("#1234"); expires is "YYYY-MM-DD", a backlog-hygiene
// checkpoint to re-triage if still open by then -- not an enforced CI gate the way
// the QUARANTINE preflight check is. findingDoc stays as the pointer to the fuller
// write-up (a docs/findings/*.md path, or a keyorix-private doc).
//
// nth and oracle (added alongside the first real entry, #2449) narrow the
// match further: nth is the exact 1-indexed fault call number
// (oracleInput.nth), and oracle is the exact letter ("a".."e") of the ONE
// GOAL oracle this tolerance covers. Without them, (op, method, kind) alone
// would match EVERY call number and EVERY oracle that happens to report a
// violation on this triple -- silently swallowing a different, unrelated
// violation (a different nth, or a different oracle) that happens to share
// the same op/method/kind. Both are required, same as issue/expires.
type knownOpenTolerance struct {
	op, method string
	kind       faultstorage.FaultKind
	nth        int
	oracle     string
	issue      string
	expires    string
	findingDoc string
	// tables, if non-empty, narrows this tolerance to ONLY match when the
	// violation's diff is confined to this set (a subset check, not an exact
	// set match) — a diff that includes even one table outside this list is a
	// DIFFERENT, unexplained divergence and must still fail loudly, not be
	// silently swallowed under this finding's name. Empty preserves the
	// original, table-unaware behavior: tolerate the full diff for this exact
	// (op, method, kind, nth, oracle).
	tables []string
	// method == "" matches ANY storage method -- for a finding whose root
	// cause is structural to the OP itself (e.g. a write that happens
	// unconditionally before the faulted call even runs), not tied to one
	// specific storage call.
}

// diffSubsetOf reports whether every table in diff also appears in allowed —
// mirrors acceptableByDesign's identical subset check (bestEffortTables),
// kept separate since knownOpenTolerance's tables field is conceptually
// distinct (a narrowing of an already-filed, not-yet-fixed finding, not a
// documented best-effort design tradeoff).
func diffSubsetOf(diff, allowed []string) bool {
	if len(diff) == 0 {
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

// F3a and F3b (docs/findings/2026-09-21-FINDING-role-update-permission-replace-swallows-storage-errors.md)
// were tolerated here and are now fixed — core.UpdateRole runs the role
// update, permission replace, and audit inside one storage.WithTransaction
// (internal/core/rbac_roles.go). The fuzzer is now the regression test for
// both; no entries needed unless a new finding is filed.
//
// docs/findings/2026-09-24-FINDING-secret-access-request-notify-panic.md was
// tolerated here and is now fixed (#2041, merged) — notifySecretAccessRequested
// (internal/core/classification_gate.go) recovers a panic in its own
// best-effort ListProjectMembers fan-out instead of letting it propagate past
// the already-committed AccessRequest row. The fuzzer is now the regression
// test (see the committed seed
// testdata/fuzz/FuzzStorageFaultOperations/630357d238f9c51b); no entry needed
// unless a new finding is filed.
// gRPC CreateUser CountProjectMembershipsByUsers panic (KindPanic, NthCall=1,
// oracle (a), filed as #2449): FIXED by #2408 (projectCounts now recovers a
// panic the same way it already handled a returned error, with its own
// regression test TestCreateUser_ProjectCountsPanicDoesNotMaskSuccess). The
// tolerance main briefly carried for it (added by #2434, which had forked
// before #2408 landed) is dropped here, not re-added -- #2408's fix is the
// regression test now.
//
// docs/findings/2026-10-02-FINDING-sod-policy-create-getrole-error-misread-as-not-admin.md
// was tolerated here and is now fixed (#2405, merged) -- isGlobalAdminRoleName
// no longer misreads a GetRole error as "not admin". No entry needed unless a
// new finding is filed.
//
// docs/findings/2026-10-02-FINDING-grpc-createrole-updaterole-rolebyid-post-commit-read.md
// was tolerated here and is now fixed (#2381, merged, dropped by this PR's own
// adcfe1a1) -- RoleGRPCService's post-commit roleByID read no longer masks a
// successful CreateRole. No entry needed unless a new finding is filed.
//
// docs/findings/2026-10-02-FINDING-mfa-verify-enforcesessionlimit-panic-masks-successful-login.md
// was tolerated here and is now fixed (#2416, merged, landed on main the same
// day this PR was authored) -- mintSession's EnforceSessionLimit call now
// recovers a panic the same way it already handled a returned error. The
// fuzzer is now the regression test (see the committed seed
// testdata/fuzz/FuzzStorageFaultOperations/mfa-verify-enforcesessionlimit-panic-2416,
// re-encoded for this PR's opCatalog wiring since #2416's own merge commit
// could not commit a working seed before that wiring existed); no entry
// needed unless a new finding is filed.
// #2407 (REST PUT /api/v1/projects/{id}/access-requests/{requestId},
// CreateAccessRequestApproval#1/error, oracle (a)) was tolerated here and is
// now fixed (#2415, merged) -- finalizeAccessRequestApproval runs the grant,
// the approval record and the request-state update inside ONE
// storage.WithTransaction, so a reported failure leaves nothing behind,
// including the former compensating revert's own "approval_race_reverted"
// audit row that produced the oracle (a) diff. Entry removed by FIX-2; #2415
// should have dropped it itself (COMMON-RULES: "the PR that fixes #NNNN
// removes its tolerance in the same PR").
//
// NO regression SEED is committed for #2407, deliberately -- it would be a
// vacuous guard. Verified by replaying the issue's own input (REPLAY_HEX=
// 4f002c3230303030, and its re-encoded equivalent 4f002c0000) against
// internal/core/invitations.go checked out at 7d9d31d6^, i.e. the genuine
// pre-fix code: the run PASSES, logging "ACCEPTABLE-BY-DESIGN: ... state
// diverges only in outcome-log tables [AuditEvent]". onlyOutcomeLogTables
// short-circuits before matchingKnownOpen is ever consulted, so this tuple
// could not fail for either the fixed or the unfixed subject, and the
// tolerance above had been dead code since that exemption landed. #2407's
// real, non-vacuous guard is
// internal/core.TestFinalizeAccessRequestApproval_ApprovalRecordFailureRevertsGrant,
// which asserts the EFFECT ("a reported failure must leave ZERO new audit
// rows") and does go red against that same pre-fix file.
var knownOpenTolerances = []knownOpenTolerance{
	// #2807 (filed 2026-10-05 from THIS PR's own fuzz-changed run, shard 0,
	// minimized input committed by the fuzzer as
	// testdata/fuzz/FuzzStorageFaultOperations/cc44f6cd6ac24cd8; pre-minimization
	// REPLAY_HEX=d820633230): a GetUserRoles error AFTER the passkey assertion
	// already verified leaves the reserved LoginAttempt consumed and an
	// MFAStepUpGrant committed, while completeLogin reports a 500 and revokes
	// only the Session (#2412). Confirmed PRE-EXISTING on origin/main @ cbb9863e
	// by replaying the same input directly against it -- this PR touches no
	// production code (it removes a dead tolerance and adds two seedIntent
	// entries), so the finding is not ours. Scoped to this one tuple and this one
	// table set, per COMMON-RULES: not table-wide, not method-wide.
	// Remove this entry in the PR that fixes #2807.
	{
		op: "REST POST /auth/webauthn/login/finish", method: "GetUserRoles", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2807", expires: "2026-10-19",
		tables:     []string{"MFAStepUpGrant", "LoginAttempt", "AuditEvent"},
		findingDoc: "#2807",
	},
	// FOUR entries citing #2549 for the bulk access-request ops
	// (bulk-reject/GetAccessRequest#1, and bulk-approve/GetAccessRequest#1,
	// /RoleSetBypassesPermissionChecks#4, /GetRolePermissions#1) were DELETED
	// here, not fixed and not re-filed: they had gone DEAD. #2549 was filed
	// when the error-reporting branch had no outcome-log exemption; it has one
	// now, so an [AuditEvent]-only diff is accepted there and report() is never
	// reached, which means matchingKnownOpen was never consulted for any of the
	// four. They were expiring carve-outs for a case nothing flags.
	//
	// Verified by driving each one: diff vs the pre-fault state is [AuditEvent],
	// accepted by onlyOutcomeLogTables with an ACCEPTABLE-BY-DESIGN log line.
	// What covers them now is pinned by
	// TestOracleAErrorBranch_BulkAccessRequestAuditDiffIsAcceptedWithoutATolerance
	// (oracle_a_by_design_test.go), so a future reader seeing that log line can
	// tell it is deliberate and does not re-add a tolerance "just in case".
	//
	// The staleness that hid this is now itself checked:
	// TestKnownOpenTolerances_AreLoadBearing drives every fully-specified entry
	// in this list and fails on any that no longer tolerates anything.
	//
	// docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md
	// (SESSION-FI, AT5, out of OWNS, not fixed there): loadTOTPSecret's
	// GetMFASecret error is checked with `err == nil` as the gate to even
	// attempt TOTP validation; on error the whole branch is skipped,
	// collapsing into the SAME path a genuine wrong code takes --
	// audited as mfa.failed AND counted toward the account lockout, for a
	// correct code that was never actually checked. Filed as #2548. Fix is PR
	// #2398, not yet merged -- keep tolerating until it lands. Reproduced
	// directly against this PR's rebased opCatalog: op="REST POST
	// /auth/mfa/verify" fault=(method=GetMFASecret, NthCall=1, kind=error) --
	// oracle (a) VIOLATION, differing tables: [AuditEvent LoginAttempt].
	{
		op: "REST POST /auth/mfa/verify", method: "GetMFASecret", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2548", expires: "2026-10-17",
		findingDoc: "docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md",
	},
	// Second trigger for the same finding (#2548), reached through a
	// structurally different call site: VerifyMFACredentials' OWN GetUser
	// call fails closed correctly -- it returns before ever reaching
	// loadTOTPSecret/recordFailedLogin -- but the HANDLER
	// (server/http/handlers/mfa.go's VerifyMFA) already called
	// reserveLoginAttempt (RecordFailedLogin by IP) UNCONDITIONALLY, before
	// VerifyMFALogin even runs, as its own rate-limiting bookkeeping (F2,
	// 2026-09-20). That write is structural to this op's wiring, not tied to
	// GetMFASecret specifically: ANY storage-error fault that makes this op
	// report failure will show the identical LoginAttempt-only diff, since
	// reserveLoginAttempt's write already landed before the fault-affected
	// call runs. method is deliberately left blank (wildcard) for this
	// reason, and tables is scoped to LoginAttempt alone -- unlike the
	// GetMFASecret entry above (whose diff also legitimately includes
	// AuditEvent from auditMFAFailed, a different code path entirely), a
	// GetUser-stage failure never reaches auditMFAFailed at all, so AuditEvent
	// never appears in ITS diff. A diff that included anything beyond
	// LoginAttempt would be a different, unexplained issue and must still
	// fail. Fix is PR #2398 (second commit), not yet merged -- keep
	// tolerating until it lands; #2398's own body says to remove this entry
	// once both it and #2392 have merged. Reproduced directly against this
	// PR's rebased opCatalog (the originally-committed seed, 877139548d2805a6,
	// now decodes to an unrelated op post-rebase -- see
	// mfa-verify-getuser-loginattempt-2548 below): op="REST POST
	// /auth/mfa/verify" fault=(method=GetUser, NthCall=1, kind=error) --
	// oracle (a) VIOLATION, differing tables: [LoginAttempt].
	{
		op: "REST POST /auth/mfa/verify", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2548", expires: "2026-10-17",
		tables:     []string{"LoginAttempt"},
		findingDoc: "docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md",
	},
	// The KindPanic arm of the SAME #2548 wildcard entry directly above. Found by
	// a live run while working #2549, confirmed PRE-EXISTING by byte-for-byte
	// replay against unmodified origin/main (fault=GetMFASecret#1/panic, oracle
	// (a), differing tables: [LoginAttempt]).
	//
	// FLAG FOR THE COORDINATOR — a pattern, not just a row. Both of this run's
	// LoginAttempt findings (this one and the webauthn/login/finish panic above)
	// are the KindPanic arm of an EXISTING KindError wildcard entry, same op,
	// same table, same root cause (reserveLoginAttempt writes unconditionally
	// before the faulted call runs, so the row is there whatever the fault is).
	// The existing entries wildcard `method` precisely so the next storage call
	// CI finds is not a fresh red build — but `kind` has no wildcard, so every
	// such entry needs its panic twin added by hand, and CI's randomized
	// fuzz-changed will keep producing them one at a time. That is the same
	// shared-mechanism question an earlier author already flagged for `nth`
	// ("the existing knownOpenTolerance struct has no nth-wildcard mechanism ...
	// inventing one is a shared-mechanism change, not a data entry"). Deciding
	// whether to add a kind-wildcard belongs with that one; NOT invented here,
	// and deliberately not worked around by widening either existing entry
	// (COMMON-RULES: never widen an existing tolerance to make CI green).
	{
		op: "REST POST /auth/mfa/verify", kind: faultstorage.KindPanic,
		nth: 1, oracle: "a", issue: "#2548", expires: "2026-10-17",
		tables:     []string{"LoginAttempt"},
		findingDoc: "docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md",
	},
	// The fifth #2549 entry (op="REST POST /api/v1/auth/mfa/stepup",
	// method=CreateMFAStepUpGrant#1, tables=[MFASecret]) MOVED to
	// oracleAByDesignErrors (oracle_a_by_design_test.go). Unlike the four bulk-op
	// entries above it was genuinely load-bearing — MFASecret is business state,
	// not an outcome log, so no existing exemption reached it — but a
	// knownOpenTolerance was the wrong instrument: this list means "a filed,
	// not-yet-fixed bug, tolerated until someone fixes it", and the entry's own
	// comment said the opposite ("NOT a bug ... the intended fail-closed
	// design"). An expiring bug tolerance over intended behaviour can only be
	// re-filed forever. It now sits in a mechanism whose rows assert
	// by-design-ness and are required to cite the production comment and the
	// proving test that establish it.
	//
	// (#2554's row — REST PATCH /api/v1/secrets/{id}/classification,
	// CreateSecretAccessLog, panic, nth 1 — is GONE, not expired. Its entry
	// said "remove this entry once PR #2560 merges"; it merged and nobody did,
	// which is precisely the decay TestKnownOpenTolerances_AreLoadBearing was
	// added to catch. writeAccessLog (internal/core/audit.go) now recovers from
	// a PANIC in CreateSecretAccessLog, not just a returned error. Same three
	// signals as the deletions at the end of this list: issue CLOSED, the
	// recover() present in the tree, and the row reported dead.)
	// Pre-existing, unrelated to this PR's own MFA-reauth changes -- found by
	// a live 2-minute FuzzStorageFaultOperations run during this PR's rebase
	// (ListWebAuthnCredentials#1/error), then CI's own fuzz-changed shard
	// independently found a SECOND call site of the identical root cause
	// (ConsumeMFAChallenge#1/error) during this PR's own CI run. Same
	// root-cause family as #2548's second (wildcard) entry above: the
	// WebAuthn login/finish handler (server/http/handlers/webauthn.go) calls
	// reserveLoginAttempt UNCONDITIONALLY, before the real assertion
	// verification runs, so a storage error on ANY call the verification path
	// makes fails closed correctly but still leaves a LoginAttempt row
	// behind -- structural to the op itself, not tied to one storage method,
	// same reasoning as #2548's own wildcard entry. method is deliberately
	// left blank for this reason (narrowed back to a single method would just
	// mean the NEXT call site CI's randomized fuzz-changed finds becomes a
	// fresh red build instead of this same already-tracked finding). Filed as
	// #2565 (cross-links #2548 and #2398's own "CR3" note, since the root
	// cause is shared across every reserveLoginAttempt call site, not
	// MFA-specific). A THIRD trigger (ConsumeWebAuthnSession#1/error, cited
	// by the coordinator as #2603) already matches this same wildcard entry
	// -- same op, same kind, same LoginAttempt-only diff -- confirmed by
	// direct replay; no separate tolerance entry needed for it. #2603 and
	// #2565 look like the same tracked finding under two issue numbers.
	{
		op: "REST POST /auth/webauthn/login/finish", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2565", expires: "2026-10-17",
		tables:     []string{"LoginAttempt"},
		findingDoc: "#2565",
	},
	// The KindPanic arm of the SAME #2565 finding, found by a 2-minute live
	// FuzzStorageFaultOperations run while working #2549
	// (fault=ListWebAuthnCredentials#1/panic, oracle (a), differing tables:
	// [LoginAttempt]). Confirmed PRE-EXISTING, not caused by #2549's change:
	// replayed byte-for-byte against unmodified origin/main, where it fails
	// identically (COMMON-RULES' "replay the failing input on origin/main
	// first" rule). #2549 only ADDS an exemption branch and deletes tolerances
	// that were already never consulted, neither of which can make the oracle
	// report more.
	//
	// Same op, same oracle, same LoginAttempt-only diff, same root cause the
	// KindError entry above describes (reserveLoginAttempt writes
	// UNCONDITIONALLY, before the verification path runs, so the row is there
	// whatever the fault is). kind is the ONLY axis that differs, so this is a
	// one-field sibling, not a widening: method stays blank for the reason that
	// entry gives, and tables stays scoped to LoginAttempt so a diff touching
	// anything else still fails. Remove when #2565 is fixed.
	//
	// No corpus seed committed for it deliberately: this harness's input bytes
	// encode the op as a raw opCatalog INDEX, so a committed seed decodes to a
	// different op after any rebase that reorders the catalog (a hazard this
	// repo has already been bitten by). The tolerance is keyed on
	// (op, kind, nth, tables), which is rebase-stable; the seed would not be.
	{
		op: "REST POST /auth/webauthn/login/finish", kind: faultstorage.KindPanic,
		nth: 1, oracle: "a", issue: "#2565", expires: "2026-10-17",
		tables:     []string{"LoginAttempt"},
		findingDoc: "#2565",
	},
	// Also found by the same live run while working #2549, also confirmed
	// PRE-EXISTING by byte-for-byte replay against unmodified origin/main, also
	// not caused by #2549's change. Filed as #2834 (no prior issue found).
	//
	// buildClassificationPosture (internal/core/compliance_posture.go:714)
	// degrades rather than fails when a sub-count read errors: the snapshot is
	// PERSISTED with partial counts and the request reports success. The
	// degradation is recorded (cp.degrade sets Degraded/DegradedReasons, and the
	// persisted row carries DegradedControls), which is the same deliberate
	// partial-snapshot-with-a-durable-marker shape OpenAccessReviewCampaign uses
	// (#483) -- so this is PROBABLY acceptable-by-design and belongs in
	// opScopedBestEffortTables with requireLogSubstring pinned to the degrade
	// line. #2834 asks the compliance-posture owner to decide that; classifying
	// another subsystem's behaviour as by-design without its owner is exactly the
	// claim #2549 was filed about, so it is tolerated here rather than
	// reclassified.
	//
	// method is NOT wildcarded even though the three sibling counts share the
	// root cause: a wildcard would hide a future, genuinely different divergence
	// on this op. tables is the one table, so anything else still fails. Remove
	// when #2834 is resolved either way.
	{
		op: "REST POST /api/v1/compliance/snapshots", method: "CountDynamicSecretConfigsByClassification",
		kind: faultstorage.KindError,
		nth:  1, oracle: "a", issue: "#2834", expires: "2026-11-07",
		tables:     []string{"CompliancePostureSnapshot"},
		findingDoc: "#2834",
	},
	// (The third pre-existing finding from the same live runs — #2841, op="REST
	// POST /auth/webauthn/login/finish", method=GetUserRoles — was tolerated here
	// and is now FIXED, so its row is gone rather than expired. Both WebAuthn
	// login paths resolve the response identity before minting the session and
	// the ambient MFAStepUpGrant, so a login that reports failure persists
	// neither; guarded by webauthn_login_no_partial_grant_test.go here and by
	// internal/core/login_identity_before_mint_test.go at the core
	// boundary. #2565's wildcard entry on this same op still stands and still
	// covers only [LoginAttempt] — unchanged, not widened.)
	//
	// Fourth and LAST pre-existing finding tolerated from the same live runs,
	// also confirmed by byte-for-byte replay against unmodified origin/main.
	// Filed as #2844, which also records the thing that made me stop here: FOUR
	// distinct pre-existing oracle (a) findings surfaced in ~15 minutes of live
	// fuzzing, the committed corpus being green throughout. Per-finding
	// tolerances cannot converge at that rate, and COMMON-RULES' remedy assumes
	// roughly one such event per PR rather than a stream — so #2844 asks for a
	// batch triage of the standing backlog (#2407 #2548 #2554 #2565 #2599 #2606
	// #2834 #2841 and itself) instead of an unbounded tolerance list growing
	// inside #2549's PR. Expect CI's fuzz-changed to find a fifth; that is the
	// documented, expected outcome, not a surprise.
	//
	// WebAuthn registration finishing is expected to invalidate the user's other
	// sessions (an MFA/credential-enrollment change is one of the session-revoke
	// events); when DeleteSessionsForUserExcept fails, the registration still
	// reports SUCCESS, so the credential is enrolled and the other sessions
	// survive. Whether that should fail closed or retry is the auth owner's call.
	// Remove when #2844 is resolved.
	{
		op: "REST POST /api/v1/auth/webauthn/register/finish", method: "DeleteSessionsForUserExcept",
		kind: faultstorage.KindError,
		nth:  1, oracle: "a", issue: "#2844", expires: "2026-11-07",
		tables:     []string{"Session"},
		findingDoc: "#2844",
	},
	// Pre-existing, unrelated to this PR's own MFA-reauth changes (#2392 only
	// newly wires /auth/mfa/verify into the fuzzer, it doesn't touch this code
	// path) -- found by a live 2-minute FuzzStorageFaultOperations run during
	// this PR's rebase. VerifyMFACredentials (internal/core/mfa.go) calls
	// MarkTOTPStepUsed (consuming the TOTP step) BEFORE mintSession's own,
	// independent CreateSession call; a CreateSession failure reports the
	// whole verify as an error with the step already burned, so the caller
	// cannot retry with the same correct code. Filed as #2567 (cross-links
	// #2548 -- same "distinguish a storage hiccup from a confirmed negative
	// result before a real-consequence side effect runs" shape, different
	// specific mechanism).
	{
		op: "REST POST /auth/mfa/verify", method: "CreateSession", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2567", expires: "2026-10-17",
		tables:     []string{"MFASecret", "LoginAttempt"},
		findingDoc: "#2567",
	},
	// Coordinator priority (12:34Z): random pre-existing fuzz findings were
	// blocking unrelated PRs (e.g. #2556). Added here, into this PR's own
	// branch, so the hotspot file stays serialized through one PR rather than
	// several concurrent ones touching the same lines.
	//
	// REST POST /api/v1/invitations, CountSetupTokensSince, error, nth 1,
	// oracle a: checkResendThrottle's CountSetupTokensSince call is on the
	// SUCCESS path (reported success, final state is [SetupToken AuditEvent]
	// different from the fault-free reference) -- traces through
	// provisionSetupLink/provisionSetupLinkThrottled -> InviteGlobalWithLink,
	// the identical architectural tradeoff PR #2393's own body already
	// documents as its deferred "#4" item (same shape as #2382's own bonus
	// finding #1: two-separate-top-level-calls, "invitation created but setup
	// link failed" still returns 201) -- not independently fixed here, same
	// reasoning #2393 gives, pending that coordinator decision.
	{
		op: "REST POST /api/v1/invitations", method: "CountSetupTokensSince", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2599", expires: "2026-10-17",
		tables:     []string{"SetupToken", "AuditEvent"},
		findingDoc: "#2599",
	},
	// REST POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide,
	// ListProjectRoleAssignments, error, nth 1, oracle a: a ListProjectRoleAssignments
	// storage error reports failure but AccessReviewItem's decision state
	// still committed. Entirely unrelated to MFA/auth -- same finding this
	// session already surfaced and filed as #2570 during the #2392 rebase's
	// own live fuzzing (deliberately not tolerated there, per this file's
	// "don't expand scope indefinitely" precedent); coordinator independently
	// filed #2606 for the same symptom. Citing #2606 per the coordinator's
	// explicit instruction -- #2570 is a duplicate worth closing in favor of
	// this one.
	{
		op:     "REST POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide",
		method: "ListProjectRoleAssignments", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2606", expires: "2026-10-17",
		tables:     []string{"AccessReviewItem"},
		findingDoc: "#2606",
	},
	// ---- SESSION ORACLE-A-1, item 1: unblock the merge queue --------------
	// Two pre-existing oracle (a) error-branch findings landed on main unfixed
	// (SESSION-STALE-PR-1: both were found on PRs that touched neither code
	// path -- #2719 and #2461 -- and both merged with the fuzz leg red, so they
	// now fail UNRELATED PRs at random). Both confirmed to reproduce on
	// pristine main at 98031965 by direct replay before these entries were
	// written, so neither is caused by any open PR.
	//
	// Both are the SAME shape, and the shape is one this repo has ALREADY
	// reviewed, classified and machine-enforced as correct:
	// docs/atomicity-exempt.tsv class B, "consume-first by design: a single-use
	// value is consumed BEFORE later work and must stay consumed even if later
	// work fails (replay protection)". Both functions carry their own
	// `// atomicity: consume-first by design` marker comment and a verifying
	// *_FailsClosed test. Oracle (a)'s error branch has no knowledge of that
	// ledger, so it reads a deliberately-retained consumption as a partial
	// commit -- the same harness-oracle gap as #2549's stepup entry above, not
	// a product bug. "Fixing" either by rolling the consume back into the
	// transaction would un-consume a single-use token on a later failure,
	// which is precisely what class B and those tests forbid.
	//
	// Each entry is scoped to ONE op + ONE storage method + ONE fault kind +
	// ONE nth + the exact tables the consumption can touch: a diff that
	// includes anything else is a DIFFERENT finding and must still fail
	// loudly. Remove each when its issue is resolved (see this session's
	// report: the recommended resolution is to teach oracle (a) the class-B
	// ledger, not to change either function).
	//
	// #2817's tolerance was here and is REMOVED by this PR -- oracle (a) now
	// knows the class-B consume-first shape directly
	// (consumeFirstAccountsForDiff, consume_first_oracle_test.go), so the
	// exemption is derived from docs/atomicity-exempt.tsv rather than listed
	// as an open finding, and it covers EVERY storage method on the op rather
	// than the one method a tolerance row could name.
	//
	// #2814's tolerance was here and is REMOVED by this PR, for the same
	// reason as #2817's directly above: CompleteSAML is itself a class-B
	// consume-first row, so oracle (a) now derives the exemption from
	// docs/atomicity-exempt.tsv (consumeFirstAccountsForDiff,
	// consume_first_oracle_test.go) instead of carrying it as an open finding
	// against one named storage method.
	// #2817: DisableMFA (internal/core/mfa.go) runs requireReauth -- itself a
	// class-B row (atomicity-exempt.tsv:61) -- BEFORE the
	// SetUserMFAEnabled+DeleteMFAForUser transaction. requireReauth's
	// MarkTOTPStepUsed burns the matched TOTP time-step
	// (MFASecret.LastUsedStep) and writes an "mfa.reauth_verified" AuditEvent
	// on c.storage, outside that transaction, so a DeleteMFAForUser error
	// rolls the disable back and correctly leaves the step burned.
	{
		op: "REST POST /api/v1/auth/mfa/disable", method: "DeleteMFAForUser", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2817", expires: "2026-10-17",
		tables:     []string{"AuditEvent", "MFASecret"},
		findingDoc: "#2817",
	},
	// #2814: CompleteSAML (internal/core/sso.go) is itself a class-B row
	// (atomicity-exempt.tsv:76) -- ConsumeSSOLoginState burns the single-use
	// RelayState row first, by design, because st.Nonce is what the
	// InResponseTo check validates against and a replayable state row would
	// let a captured (RelayState, SAMLResponse) pair re-drive user
	// resolution/provisioning. A GetUserByUsername error inside
	// resolveSSOUser therefore fails closed with the state correctly consumed.
	{
		op: "REST POST /auth/saml/{provider}/acs", method: "GetUserByUsername", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2814", expires: "2026-10-17",
		tables:     []string{"SSOLoginState"},
		findingDoc: "#2814",
	},
	// #2842 (ORACLE-A-1). Surfaced by CI's fuzz shard 0 + fuzz-changed on
	// #2821, whose entire diff was the two auth/MFA/SAML rows directly above
	// -- nothing in the secrets path. Confirmed to reproduce on pristine
	// origin/main by direct replay before this entry was written.
	//
	// NOT a bug: RollbackSecret (internal/core/versions.go) re-instates a
	// historical value via RotateSecret, whose storeNextSecretVersion +
	// c.storage.UpdateSecret pair is DELIBERATELY non-transactional.
	// updateSecretWithNewVersion's own doc comment
	// (internal/core/secrets_versions.go) says so, and gives the reason by
	// contrast with the UpdateSecret path it DID make transactional: for a
	// rotation the new value may already have been applied to an external
	// upstream system, and the version row is the only record of it, so
	// rolling it back would trade a loud failure for silent loss of the only
	// record of a live credential. The version row surviving the node update's
	// failure is the intended outcome.
	//
	// Deliberately a tolerance and NOT a consumeFirstExemptions entry: that
	// mechanism requires a class-B (consume-first) row in
	// docs/atomicity-exempt.tsv, enforced by
	// TestConsumeFirstExemptions_MatchAtomicityLedger, precisely so it cannot
	// become a general "state on an error path is fine" carve-out. Nothing is
	// consumed here -- the rationale is "must not roll back", a different
	// claim. #2842 asks for RotateSecret to be classified in that ledger and
	// for oracle (a) to key off the classification; remove this entry then.
	//
	// Scoping is sufficient here, and that is measured rather than assumed: a
	// DERIVED sweep of this op -- run it once unfaulted, read the real call
	// log off FaultyStorage.Calls(), then fault every (method, nth) pair the
	// op actually makes -- enumerated all 96 real pairs and found exactly ONE
	// oracle violation, the UpdateSecret#1 pair below. So unlike #2548/#2565
	// (where the write lands before any faulted call, making every method on
	// the op reproduce it and forcing a method wildcard), this one really is
	// specific to the single call that straddles the version write. No
	// wildcard needed, and no #2549-style treadmill of one new row per red
	// build expected on this op.
	{
		op: "REST POST /api/v1/secrets/{id}/rollback", method: "UpdateSecret", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2842", expires: "2026-10-17",
		tables:     []string{"SecretVersion"},
		findingDoc: "#2842",
	},
	// (#2599's row — REST POST /api/v1/invitations, CountSetupTokensSince,
	// error, nth 1 — is GONE, not expired. The bug is fixed: a throttle count
	// that cannot be read is now its own refusal
	// (core.ErrResendThrottleUnverifiable, internal/core/invitations.go), so
	// the invitation is no longer persisted while the request reports the
	// failure. Confirmed on three independent signals before deleting: the
	// issue is CLOSED, the fix's own sentinel is present in the tree, and
	// TestKnownOpenTolerances_AreLoadBearing reports the row dead — the
	// oracle no longer flags its case at all.)
	//
	// (#2606's row — .../items/{itemId}/decide, ListProjectRoleAssignments,
	// error, nth 1 — is likewise GONE. Fixed by #2570: DecideAccessReviewItem's
	// attest path runs its reads before the claim, so the item stays pending
	// when the grant lookup errors. Same three signals: issue CLOSED, the
	// proving test present in the tree
	// (internal/core/TestDecideAccessReviewItem_AttestGrantLookupErrorLeavesItemPending),
	// and the row reported dead.)
}

// observeKnownOpenMatch, when non-nil, is called with every tolerance
// matchingKnownOpen actually returns. #2549: it exists so
// TestKnownOpenTolerances_AreLoadBearing can watch the REAL suppression
// decision instead of re-deriving checkOracles' accept-before-report ordering.
// A reconstruction of that ordering would be a second implementation of it, and
// if the two drifted the staleness check would report a LIVE tolerance as dead
// and invite someone to delete a real carve-out — the one failure mode a
// staleness check must not have.
var observeKnownOpenMatch func(*knownOpenTolerance)

func matchingKnownOpen(in oracleInput, oracle string, diff []string) *knownOpenTolerance {
	for i, k := range knownOpenTolerances {
		if k.op != in.op || k.kind != in.kind || k.nth != in.nth || k.oracle != oracle {
			continue
		}
		if k.method != "" && k.method != in.method {
			continue
		}
		if len(k.tables) > 0 && !diffSubsetOf(diff, k.tables) {
			continue
		}
		if observeKnownOpenMatch != nil {
			observeKnownOpenMatch(&knownOpenTolerances[i])
		}
		return &knownOpenTolerances[i]
	}
	return nil
}

// TestKnownOpenTolerances_CarryIssueAndExpiry enforces knownOpenTolerance's own
// doc comment: issue and expires are required, not optional decoration. Passes
// trivially while knownOpenTolerances is empty (today) -- it exists for the next
// entry, not this one; see docs/adr-069-testing-strategy.md's QUARANTINE
// expiry-check precedent for why a tolerance without a checked issue+expiry pair
// tends to become a silent permanent carve-out instead of the bounded, visible
// one it's meant to be.
func TestKnownOpenTolerances_CarryIssueAndExpiry(t *testing.T) {
	for _, k := range knownOpenTolerances {
		label := fmt.Sprintf("%s/%s/%s", k.op, k.method, k.kind)
		if k.issue == "" {
			t.Errorf("knownOpenTolerance %s: issue is empty -- every tolerance must cite a GitHub issue (\"#1234\")", label)
		}
		if k.expires == "" {
			t.Errorf("knownOpenTolerance %s: expires is empty -- every tolerance must carry an explicit \"YYYY-MM-DD\" expiry", label)
			continue
		}
		if _, err := time.Parse("2006-01-02", k.expires); err != nil {
			t.Errorf("knownOpenTolerance %s: expires %q does not parse as YYYY-MM-DD: %v", label, k.expires, err)
		}
	}
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
	// flagged here. FLAG FOR REVIEW (updated, item 4 of the UX-fixes batch):
	// "no caller-visible signal" above is no longer true for an operator or
	// automated sweep -- seedProjectEnvironment now writes an
	// EventProjectEnvironmentSeedFailed audit event (AuditEvent row, hence
	// that table joining the diff here too) for every failed/panicked seed,
	// once the outer transaction commits (reportProjectEnvironmentSeedFailures).
	// Still open: whether CreateProject should ALSO report which environments
	// seeded successfully in its own HTTP response, rather than only via the
	// audit trail. Left undecided, same as before.
	"CreateEnvironment": {"Environment", "AuditEvent"},
	// LastUserSecretActivity: OpenAccessReviewCampaign (internal/core/
	// access_review_campaign.go) deliberately, by design (#483), persists a
	// failure of this ONE sub-query onto the campaign row itself —
	// Degraded/DegradedReasons — rather than aborting the campaign or
	// silently leaving every item's LastUsedAt nil (indistinguishable from
	// "genuinely never used"). annotateLastUsedAt (access_review.go) only
	// sets report.degrade(...) and returns on this specific error; it does
	// not alter entries, so AccessReviewItem rows are identical either way
	// — the ENTIRE diff this failure can ever produce is confined to
	// AccessReviewCampaign's own Degraded/DegradedReasons columns, found
	// live by FuzzStorageFaultOperations (REST POST .../access-review/
	// campaigns). This is the intended, documented behavior #483 built —
	// not an undiscovered bug — so it belongs here, not in
	// knownOpenTolerances.
	"LastUserSecretActivity": {"AccessReviewCampaign"},
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
// (Named *Reporting, and taking fuzzVerdict rather than *testing.T, for the
// same reason runOneFuzzIterationReporting does: a test that is only INSPECTING
// one case must be able to observe the oracle's verdict without that verdict
// ending it. See drive_sink_test.go.)
func checkOraclesReporting(t fuzzVerdict, in oracleInput) {
	t.Helper()
	label := fmt.Sprintf("op=%s fault=%s#%d/%s", in.op, in.method, in.nth, in.kind)

	report := func(oracle string, diff []string, format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if known := matchingKnownOpen(in, oracle, diff); known != nil {
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
		report("c", nil, "%s: ORACLE (c) VIOLATION — a fault on an authz-resolution read produced a SUCCESSFUL "+
			"result instead of an error/deny: %s", label, in.result.Detail)
		return
	}

	// Oracle (e): error hygiene — no secret plaintext in an error body.
	if !in.result.Success {
		for _, frag := range canaryFragments {
			if strings.Contains(in.result.Detail, frag) {
				report("e", nil, "%s: ORACLE (e) VIOLATION — error response leaked secret plaintext %q: %s",
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
			if opScopedAcceptableByDesign(in.op, in.method, in.nth, diff, in.execLog) {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges only in %v, which this op/method pair "+
					"explicitly documents as best-effort/non-fatal (see opScopedBestEffortTables' doc comment)",
					label, diff)
				return
			}
			if bulkPartialFailureAccountsForDiff(in) {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges from the reference only in %v, but this "+
					"run's own before/after state is byte-for-byte unchanged and the response body's own "+
					"\"failed\" array already reports this item as not deleted — this op's documented "+
					"partial-success design (see bulkPartialFailureAccountsForDiff's doc comment), not an "+
					"unreported business-state change", label, diff)
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
			if onlyOutcomeLogTables(diff) {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges only in outcome-log tables %v — oracle (c) already "+
					"ruled out a fail-open authz cause, and every traced instance of this shape has been "+
					"benign audit-content degradation, not a business-state inconsistency", label, diff)
				return
			}
			report("a", diff, "%s: ORACLE (a) VIOLATION — reported SUCCESS but final state does not match the "+
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
		// SecretAccessLog is excluded for the same reason as AuditEvent: it is
		// written by the handler/core only for the REPORTED outcome (best-effort
		// writeAccessLog), so an effect-then-error delete legitimately has the
		// secret gone but no access-log row. It only became visible to this
		// oracle once secret_access_logs was migrated on every install (#2314).
		excludedTables := append(append([]string{}, outcomeLogTables...), effectThenErrorExtraExcludedTables(in.op, in.method)...)
		excludedColumns := effectThenErrorExtraExcludedColumns(in.op, in.method)
		nonAuditBefore := hashExcludingColumns(in.before, excludedTables, excludedColumns)
		nonAuditAfter := hashExcludingColumns(in.after, excludedTables, excludedColumns)
		nonAuditRef := hashExcludingColumns(in.refAfter, excludedTables, excludedColumns)
		if nonAuditAfter != nonAuditBefore && nonAuditAfter != nonAuditRef {
			if multiStepFirstCallAmbiguousCommit(in.op, in.method, in.nth) {
				t.Logf("FLAG FOR REVIEW (not auto-fixed, not silently accepted): %s: state matches neither "+
					"old nor new — see multiStepFirstCallAmbiguousCommit's doc comment for the traced "+
					"explanation (an ambiguous commit on the FIRST call of a multi-step create, which the "+
					"caller has no ID to compensate for, unlike the SECOND call's already-existing cleanup)",
					label)
				return
			}
			report("d", nil, "%s: ORACLE (d) VIOLATION — effect-then-error state matches NEITHER the pre-fault "+
				"state nor the fault-free reference state (a genuine partial/mixed commit, not just an "+
				"ambiguous-but-consistent one). Differing tables vs before: %v; vs reference: %v",
				label, diffTables(in.before, in.after), diffTables(in.refAfter, in.after))
		}
	default:
		if in.after.Hash != in.before.Hash {
			diff := diffTables(in.before, in.after)
			// Same 3-layer tolerance as the SUCCESS branch above, reused here for
			// a reported ERROR that still changed state: a function can commit a
			// real effect and then fail on a later, best-effort or documented-
			// partial step (see opScopedBestEffortTables' MigrateUserToMachine
			// entry and bestEffortTables generally) just as easily on the error
			// path as on the success path — there is nothing about "the caller
			// was told ERROR" that makes a best-effort audit-log failure, or a
			// documented partial-commit-on-error design, suddenly a bug.
			if acceptableByDesign(in.method, diff) {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges only in %v, which %s explicitly documents "+
					"as best-effort/non-fatal (see acceptableByDesign's doc comment)", label, diff, in.method)
				return
			}
			if opScopedAcceptableByDesign(in.op, in.method, in.nth, diff, in.execLog) {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges only in %v, which this op/method pair "+
					"explicitly documents as best-effort/non-fatal (see opScopedBestEffortTables' doc comment)",
					label, diff)
				return
			}
			if onlyOutcomeLogTables(diff) {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges only in outcome-log tables %v — see "+
					"onlyOutcomeLogTables' doc comment on the SUCCESS branch above; the same reasoning applies "+
					"to a reported ERROR", label, diff)
				return
			}
			// Fourth layer, ERROR branch only: the consume-first shape
			// docs/atomicity-exempt.tsv already classifies as correct (class B).
			// Accepts ONLY when the entire before→after change is the op's
			// declared single-use consumption — see consume_first_oracle_test.go
			// for exactly what it verifies and, as importantly, what it does not.
			if e, ok := consumeFirstAccountsForDiff(in); ok {
				t.Logf("ACCEPTABLE-BY-DESIGN (consume-first, docs/atomicity-exempt.tsv class B, %s): %s: "+
					"state diverges in %v, but every table and column OUTSIDE this op's declared single-use "+
					"consumption is byte-for-byte identical to this run's own pre-fault state — %s",
					e.fn, label, diff, e.why)
			// #2549: the error-reporting branch's own business-state exemption.
			// The three layers above all describe a side effect the code is
			// willing to LOSE (best-effort) or a log of the reported outcome.
			// Neither covers the opposite shape: a mutation the code
			// deliberately KEEPS while reporting failure, where the mutation IS
			// the security behaviour (VerifyMFAStepUp advancing the TOTP replay
			// window before failing closed). Each row is reviewed, names the
			// production comment and the test that establish the design, and
			// allowlists an EXACT table set — see oracle_a_by_design_test.go.
			if e := oracleAErrorByDesign(in.op, in.method, in.kind, in.nth, diff); e != nil {
				t.Logf("ACCEPTABLE-BY-DESIGN: %s: state diverges only in %v, which this op/method pair "+
					"deliberately keeps while reporting failure — %s (proving test: %s)",
					label, diff, e.designComment, e.provingTest)
				return
			}
			report("a", diff, "%s: ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway "+
				"(partial commit). Differing tables: %v", label, diff)
		}
	}
}

// outcomeLogTables record what the caller was TOLD happened (audit trail, secret
// access log), not application state; the oracles compare them separately.
var outcomeLogTables = []string{"AuditEvent", "SecretAccessLog", "Notification"}

// onlyOutcomeLogTables reports whether every differing table is an outcome log.
func onlyOutcomeLogTables(diff []string) bool {
	if len(diff) == 0 {
		return false
	}
	for _, d := range diff {
		ok := false
		for _, o := range outcomeLogTables {
			if d == o {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// bulkPartialSuccessOps names ops whose success response body is
// {"data":{"deleted":[ids],"failed":[{"secret_id":id,...}],"total":N}} —
// BulkDeleteSecrets' own documented shape (internal/core/bulk_delete.go: "Partial
// success is allowed — individual failures are collected in Failed"). A
// per-item failure here is accurately reported in the body even though the
// HTTP-level call still reports overall success — by this op's own design, not
// a bug. Scoped to exactly this op for now: a sibling bulk op (bulk-rename,
// bulk-rotate, extend-expiring) sharing the same partial-success shape would
// need its own entry here, not inferred from this one (CLAUDE.md's "an
// enumeration is only as complete as the idioms it knows about").
var bulkPartialSuccessOps = map[string]bool{
	"REST POST /api/v1/projects/{id}/secrets/bulk-delete": true,
}

// bulkPartialFailureAccountsForDiff reports whether in.op's response body
// (in.result.Detail, "HTTP <code>: <json body>") shows EVERY requested item
// failed (an empty "deleted" array, a non-empty "failed" array — the only
// shape FuzzStorageFaultOperations' bulk-delete op, which always submits
// exactly one secret_id, can currently produce) AND this run's final state is
// BYTE-FOR-BYTE IDENTICAL to its own pre-fault snapshot (in.before == in.after).
//
// Deliberately NOT "diff confined to the tables a delete would touch" —
// coordinator review caught that an earlier version of this check compared
// against ONLY the fault-free reference run and accepted any diff limited to
// {SecretNode, AuditEvent, SecretAccessLog}, which is too broad: it would wave
// through a REAL bug where an audit event or access-log row gets written for
// an item the body itself reports as failed (both runs would still show a
// non-empty AuditEvent table, just with different content, and a table-name-
// only diff can't tell those apart). Zero reported deletions means literally
// nothing should have changed in the database during this call — the
// strictest, most direct statement of "this item's effect never committed,
// and the body correctly says so." Deliberately does NOT generalize to a true
// mixed batch (some deleted, some failed): this fuzz op never exercises that
// shape, so nothing here has been red/green-tested against it.
func bulkPartialFailureAccountsForDiff(in oracleInput) bool {
	if !bulkPartialSuccessOps[in.op] {
		return false
	}
	detail := in.result.Detail
	sep := strings.Index(detail, ": ")
	if sep < 0 {
		return false
	}
	var body struct {
		Data struct {
			Deleted []uint `json:"deleted"`
			Failed  []struct {
				SecretID uint   `json:"secret_id"`
				Error    string `json:"error"`
			} `json:"failed"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(detail[sep+2:]), &body); err != nil {
		return false
	}
	if len(body.Data.Deleted) != 0 || len(body.Data.Failed) == 0 {
		return false
	}
	return in.before.Hash == in.after.Hash
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

// hashExcludingColumns is hashExcluding's column-scoped sibling (#2410): the
// tables in excludeTables are dropped from the comparison entirely, same as
// hashExcluding; each table named in excludeColumns instead STAYS in the
// comparison, but has the named column(s) stripped from every row before
// that table's own hash is recomputed -- so a difference in some OTHER
// column of that same table is still caught, while an already-documented,
// legitimately-divergent column doesn't make the whole table (and therefore
// the whole snapshot) look different. excludeColumns may be nil.
func hashExcludingColumns(snap dbSnapshot, excludeTables []string, excludeColumns map[string][]string) string {
	exclude := make(map[string]bool, len(excludeTables))
	for _, t := range excludeTables {
		exclude[t] = true
	}
	var lines []string
	for name, ts := range snap.Tables {
		if exclude[name] {
			continue
		}
		h := ts.Hash
		if cols := excludeColumns[name]; len(cols) > 0 {
			h = rowsHashExcludingColumns(ts.Rows, cols)
		}
		lines = append(lines, name+":"+h)
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}

// rowsHashExcludingColumns recomputes one table's canonical hash (same
// construction snapshotDB uses: sorted per-row JSON, newline-joined, SHA-256)
// with columns stripped from each row's already-canonicalized JSON first.
// rows are always this file's own canonicalRow output (sorted-key JSON of a
// model's exported, non-excluded fields -- see snapshot_test.go) and never
// fuzz input; a row that fails to parse as JSON is kept as-is rather than
// silently dropped, since that would only happen if canonicalRow's own
// output shape changed underneath this function.
func rowsHashExcludingColumns(rows []string, columns []string) string {
	strip := make(map[string]bool, len(columns))
	for _, c := range columns {
		strip[c] = true
	}
	canon := make([]string, 0, len(rows))
	for _, row := range rows {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(row), &fields); err != nil {
			canon = append(canon, row)
			continue
		}
		for c := range strip {
			delete(fields, c)
		}
		b, err := json.Marshal(fields) // map[string]json.RawMessage marshals with sorted keys
		if err != nil {
			canon = append(canon, row)
			continue
		}
		canon = append(canon, string(b))
	}
	sort.Strings(canon)
	h := sha256.Sum256([]byte(strings.Join(canon, "\n")))
	return hex.EncodeToString(h[:])
}

// TestOpScopedAcceptableByDesign_ProjectWithTransaction_RequiresNthCallTwo is
// the coordinator-requested split-out check (PR #2252 review) for the
// "REST POST /api/v1/projects"/WithTransaction/[Environment] exemption above:
// it must not accept a fault on WithTransaction call #1 (the OUTER
// transaction wrapping the whole CreateProject) as this well-understood
// per-environment-SAVEPOINT tradeoff — only call #2+ (a per-environment
// SAVEPOINT) is the documented, accepted case. Red without minNthCall (or
// with it reverted to 0): NthCall=1 would also return true here, silently
// widening the exemption to the outer transaction fault this entry's own doc
// comment says never even reaches this success-branch check in practice —
// this test pins that assumption as an explicit, checked invariant rather
// than an implicit one.
//
// Extended for the session-M follow-up (inbox/CORE.md's "2026-09-30
// session-m" entry) with the requireLogSubstring cases: an Environment-only
// diff at a qualifying NthCall must ALSO have the warning log actually
// present — a planted bug that silently skips env seeding with no warning
// (e.g. a swallowed error that never reaches catalog.go's log.Printf) must
// stay a violation, not get waved through just because the diff shape
// matches. Red without the requireLogSubstring check: the "no log" and
// "unrelated log" cases below would both wrongly return true.
func TestOpScopedAcceptableByDesign_ProjectWithTransaction_RequiresNthCallTwo(t *testing.T) {
	const op = "REST POST /api/v1/projects"
	const method = "WithTransaction"
	const warningLog = `2026/10/02 14:13:33 Warning: project 2 (fuzz-project) created without its environment "production": fault-fuzz injected failure` + "\n"

	assert.False(t, opScopedAcceptableByDesign(op, method, 1, []string{"Environment"}, warningLog),
		"NthCall=1 (the OUTER transaction) must NOT be exempted -- only an inner per-environment SAVEPOINT fault (NthCall>=2) is the documented, accepted tradeoff")
	assert.True(t, opScopedAcceptableByDesign(op, method, 2, []string{"Environment"}, warningLog),
		"NthCall=2 (the first per-environment SAVEPOINT) with an Environment-only diff AND the warning log present must be exempted")
	assert.True(t, opScopedAcceptableByDesign(op, method, 5, []string{"Environment"}, warningLog),
		"a later per-environment SAVEPOINT (NthCall=5) must be exempted the same way as NthCall=2")
	assert.False(t, opScopedAcceptableByDesign(op, method, 2, []string{"Environment", "Project"}, warningLog),
		"a diff touching a table OUTSIDE the allowed set must never be exempted, regardless of NthCall or log evidence")
	assert.False(t, opScopedAcceptableByDesign("REST POST /api/v1/other", method, 2, []string{"Environment"}, warningLog),
		"an unrelated op must never match this op-scoped entry")
	assert.False(t, opScopedAcceptableByDesign(op, method, 2, []string{"Environment"}, ""),
		"EVIDENCE REQUIRED: an Environment-only diff with NO captured log output must NOT be exempted -- a silent env-seed skip (no warning logged) stays an oracle (a) violation")
	assert.False(t, opScopedAcceptableByDesign(op, method, 2, []string{"Environment"}, "some unrelated log line\n"),
		"EVIDENCE REQUIRED: log output present but not containing the specific warning substring must NOT be exempted")
}

// TestOpScopedAcceptableByDesign_UnrestrictedEntriesIgnoreNthCall proves the
// two pre-existing opScopedBestEffortTables entries (minNthCall: 0 and
// requireLogSubstring: "", both zero values) are unaffected by adding
// minNthCall/requireLogSubstring to the struct -- they must keep matching at
// every NthCall with no log evidence required, exactly as before either
// field existed.
func TestOpScopedAcceptableByDesign_UnrestrictedEntriesIgnoreNthCall(t *testing.T) {
	assert.True(t, opScopedAcceptableByDesign("REST POST /api/v1/users/", "AssignRole", 1, []string{"UserRole"}, ""))
	assert.True(t, opScopedAcceptableByDesign("REST POST /api/v1/users/", "GetRoleByName", 99, []string{"UserRole"}, ""))
}

// TestHashExcludingColumns_ColumnScopedExclusion is #2410's direct proof:
// excluding one column from one table must mask ONLY a change isolated to
// that column, and still catch a change to any OTHER column on the same
// table -- the exact distinction a whole-table exclusion (hashExcluding, and
// the effectThenErrorExtraExclusions `tables` field) cannot make, and
// exactly why this entry needed `columns` instead.
func TestHashExcludingColumns_ColumnScopedExclusion(t *testing.T) {
	mkSnap := func(revokeError, other string) dbSnapshot {
		row := fmt.Sprintf(`{"Other":%q,"RevokeError":%q}`, other, revokeError)
		h := sha256.Sum256([]byte(row))
		ts := tableSnapshot{Table: "DynamicSecretLease", Hash: hex.EncodeToString(h[:]), Rows: []string{row}}
		return dbSnapshot{Tables: map[string]tableSnapshot{"DynamicSecretLease": ts}}
	}

	base := mkSnap("", "same")
	onlyRevokeErrorDiffers := mkSnap("boom", "same")
	otherColumnDiffers := mkSnap("", "different")

	excludeColumns := map[string][]string{"DynamicSecretLease": {"RevokeError"}}

	assert.Equal(t,
		hashExcludingColumns(base, nil, excludeColumns),
		hashExcludingColumns(onlyRevokeErrorDiffers, nil, excludeColumns),
		"a change isolated to the excluded column must not change the hash")

	assert.NotEqual(t,
		hashExcludingColumns(base, nil, excludeColumns),
		hashExcludingColumns(otherColumnDiffers, nil, excludeColumns),
		"a change to a DIFFERENT column on the same table must still be caught -- column exclusion must not become a whole-table one")
}

// TestHashExcludingColumns_MatchesHashExcludingWhenNoColumns proves
// hashExcludingColumns, called with a nil excludeColumns map, reduces to
// exactly hashExcluding's whole-table-exclusion behavior -- the pre-#2410
// callers of hashExcluding (world_reuse_soundness_test.go,
// mixed_principal_authority_fuzz_test.go, fuzz_shared_secrets_view_test.go)
// still call hashExcluding directly and are unaffected by this change; this
// proves the function the oracle (d) call site switched TO would have given
// them the identical answer, for the entries that only ever used `tables`.
func TestHashExcludingColumns_MatchesHashExcludingWhenNoColumns(t *testing.T) {
	snap := dbSnapshot{Tables: map[string]tableSnapshot{
		"A": {Table: "A", Hash: "aaa"},
		"B": {Table: "B", Hash: "bbb"},
	}}
	assert.Equal(t, hashExcluding(snap, "A"), hashExcludingColumns(snap, []string{"A"}, nil))
	assert.Equal(t, hashExcluding(snap), hashExcludingColumns(snap, nil, nil))
}
