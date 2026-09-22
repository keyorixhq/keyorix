package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// coreSeqModels is the migration set for FuzzCoreOperationSequence's world.
var coreSeqModels = []any{
	&models.Project{}, &models.Environment{},
	&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{},
	&models.ShareRecord{}, &models.SecretACL{},
	&models.User{}, &models.Group{}, &models.UserGroup{},
	&models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.GroupRole{},
	&models.SoDPolicy{}, &models.AuditEvent{}, &models.Session{},
}

// coreSeqResetTables is the explicit, hand-named table list fuzzCoreResetTables
// clears between iterations that reuse the same per-worker world (see
// fuzzworld_test.go's RESET SCOPE note). Dependent-first order.
var coreSeqResetTables = []string{
	"role_permissions", "user_roles", "group_roles", "user_groups",
	"secret_versions", "secret_access_schedules", "share_records", "secret_acls", "secret_nodes",
	"environments", "projects",
	"sod_policies", "audit_events", "sessions",
	"users", "groups", "roles", "permissions",
}

// coreCurrentSizes/coreTransitionSizes are FuzzCoreOperationSequence's abstract
// security-state tuple, bucketed into small enums and encoded via
// fuzzutil.PackTuple. This harness has no tokens, sessions, cache, or tenant
// variation (one project throughout, no HTTP layer) -- so, unlike the HTTP
// harness below, the tuple is deliberately narrow: only the axes that
// correspond to a real state distinction this harness can actually reach.
//
//	opKind (5):           create / grant / revoke / read / rotate (op % 5)
//	principal (3):        the targeted principal's index; 0 (n/a) for
//	                       create/rotate, which never target a principal
//	roleState (2):        targeted principal's canRead BEFORE this op; 0 (n/a)
//	                       for create/rotate
//	secretPopulation (3): len(secretIDs) bucketed {0, 1, 2+}
//
// coreTransitionSizes prepends priorOutcome (3: none-yet / success /
// business-deny -- see runCoreSeqIteration's outcome tracking; a guard
// timeout aborts the test via t.Fatalf before a next step could run, so it is
// not a reachable bucket here and is deliberately not modeled).
//
// Not modeled at all: impersonation (no such op exists in this harness) --
// its future home is the mixed-principal authority fuzzer, not this one.
var (
	coreCurrentSizes    = []int{5, 3, 2, 3}
	coreTransitionSizes = []int{3, 5, 3, 2, 3}

	coreCurrentBase    = 0
	coreTransitionBase = coreCurrentBase + fuzzutil.TupleSpace(coreCurrentSizes)

	coreOpKindNames  = []string{"create", "grant", "revoke", "read", "rotate"}
	coreOutcomeNames = []string{"none-yet", "success", "business-deny"}
)

// coreCurrentLabel/coreTransitionLabel render a tuple human-readably for
// FUZZ_STATE_REPORT (fuzzutil.StateReport) -- the SAME functions
// TestEnumerateCoreStateLabels calls to build the full enumerable space, so
// the report and the enumeration can never drift apart.
func coreCurrentLabel(kind, principal, roleState, pop int) string {
	return fmt.Sprintf("core/current op=%s principal=%d roleState=%d secretPop=%d",
		coreOpKindNames[kind], principal, roleState, pop)
}

func coreTransitionLabel(prior, kind, principal, roleState, pop int) string {
	return fmt.Sprintf("core/transition priorOutcome=%s op=%s principal=%d roleState=%d secretPop=%d",
		coreOutcomeNames[prior], coreOpKindNames[kind], principal, roleState, pop)
}

// FuzzCoreOperationSequence is a stateful, model-based fuzzer for KeyorixCore: it
// drives a fuzzer-chosen SEQUENCE of create / grant / revoke / read / rotate
// operations, with the acting principal varied per step, against a real core over
// an in-memory store, and checks each step against a tiny shadow model that IS the
// oracle. This reaches the bug class a single-call harness cannot: an outcome that
// only breaks ACROSS operations — a revoke that doesn't take effect, a grant that
// leaks, a read allowed after the role behind it was removed, or a rotation that
// loses or corrupts the stored value.
//
// Two sound invariant families (each asserted only in the direction a
// trivially-correct model is certain of — never "grant ⇒ must succeed"):
//
//	FAIL-CLOSED (authz): if the model says principal P does NOT currently hold read,
//	GetSecretValueWithPermissionCheck(secret, P) MUST be denied — it must never
//	return plaintext. We assert the DENY direction only; an allow can carry extra
//	legitimate conditions.
//
//	PRESERVE-DATA (integrity): after a create or a rotate, the admin (who bypasses
//	permission checks) MUST read back exactly the value the model last wrote — the
//	plaintext round-trips through the real encrypt→store→decrypt path. And when an
//	authorized principal's read SUCCEEDS, the plaintext it returns must equal the
//	model value too (integrity conditional on success, so it can't false-positive).
//
// The three fuzzable principals are deliberately non-admin and own no secrets (the
// admin fixture creates, owns, and rotates every secret), so the only path to read
// is the reader role we grant/revoke — which makes the model's canRead an exact
// predicate, and makes the admin the trusted oracle for the current value.
//
// NOTE on scope: audit-completeness is deliberately NOT asserted here. In keyorix
// the secret.created / secret.rotated audit events are emitted by the HANDLER layer
// (HTTP/gRPC/CLI), which carries the authenticated actor/IP/UA — core.CreateSecret /
// core.RotateSecret do not self-audit by design. Asserting "each core mutation
// appends an audit event" would therefore FAIL on correct code. Audit-completeness
// belongs to a handler/service-level harness and is tracked separately.
func FuzzCoreOperationSequence(f *testing.F) {
	const (
		adminRoleID  = 900
		readerRoleID = 901
		readPermID   = 900
		adminUserID  = 1
	)
	// principal user IDs the fuzzer drives (none is admin; none owns a secret).
	principals := []uint{2, 3, 4}

	newWorld := func(t *testing.T, w *fuzzCoreDBWorld) (*KeyorixCore, *store.LocalStorage, uint, uint) {
		t.Helper()
		fuzzCoreResetTables(t, w, coreSeqResetTables)
		db := w.db
		ls := store.NewLocalStorage(db)
		ctx := context.Background()

		// --- fixed world: project + environment (store layer, no authz) ---
		proj, err := ls.CreateProject(ctx, &models.Project{Name: "projA"})
		if err != nil {
			t.Fatalf("create project: %v", err)
		}
		env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
		if err != nil {
			t.Fatalf("create env: %v", err)
		}

		// --- roles/permissions seeded directly (fast, deterministic) ---
		// admin bypasses all checks (ADR-084: the flag, not the name); reader carries
		// secrets.read and is what the fuzzer grants/revokes at project scope.
		mustCreate := func(v interface{}) {
			if err := db.Create(v).Error; err != nil {
				t.Fatalf("seed %T: %v", v, err)
			}
		}
		mustCreate(&models.Role{ID: adminRoleID, Name: "fuzz-admin", NameFolded: "fuzz-admin", BypassesPermissionChecks: true})
		mustCreate(&models.Role{ID: readerRoleID, Name: "fuzz-reader", NameFolded: "fuzz-reader"})
		mustCreate(&models.Permission{ID: readPermID, Name: "secrets.read", Resource: "secrets", Action: "read"})
		mustCreate(&models.RolePermission{RoleID: readerRoleID, PermissionID: readPermID})

		mkUser := func(id uint) {
			mustCreate(&models.User{
				ID: id, Username: fmt.Sprintf("u%d", id), UsernameFolded: fmt.Sprintf("u%d", id),
				Email: fmt.Sprintf("u%d@x.io", id), EmailFolded: fmt.Sprintf("u%d@x.io", id), IsActive: true,
			})
		}
		mkUser(adminUserID)
		mustCreate(&models.UserRole{UserID: adminUserID, RoleID: adminRoleID}) // global admin
		for _, p := range principals {
			mkUser(p)
		}

		c := NewKeyorixCore(ls)
		return c, ls, proj.ID, env.ID
	}

	// admin creates one secret so there is always a target; returns its ID.
	createSecret := func(t *testing.T, c *KeyorixCore, projID, envID uint, name string, val []byte) (uint, bool) {
		t.Helper()
		s, err := c.CreateSecret(context.Background(), &CreateSecretRequest{
			Name: name, Value: val, ProjectID: projID, EnvironmentID: envID,
			Type: "password", CreatedBy: "fuzz-admin", OwnerID: adminUserID,
		})
		if err != nil || s == nil {
			return 0, false
		}
		return s.ID, true
	}

	// Built ONCE per testing.F, before f.Fuzz -- see fuzzworld_test.go's PERFORMANCE note.
	// SQLite always; PostgreSQL too when KEYORIX_TEST_PG_DSN is set.
	worlds := buildFuzzCoreDBWorlds(f, "coreseqfuzz", coreSeqModels)

	f.Add([]byte{0, 0, 1, 0, 3, 0, 2, 0, 3, 0})
	f.Add([]byte{0, 1, 3, 1, 1, 1, 3, 4, 2, 1, 3, 4})
	f.Add([]byte{0, 0, 4, 0, 9, 3, 0, 0, 1, 2, 3, 2}) // create, rotate, read
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		for _, w := range worlds {
			runCoreSeqIteration(t, w, program, newWorld, createSecret, principals, adminRoleID, readerRoleID, adminUserID)
		}
	})
}

func runCoreSeqIteration(
	t *testing.T, w *fuzzCoreDBWorld, program []byte,
	newWorld func(*testing.T, *fuzzCoreDBWorld) (*KeyorixCore, *store.LocalStorage, uint, uint),
	createSecret func(*testing.T, *KeyorixCore, uint, uint, string, []byte) (uint, bool),
	principals []uint, adminRoleID, readerRoleID, adminUserID uint,
) {
	t.Helper()
	c, _, projID, envID := newWorld(t, w)
	ctx := context.Background()
	scope := Scope{ProjectID: projID}

	// shadow model:
	//   canRead[userID] mirrors the REAL grant state (updated only on a nil-error
	//   grant/revoke); value[secretID] is the plaintext the model last wrote via a
	//   successful create/rotate (the admin is the trusted oracle for it).
	canRead := map[uint]bool{}
	value := map[uint][]byte{}
	var secretIDs []uint
	secretSeq, rotateSeq := 0, 0

	// state-edge bookkeeping: a fresh gate per iteration (one fuzz input), so
	// revisiting the same abstract state twice within one input doesn't
	// re-fire the edge -- see fuzzutil.StateEdgeGate. priorOutcome feeds the
	// transition-pair tuple; see coreTransitionSizes' doc comment for its
	// 3-value domain (guard-timeout is unreachable, not modeled).
	edgeGate := fuzzutil.NewStateEdgeGate()
	const (
		outcomeNoneYet = iota
		outcomeSuccess
		outcomeBusinessDeny
	)
	priorOutcome := outcomeNoneYet
	secretPopBucket := func() int {
		switch {
		case len(secretIDs) == 0:
			return 0
		case len(secretIDs) == 1:
			return 1
		default:
			return 2
		}
	}

	// assertAdminValue enforces PRESERVE-DATA: the admin bypasses permission checks
	// and our secrets are unclassified with no max-reads, so a successful create or
	// rotate MUST leave the value admin-readable and byte-identical to the model.
	assertAdminValue := func(sid uint, want []byte) {
		var got []byte
		var aerr error
		fuzzutil.Guard(t.Fatalf, "admin GetSecretValueWithPermissionCheck", func() {
			got, aerr = c.GetSecretValueWithPermissionCheck(ctx, sid, adminUserID)
		})
		if aerr != nil {
			t.Fatalf("DATA LOSS/AVAILABILITY: admin cannot read secret %d after a successful mutation: %v", sid, aerr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("DATA CORRUPTION: secret %d admin-read=%q want=%q", sid, got, want)
		}
	}

	step := func(op, a, b byte) {
		kind := int(op % 5)

		// principal/roleState are only meaningful for ops that target a principal
		// (grant/revoke/read); create/rotate are admin-only, so they bucket to the
		// fixed n/a value 0 rather than fabricating a distinction that isn't there.
		principalIdx := 0
		roleState := 0
		if kind == 1 || kind == 2 || kind == 3 {
			principalIdx = int(a) % len(principals)
			if canRead[principals[principalIdx]] {
				roleState = 1
			}
		}
		pop := secretPopBucket()

		curKey := fuzzutil.PackTuple([]int{kind, principalIdx, roleState, pop}, coreCurrentSizes)
		edgeGate.FireOnce(uint32(coreCurrentBase + curKey))
		transKey := fuzzutil.PackTuple([]int{priorOutcome, kind, principalIdx, roleState, pop}, coreTransitionSizes)
		edgeGate.FireOnce(uint32(coreTransitionBase + transKey))
		if fuzzutil.StateReportEnabled() {
			fuzzutil.StateReport(coreCurrentLabel(kind, principalIdx, roleState, pop))
			fuzzutil.StateReport(coreTransitionLabel(priorOutcome, kind, principalIdx, roleState, pop))
		}

		// outcome defaults to business-deny: every early "no target yet" return
		// below (case 3/4 with no secret created yet) falls through this default
		// via the defer, exactly like a real denial would.
		outcome := outcomeBusinessDeny
		defer func() { priorOutcome = outcome }()

		switch kind {
		case 0: // admin creates a secret
			secretSeq++
			val := []byte{a, b}
			if id, ok := createSecret(t, c, projID, envID, fmt.Sprintf("s%d", secretSeq), val); ok {
				secretIDs = append(secretIDs, id)
				value[id] = val
				assertAdminValue(id, val) // round-trip integrity on create
				outcome = outcomeSuccess
			}
		case 1: // grant reader to a principal (system actor 0 bypasses the grant ceiling)
			u := principals[principalIdx]
			if err := c.AssignUserRole(ctx, 0, u, readerRoleID, scope, false); err == nil {
				canRead[u] = true
				outcome = outcomeSuccess
			}
		case 2: // revoke reader from a principal
			u := principals[principalIdx]
			if err := c.RemoveUserRole(ctx, 0, u, readerRoleID, scope); err == nil {
				canRead[u] = false
				outcome = outcomeSuccess
			}
		case 3: // a principal attempts a permission-checked VALUE read
			if len(secretIDs) == 0 {
				return
			}
			u := principals[principalIdx]
			sid := secretIDs[int(b)%len(secretIDs)]
			var got []byte
			var rerr error
			fuzzutil.Guard(t.Fatalf, "GetSecretValueWithPermissionCheck", func() {
				got, rerr = c.GetSecretValueWithPermissionCheck(ctx, sid, u)
			})
			if rerr == nil {
				outcome = outcomeSuccess
			}
			if !canRead[u] {
				// Fail-closed: no read-granting role, owns nothing → must be denied,
				// and must NOT leak plaintext.
				if rerr == nil {
					t.Fatalf("AUTHZ BYPASS: principal %d read secret %d plaintext with no read grant (canRead=false): %q", u, sid, got)
				}
			} else if rerr == nil {
				// Authorized AND succeeded → the plaintext must equal the model value
				// (integrity through the permission path; conditional on success so an
				// extra legitimate deny-condition can't false-positive).
				if !bytes.Equal(got, value[sid]) {
					t.Fatalf("INTEGRITY: principal %d read secret %d got=%q want=%q", u, sid, got, value[sid])
				}
			}
			if rerr != nil && got != nil {
				t.Fatalf("result-shape: denied read returned non-nil plaintext (id=%d principal=%d): %q", sid, u, got)
			}
		case 4: // admin rotates a secret to a fresh, distinct value
			if len(secretIDs) == 0 {
				return
			}
			sid := secretIDs[int(a)%len(secretIDs)]
			rotateSeq++
			// A 5-byte value keyed on rotateSeq is never equal to a 2-byte create
			// value nor to another rotation, so RotateSecret always performs a REAL
			// rotation (never the identical-value no-op path) — the model's value is
			// then the unambiguous post-rotation ground truth.
			newVal := []byte{0xAA, byte(rotateSeq >> 8), byte(rotateSeq), a, b}
			var rerr error
			fuzzutil.Guard(t.Fatalf, "RotateSecret", func() {
				_, rerr = c.RotateSecret(ctx, sid, newVal, adminUserID, "fuzz-admin")
			})
			if rerr == nil {
				value[sid] = newVal
				assertAdminValue(sid, newVal) // rotation preserved data, no loss/corruption
				outcome = outcomeSuccess
			}
		}
	}

	// decode the program: 3 bytes per step (op, a, b), bounded.
	const maxSteps = 32
	steps := 0
	for i := 0; i+2 < len(program) && steps < maxSteps; i += 3 {
		step(program[i], program[i+1], program[i+2])
		steps++
	}
	// ensure at least one secret + one read exercised on short inputs
	if len(secretIDs) == 0 {
		if id, ok := createSecret(t, c, projID, envID, "s-seed", []byte("v")); ok {
			secretIDs = append(secretIDs, id)
			value[id] = []byte("v")
		}
	}
	if len(secretIDs) > 0 {
		step(3, 0, 0) // outsider read of secret 0 — must be denied (canRead false unless granted)
	}
}
