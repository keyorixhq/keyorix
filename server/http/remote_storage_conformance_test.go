// remote_storage_conformance_test.go — issue #1808: differential conformance
// harness for RemoteStorage, phase 1.
//
// Seven tests below, one per defect class from remote_proxy_correctness_audit_test.go's
// KNOWN NON-COVERAGE list, each built on the actual historical defect's method where
// the task brief names one: Health (class 1), RemoveRoleFromGroup (class 2),
// CreateMachineIdentityCredential (class 3), GetSecretByName (class 4), CreateSecret
// (class 5), LockUserForUpdate (class 6), LogAuditEvent (class 7).
//
// Every test drives RemoteStorage.M(x) through a REAL server/http.NewRouter and a
// REAL LocalStorage-backed core.KeyorixCore (newConformanceHarness, in
// remote_storage_conformance_helpers_test.go), and compares its result against
// LocalStorage.M(x) against the SAME backing database — never a hand-written fake
// handler. See that file's package doc for why this is a different, complementary
// question to the existing internal/storage/store/remote_*_test.go corpus, not a
// replacement for it.
//
// See remote_storage_conformance_mutation_test.go for the historical-defect
// replay/reintroduction that validates this harness actually detects what it claims to.
package http

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- Class 1: Health ---

func TestConformance_Health(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	assert.NoError(t, h.rs.Health(ctx),
		"RemoteStorage.Health must report healthy against a real, healthy server -- the historical "+
			"class-1 bug checked resp.Success on /health's response body, but /health carries no "+
			"{success,data} envelope at all, so a genuinely healthy server was reported unhealthy "+
			"unconditionally (see remote_stats.go's Health doc)")
	assert.NoError(t, h.ls.HealthCheck(ctx),
		"LocalStorage.HealthCheck against the same backing database must also report healthy")
}

// --- Class 2: RemoveRoleFromGroup ---

func TestConformance_RemoveRoleFromGroup(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	adminRole, err := h.ls.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	scope := coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID}

	localGroup, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-rrfg-local"})
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRoleToGroup(ctx, localGroup.ID, adminRole.ID, scope))

	remoteGroup, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-rrfg-remote"})
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRoleToGroup(ctx, remoteGroup.ID, adminRole.ID, scope))

	localErr := h.ls.RemoveRoleFromGroup(ctx, localGroup.ID, adminRole.ID, scope)
	remoteErr := h.rs.RemoveRoleFromGroup(ctx, remoteGroup.ID, adminRole.ID, scope)

	require.NoError(t, localErr)
	require.NoError(t, remoteErr,
		"RemoteStorage.RemoveRoleFromGroup must succeed for a grant that genuinely exists at this scope -- "+
			"the historical class-2 bug declared the scope parameter `_`, so the outgoing DELETE always carried "+
			"a zero-value scope, which cannot match a grant assigned at a real (non-global) scope")

	localAfter, err := h.ls.ListGroupRoleAssignments(ctx, localGroup.ID)
	require.NoError(t, err)
	remoteAfter, err := h.ls.ListGroupRoleAssignments(ctx, remoteGroup.ID)
	require.NoError(t, err)

	assert.False(t, containsRoleGrant(localAfter, adminRole.ID, scope), "sanity: LocalStorage's own removal must take effect")
	assert.False(t, containsRoleGrant(remoteAfter, adminRole.ID, scope),
		"RemoteStorage.RemoveRoleFromGroup must actually remove the scoped grant, matching LocalStorage's effect on "+
			"the same backing store -- a scope-dropping bug leaves the real (non-zero-scope) grant untouched even "+
			"though the call reports success (a 'not found for scope zero' delete elsewhere would surface as an "+
			"error above instead, so this assertion and the NoError one above together cover both failure shapes)")
}

func containsRoleGrant(grants []coreStorage.RoleAssignment, roleID uint, scope coreStorage.Scope) bool {
	for _, g := range grants {
		if g.RoleID == roleID && g.ProjectID == scope.ProjectID && g.EnvironmentID == scope.EnvironmentID {
			return true
		}
	}
	return false
}

// --- Class 3: CreateMachineIdentityCredential ---

func TestConformance_CreateMachineIdentityCredential(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	miLocal, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-mic-local", core.MachineTypeNode, "conformance test node", "", h.adminUserID, 0)
	require.NoError(t, err)
	miRemote, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-mic-remote", core.MachineTypeNode, "conformance test node", "", h.adminUserID, 0)
	require.NoError(t, err)

	expiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	newCred := func(machineID uint, suffix string) *models.MachineIdentityCredential {
		return &models.MachineIdentityCredential{
			MachineIdentityID: machineID,
			Name:              "conformance-cred-" + suffix,
			TokenHash:         "conformance-hash-" + suffix, // must be unique (uniqueIndex)
			TokenPrefix:       "kxm_" + suffix,
			// AllowedCIDRs is the actual historical class-3 field: RemoteStorage's
			// wire struct (machineIdentityCredentialWire) used to omit it entirely,
			// silently stripping every machine token's IP allowlist on create, and
			// ClassifyMachineToken's read-mutate-Save cycle would then actively WIPE
			// a previously-set allowlist on the next classification change.
			AllowedCIDRs:   "10.0.0.0/8,192.168.1.0/24",
			ExpiresAt:      &expiry,
			Classification: "internal",
		}
	}

	// LocalStorage.CreateMachineIdentityCredential is a raw db.Create -- it returns
	// the SAME pointer it was given, now populated with DB-assigned fields, so
	// comparing input vs output can only ever pass here. It is kept as a sanity
	// baseline; the real test is RemoteStorage's below.
	localInput := newCred(miLocal.ID, "local")
	localSnapshot := *localInput
	localOut, err := h.ls.CreateMachineIdentityCredential(ctx, localInput)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateMachineIdentityCredential (input vs output, sanity baseline)",
		&localSnapshot, localOut, map[string]bool{"ID": true, "CreatedAt": true})

	// RemoteStorage.CreateMachineIdentityCredential marshals its argument to JSON
	// and returns a freshly-decoded struct from the wire response -- genuinely
	// independent of the input pointer, so this comparison is the real test: does
	// every field the caller set survive being sent over the wire and decoded back?
	remoteInput := newCred(miRemote.ID, "remote")
	remoteSnapshot := *remoteInput
	remoteOut, err := h.rs.CreateMachineIdentityCredential(ctx, remoteInput)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateMachineIdentityCredential (input vs wire round trip)",
		&remoteSnapshot, remoteOut, map[string]bool{"ID": true, "CreatedAt": true})
}

// --- Class 4: GetSecretByName ---

func TestConformance_GetSecretByName(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	created, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name:          "conformance-gsbn-secret",
		ProjectID:     h.projectID,
		EnvironmentID: h.environmentID,
		Type:          "password",
	})
	require.NoError(t, err)

	// Both reads fetch the identical DB row (same backing store) -- unlike the
	// create-path tests, there is no server-side business logic that can
	// legitimately mutate a read, so no field exclusions are needed at all: a
	// clean field-exhaustive comparison of the SAME row read two ways.
	localOut, err := h.ls.GetSecretByName(ctx, created.Name, h.projectID, h.environmentID)
	require.NoError(t, err)
	remoteOut, err := h.rs.GetSecretByName(ctx, created.Name, h.projectID, h.environmentID)
	require.NoError(t, err,
		"RemoteStorage.GetSecretByName must succeed for a secret that genuinely exists -- the historical "+
			"class-4 bug requested GET /api/v1/secrets/by-name/{name} (a path segment), a route "+
			"server/http/router.go never registered, so every call 404'd regardless of whether the secret existed")

	assertFieldExhaustiveEqual(t, "GetSecretByName (RemoteStorage vs LocalStorage, same row)",
		localOut, remoteOut, map[string]bool{})
}

// --- Class 5 (and 3): CreateSecret ---

func TestConformance_CreateSecret(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// A pre-existing secret used as the ParentID target -- the actual historical
	// class-3/5 defect was ParentID silently vanishing from the wire, creating
	// every secret at project root regardless of the caller's intended folder
	// placement (secretCreateWireRequest, remote_secrets.go).
	parent, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-cs-parent", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password",
	})
	require.NoError(t, err)

	maxReads := 7
	// Description and Expiration were themselves found silently dropped from
	// this exact wire path while this test was being designed (neither
	// secretCreateWireRequest nor the handler's reqBody had a slot for
	// either) -- fixed alongside this harness, not left as a documented gap.
	// Exercising both here is what proves the fix, not just the ParentID
	// class-3/5 replay this test already covered.
	expiration := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	newSecret := func(name string) *models.SecretNode {
		return &models.SecretNode{
			Name:           name,
			ProjectID:      h.projectID,
			EnvironmentID:  h.environmentID,
			Type:           "password",
			MaxReads:       &maxReads,
			ParentID:       &parent.ID,
			Classification: "internal",
			Description:    "conformance test secret",
			Expiration:     &expiration,
		}
	}

	// Sanity baseline: LocalStorage.CreateSecret is a raw insert on the same
	// pointer it was given, so input-vs-output can only ever pass.
	localInput := newSecret("conformance-cs-local")
	localSnapshot := *localInput
	localOut, err := h.ls.CreateSecret(ctx, localInput)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateSecret (input vs output, sanity baseline)",
		&localSnapshot, localOut, map[string]bool{
			"ID": true, "CreatedAt": true, "UpdatedAt": true,
			// GORM's `gorm:"default:'active'"` tag rewrites the zero-value ""
			// this test leaves on the input to "active" at insert time -- a DB
			// default, not something either storage backend's proxy layer does.
			"Status": true,
		})

	// RemoteStorage.CreateSecret proxies onto the human-facing POST /api/v1/secrets
	// route, which runs the FULL core.CreateSecret business logic server-side (not
	// a raw storage passthrough) -- so a few fields legitimately diverge from the
	// caller's input for reasons that have nothing to do with wire fidelity. Each
	// exclusion below is independently confirmed (not assumed) against
	// internal/core/secrets.go and server/http/handlers/secrets_crud.go.
	remoteInput := newSecret("conformance-cs-remote")
	remoteSnapshot := *remoteInput
	remoteOut, err := h.rs.CreateSecret(ctx, remoteInput, "conformance-secret-value")
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateSecret (input vs wire round trip)",
		&remoteSnapshot, remoteOut, map[string]bool{
			"ID": true, "CreatedAt": true, "UpdatedAt": true,
			// core.CreateSecret hard-sets Status: "active" unconditionally
			// (internal/core/secrets.go) -- a business-logic default, not a field
			// the wire carries either way (LocalStorage converges to the same value
			// via a GORM default:'active' tag when left unset).
			"Status": true,
			// CreatedBy is never on the wire at all in either direction
			// (secretCreateWireRequest and the handler's reqBody both omit it) --
			// the server always substitutes its own authenticated actor's username.
			"CreatedBy": true,
			// ValueStored (gorm:"-" json:"-") is a process-local signal, never
			// persisted or serialized: RemoteStorage sets it true specifically
			// because it forwarded plaintextValue and the server stored version 1
			// atomically; LocalStorage's raw insert never sets it. Documented,
			// intentional divergence (remote_secrets.go's CreateSecret doc), not a
			// wire-fidelity bug.
			"ValueStored": true,
			// IsSecret is unconditionally set true by core.CreateSecret's
			// constructed secret literal (internal/core/secrets.go) for every
			// secret created through this route, regardless of the caller's
			// input -- a business-logic constant on this path, not a wire field.
			"IsSecret": true,
			// OwnerMachineIdentityID: the handler derives ownership from the
			// AUTHENTICATED CALLER's own machine identity (userCtx.MachineIdentityID),
			// never from client input -- confirmed neither wire struct nor the
			// handler's reqBody carries an owner field at all. Same reasoning as
			// CreatedBy above, just for the machine-caller ownership slot.
			"OwnerMachineIdentityID": true,
		})

	// Independently verify the create really landed server-side by reading it back
	// through the SAME LocalStorage instance the router wraps -- not just trusting
	// the HTTP response body (which class 5's historical bug shows can lie: the
	// pre-fix response envelope could itself omit a field the DB row still lacked).
	persisted, err := h.ls.GetSecret(ctx, remoteOut.ID)
	require.NoError(t, err)
	require.NotNil(t, persisted.ParentID)
	assert.Equal(t, parent.ID, *persisted.ParentID,
		"the secret actually persisted server-side must carry the caller's ParentID, not just the HTTP response")
}

// --- Class 6: LockUserForUpdate ---

func TestConformance_LockUserForUpdate(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	user, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lufu", Email: "conformance-lufu@example.com",
		DisplayName: "Conformance LockUserForUpdate", IsActive: true,
	})
	require.NoError(t, err)

	// Warm RemoteStorage's 5-minute response cache via a plain GetUser -- the
	// actual historical class-6 bug was LockUserForUpdate simply delegating to
	// GetUser and so sharing its cache, defeating the anti-TOCTOU recheck
	// LockUserForUpdate exists for (#500, remote_users.go's doc comment).
	cached, err := h.rs.GetUser(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, 0, cached.FailedLoginAttempts)

	// Mutate the row directly through LocalStorage, bypassing RemoteStorage
	// entirely -- simulating a concurrent writer (e.g. another replica's own
	// failed-login accounting) landing in the window between the cache-warming
	// GetUser above and the lock below.
	fresh, err := h.ls.GetUser(ctx, user.ID)
	require.NoError(t, err)
	const wantAttempts = 4
	fresh.FailedLoginAttempts = wantAttempts
	_, err = h.ls.UpdateUser(ctx, fresh)
	require.NoError(t, err)

	locked, err := h.rs.LockUserForUpdate(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, wantAttempts, locked.FailedLoginAttempts,
		"LockUserForUpdate must observe the genuinely current row, not GetUser's cached snapshot -- a "+
			"cache-sharing regression (the historical class-6 bug) would still report 0 here, up to 5 "+
			"minutes after the cache-warming GetUser above")

	localLocked, err := h.ls.LockUserForUpdate(ctx, user.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LockUserForUpdate (RemoteStorage vs LocalStorage, same row)",
		localLocked, locked, map[string]bool{
			// CreatedAt/UpdatedAt: this repo has an established SQLite/GORM
			// timezone-and-precision round-trip quirk (see CLAUDE.md memory,
			// "GORM SQLite timezone mismatch", fixed elsewhere via BeforeSave
			// hooks + UTC WHERE clauses) -- a value read directly through GORM
			// twice in a row for the SAME unchanged row can still surface with
			// different sub-second precision/Location than one that round-tripped
			// through this harness's HTTP/JSON envelope. Equal() already handles
			// genuine instant differences (see valuesEqual); this excludes only
			// the two timestamp fields, not the FailedLoginAttempts field the
			// class-6 cache-staleness assertion above already exercises directly.
			"CreatedAt": true, "UpdatedAt": true,
		})
}

// --- Class 7: LogAuditEvent ---

func TestConformance_LogAuditEvent(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	t.Run("normal write lands identically", func(t *testing.T) {
		remoteEvent := &models.AuditEvent{
			EventType: "conformance.remote", IPAddress: "203.0.113.20",
			Description: fmt.Sprintf("conformance remote audit event %d", time.Now().UnixNano()),
			EventTime:   time.Now().UTC(),
		}
		require.NoError(t, h.rs.LogAuditEvent(ctx, remoteEvent))

		found := findAuditEventByDescription(t, h.ls, ctx, remoteEvent.Description)
		require.NotNil(t, found, "RemoteStorage.LogAuditEvent must actually persist the event server-side")
		assert.Equal(t, remoteEvent.EventType, found.EventType)
		assert.Equal(t, remoteEvent.IPAddress, found.IPAddress)
	})

	// Class 7 needs the caller's context cancelled mid-flight, with an assertion
	// that the audit write still lands -- merely passing a context through does
	// not test this (see remote_proxy_correctness_audit_test.go's class-7 note: a
	// check whose condition for "correct" is that ctx IS forwarded verbatim
	// CERTIFIES the defect on an audit-emitting path, it doesn't miss it neutrally).
	// An already-cancelled context is the deterministic limit case of "cancelled
	// mid-flight": if LogAuditEvent forwards ctx instead of detaching
	// (auditWriteContext), the outbound HTTP call fails immediately with
	// context.Canceled before a single byte reaches the wire -- so both the
	// returned error AND independent server-side persistence must be checked.
	t.Run("caller's context cancelled before the call still lands (#1650, class 7)", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		localEvent := &models.AuditEvent{
			EventType: "conformance.local.cancelled", IPAddress: "203.0.113.30",
			Description: fmt.Sprintf("conformance cancelled-ctx local %d", time.Now().UnixNano()),
			EventTime:   time.Now().UTC(),
		}
		require.NoError(t, h.ls.LogAuditEvent(cancelledCtx, localEvent),
			"LocalStorage.LogAuditEvent must detach from an already-cancelled caller context (auditWriteContext)")

		remoteEvent := &models.AuditEvent{
			EventType: "conformance.remote.cancelled", IPAddress: "203.0.113.40",
			Description: fmt.Sprintf("conformance cancelled-ctx remote %d", time.Now().UnixNano()),
			EventTime:   time.Now().UTC(),
		}
		require.NoError(t, h.rs.LogAuditEvent(cancelledCtx, remoteEvent),
			"RemoteStorage.LogAuditEvent must detach from an already-cancelled caller context before the "+
				"outbound HTTP call -- forwarding it verbatim (the historical class-7 bug) makes the "+
				"request fail immediately with context.Canceled")

		assert.NotNil(t, findAuditEventByDescription(t, h.ls, ctx, localEvent.Description),
			"the local write must actually be persisted, not just return a nil error")
		assert.NotNil(t, findAuditEventByDescription(t, h.ls, ctx, remoteEvent.Description),
			"the remote write must actually be persisted server-side, not just return a nil error -- this "+
				"is the assertion a context-cancellation test must make, per the task brief: 'a test that "+
				"merely passes a context is not testing this'")
	})
}

func findAuditEventByDescription(t *testing.T, ls *store.LocalStorage, ctx context.Context, description string) *models.AuditEvent {
	t.Helper()
	events, _, err := ls.GetAuditLogs(ctx, &coreStorage.AuditFilter{Page: 1, PageSize: 500})
	require.NoError(t, err)
	for _, e := range events {
		if e.Description == description {
			return e
		}
	}
	return nil
}
