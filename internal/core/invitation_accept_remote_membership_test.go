package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// This file proves the #511 fix for the ACTUAL real-world caller it unblocks:
// applyInvitationGrants (invitations.go) — not the CreateProjectMembership/
// GetActiveProjectMembership storage primitives in isolation (already covered,
// against the real production router/handlers, by
// server/http/remote_storage_project_memberships_test.go).
//
// applyInvitationGrants is unexported, and its only exported entry point
// (setup_consume.go's CompleteSetup → completeInvitationAccept) additionally
// requires SetupToken CRUD to resolve the raw token — RemoteStorage's SetupToken
// methods are ENTIRELY stubbed (#510, a separate, already-filed finding, not
// #511's to fix). Reaching applyInvitationGrants from outside package core
// therefore isn't possible today without also closing #510. Matching this
// package's own established test convention for exercising this exact method
// (TestApplyInvitationGrants_GlobalInvite, invitation_global_test.go) — a
// same-package test calling c.applyInvitationGrants directly — this test does
// the same, but backs ONLY the two storage.Storage methods #511 actually
// implements (CreateProjectMembership, GetActiveProjectMembership) with a REAL
// store.RemoteStorage client making REAL HTTP calls against a REAL server, while
// every other storage.Storage method the call path touches
// (GetRoleByName, GetProject, LogAuditEvent) stays mocked exactly as
// TestApplyInvitationGrants_GlobalInvite already does — those are unrelated,
// separately-filed gaps (#512's missing GetRoleByName route,
// RemoteStorage.GetProject's blanket "remoteUnsupported" stub), not #511's to
// fix, and mocking them keeps this test isolated to what #511 actually changed.

// membershipTestWire mirrors internal/storage/store's (unexported) membershipWire
// and server/http/handlers' (unexported) membershipProxyWire field-for-field —
// this package can reach neither directly (store's types are unexported; handlers
// can't be imported here at all without an import cycle, since handlers already
// imports core) — so the server side of this test's httptest handler is written
// against an independent copy of the exact same wire contract.
type membershipTestWire struct {
	ID          uint       `json:"id"`
	ProjectID   uint       `json:"project_id"`
	UserID      uint       `json:"user_id"`
	Role        string     `json:"role"`
	State       string     `json:"state"`
	InvitedBy   uint       `json:"invited_by"`
	InvitedAt   time.Time  `json:"invited_at"`
	ActivatedAt *time.Time `json:"activated_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func newMembershipTestWire(m *models.ProjectMembership) membershipTestWire {
	return membershipTestWire{
		ID: m.ID, ProjectID: m.ProjectID, UserID: m.UserID, Role: m.Role, State: m.State,
		InvitedBy: m.InvitedBy, InvitedAt: m.InvitedAt, ActivatedAt: m.ActivatedAt,
		RevokedAt: m.RevokedAt, UpdatedAt: m.UpdatedAt,
	}
}

func (w membershipTestWire) toModel() *models.ProjectMembership {
	return &models.ProjectMembership{
		ID: w.ID, ProjectID: w.ProjectID, UserID: w.UserID, Role: w.Role, State: w.State,
		InvitedBy: w.InvitedBy, InvitedAt: w.InvitedAt, ActivatedAt: w.ActivatedAt,
		RevokedAt: w.RevokedAt, UpdatedAt: w.UpdatedAt,
	}
}

type testRemoteAPIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func writeTestRemoteSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(testRemoteAPIResponse{Success: true, Data: data})
}

func writeTestRemoteError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(testRemoteAPIResponse{Success: false, Error: &struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: msg}})
}

// remoteMembershipStorage wraps MockStorage, delegating ONLY
// CreateProjectMembership/GetActiveProjectMembership — the two primitives
// applyInvitationGrants' project-scoped path (inviteMemberWithMode) actually
// calls — to a real store.RemoteStorage client. Every other storage.Storage
// method stays on the embedded MockStorage, stubbed per-test exactly as
// TestApplyInvitationGrants_GlobalInvite already does.
type remoteMembershipStorage struct {
	*MockStorage
	rs *store.RemoteStorage
}

func (s *remoteMembershipStorage) CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error) {
	return s.rs.CreateProjectMembership(ctx, m)
}

func (s *remoteMembershipStorage) GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error) {
	return s.rs.GetActiveProjectMembership(ctx, projectID, userID)
}

// newRemoteMembershipStorage builds a remoteMembershipStorage: a real upstream
// store.LocalStorage (real SQLite, real DB-level uniq_project_memberships_active
// partial unique index, #309) served over a real httptest.Server whose handler
// reproduces server/http/handlers/project_memberships_proxy.go's exact wire
// contract for POST /api/v1/system/project-memberships and
// GET /api/v1/system/project-memberships/active — fronted by a real
// store.RemoteStorage client, so CreateProjectMembership/GetActiveProjectMembership
// genuinely round-trip over HTTP, not an in-process shortcut.
func newRemoteMembershipStorage(t *testing.T, mockBase *MockStorage) *remoteMembershipStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ProjectMembership{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error)
	upstream := store.NewLocalStorage(db)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/system/project-memberships", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeTestRemoteError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "unsupported method")
			return
		}
		var body membershipTestWire
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeTestRemoteError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
			return
		}
		created, err := upstream.CreateProjectMembership(r.Context(), body.toModel())
		if err != nil {
			if errors.Is(err, coreStorage.ErrDuplicateActiveMembership) {
				writeTestRemoteError(w, http.StatusConflict, "DUPLICATE_ACTIVE_MEMBERSHIP", coreStorage.ErrDuplicateActiveMembership.Error())
				return
			}
			writeTestRemoteError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error())
			return
		}
		writeTestRemoteSuccess(w, newMembershipTestWire(created))
	})
	mux.HandleFunc("/api/v1/system/project-memberships/active", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var projectID, userID uint
		_, _ = fmt.Sscanf(q.Get("project_id"), "%d", &projectID)
		_, _ = fmt.Sscanf(q.Get("user_id"), "%d", &userID)
		m, err := upstream.GetActiveProjectMembership(r.Context(), projectID, userID)
		if err != nil {
			writeTestRemoteError(w, http.StatusNotFound, "NOT_FOUND", "no active membership")
			return
		}
		writeTestRemoteSuccess(w, newMembershipTestWire(m))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: srv.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: false,
	})
	require.NoError(t, err)

	return &remoteMembershipStorage{MockStorage: mockBase, rs: rs}
}

// TestApplyInvitationGrants_ProjectScopedInvite_RemoteMembershipStorage is the
// critical #511 proof: applyInvitationGrants — the REAL, unmodified core method
// completeInvitationAccept calls on every invitation accept — successfully
// materializes a project membership when its storage backend's
// CreateProjectMembership/GetActiveProjectMembership are the real
// storage.type: remote implementation this PR adds, not
// ErrRemoteUnsupported. Before this fix, this exact call always failed with
// "operation not supported in remote (client) mode".
func TestApplyInvitationGrants_ProjectScopedInvite_RemoteMembershipStorage(t *testing.T) {
	ms := new(MockStorage)
	rms := newRemoteMembershipStorage(t, ms)

	ctx := context.Background()
	const projectID, userID, invitedBy = uint(1), uint(20), uint(9)

	ms.On("GetRoleByName", ctx, "viewer").Return(&models.Role{ID: 6, Name: "viewer"}, nil)
	ms.On("GetProject", ctx, projectID).Return(&models.Project{ID: projectID, Name: "proj"}, nil)
	anyAudit(ms)

	fixed := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: rms, now: func() time.Time { return fixed }}

	// Allowlist mode: the membership starts "invited", not "active" — so this
	// exercises applyInvitationGrants without also needing AddProjectMember's
	// role-grant side effect (an unrelated, already-working code path).
	inv := &models.ProjectInvitation{
		ID: 1, ProjectID: projectID, Email: "invitee@example.com", Role: "viewer",
		InvitedBy: invitedBy, ValidationModeAtInvite: ValidationModeAllowlist,
	}

	err := c.applyInvitationGrants(ctx, inv, userID)
	require.NoError(t, err, "applyInvitationGrants must materialize the membership via storage.type: remote")

	// Confirm the membership genuinely landed on the upstream (over the real
	// RemoteStorage client, hitting the real HTTP server), not merely that the
	// call didn't error.
	m, err := rms.GetActiveProjectMembership(ctx, projectID, userID)
	require.NoError(t, err)
	assert.Equal(t, userID, m.UserID)
	assert.Equal(t, "viewer", m.Role)
	assert.Equal(t, MembershipInvited, m.State)

	ms.AssertExpectations(t)
}

// TestApplyInvitationGrants_ProjectScopedInvite_DuplicateMembership proves that
// a second invitation accept for a user who already has a non-revoked membership
// in the target project surfaces the SAME clean "already has a membership" error
// applyInvitationGrants produces against LocalStorage — i.e. the #309
// duplicate-active-membership guarantee (DB-level unique index +
// storage.ErrDuplicateActiveMembership sentinel translation, #511) survives the
// HTTP hop end to end through the real caller, not just the storage primitive.
func TestApplyInvitationGrants_ProjectScopedInvite_DuplicateMembership(t *testing.T) {
	ms := new(MockStorage)
	rms := newRemoteMembershipStorage(t, ms)

	ctx := context.Background()
	const projectID, userID, invitedBy = uint(1), uint(20), uint(9)

	ms.On("GetRoleByName", ctx, "viewer").Return(&models.Role{ID: 6, Name: "viewer"}, nil)
	ms.On("GetProject", ctx, projectID).Return(&models.Project{ID: projectID, Name: "proj"}, nil)
	anyAudit(ms)

	fixed := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: rms, now: func() time.Time { return fixed }}

	inv := &models.ProjectInvitation{
		ID: 1, ProjectID: projectID, Email: "invitee@example.com", Role: "viewer",
		InvitedBy: invitedBy, ValidationModeAtInvite: ValidationModeAllowlist,
	}
	require.NoError(t, c.applyInvitationGrants(ctx, inv, userID))

	// A second accept for the SAME user/project (e.g. a resent, later-accepted
	// invitation) must be refused cleanly, not silently produce a second row or
	// an opaque storage error.
	inv2 := &models.ProjectInvitation{
		ID: 2, ProjectID: projectID, Email: "invitee@example.com", Role: "viewer",
		InvitedBy: invitedBy, ValidationModeAtInvite: ValidationModeAllowlist,
	}
	err := c.applyInvitationGrants(ctx, inv2, userID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already has a")
	assert.Contains(t, err.Error(), "membership in this project")
}
