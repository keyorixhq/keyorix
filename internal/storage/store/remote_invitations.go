// remote_invitations.go — invitations + access requests for RemoteStorage (ADR-024).
//
// Project-invitation methods (#507) are thin passthroughs onto four new
// server-side routes under /api/v1/system/invitations
// (server/http/handlers/invitations_proxy.go), mirroring the #452-follow-up
// login-attempts proxy pattern (internal/storage/store/remote_login_attempts.go,
// docs/adr-040-distributed-rate-limiting.md's addendum): gated on the SAME broad
// system.read/system.write RBAC permissions a RemoteStorage credential already
// needs for every other proxied call (full user CRUD, secret CRUD, ...), so this
// introduces no new privilege class. No invitation POLICY decision (escalation
// checks, TTLs, single-use-accept enforcement) is made in these routes — that
// stays entirely in the CALLING server's own internal/core.KeyorixCore, exactly as
// it does against a local backend. The routes are raw passthroughs onto
// storage.Storage's own CreateProjectInvitation/GetProjectInvitation/
// UpdateProjectInvitation/ListProjectInvitations, including
// UpdateProjectInvitation's conditional `WHERE id=? AND state='pending'` atomic
// write (local_invitations.go) — critical, since this is the SAME operation
// setup_consume.go's completeInvitationAccept relies on for single-use-accept: two
// concurrent accept requests racing to flip the same invitation must result in
// exactly one success, both locally and now across this HTTP hop.
//
// Two gaps discovered while wiring this up are NOT fixed here (documented, not
// silently worked around):
//   - internal/storage/store/remote_auth.go's SetupToken CRUD
//     (CreateSetupToken/GetSetupTokenByHash/MarkSetupTokenConsumed/...) is entirely
//     stubbed, so CompleteSetup's very first step (inspectActiveSetupToken) still
//     hard-fails under storage.type: remote for EVERY setup-token purpose
//     (account_setup, password_reset_link, invitation_accept), not just invitations.
//   - remote_memberships.go's CreateProjectMembership/GetActiveProjectMembership are
//     also entirely stubbed, so applyInvitationGrants' membership-materialization
//     step (inviteMemberWithMode) still hard-fails after a successful accept.
//
// Both are themselves whole missing subsystems (their own atomic-concurrency and
// authorization design), well beyond this finding's named scope
// (CreateProjectInvitation/GetProjectInvitation/UpdateProjectInvitation/
// ListProjectInvitations) — flagged as follow-up findings rather than folded in.
//
// Access-request methods (CreateAccessRequest.../CreateAccessRequestApproval...)
// are unrelated to this finding and remain stubs. For the local (GORM) equivalent
// of everything here see local_invitations.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// invitationWire mirrors models.ProjectInvitation's fields exactly (snake_case),
// used for both the create-request body and every response (create/get/list) —
// there is no models.ProjectInvitation json tag to fall back on (a GORM model,
// like models.User before #496), so a direct marshal/unmarshal would silently
// drop every field whose wire name isn't case-insensitively identical to its Go
// name (ValidationModeAtInvite, AssignmentsJSON, ExpiresAt, ...). See
// remote_users.go's userWireResponse comment for the full explanation of why this
// codebase names every field explicitly instead of relying on that fallback.
type invitationWire struct {
	ID                     uint       `json:"id"`
	ProjectID              uint       `json:"project_id"`
	Email                  string     `json:"email"`
	Role                   string     `json:"role"`
	State                  string     `json:"state"`
	InvitedBy              uint       `json:"invited_by"`
	ValidationModeAtInvite string     `json:"validation_mode_at_invite"`
	SystemRole             string     `json:"system_role"`
	AssignmentsJSON        string     `json:"assignments_json"`
	ExpiresAt              *time.Time `json:"expires_at"`
	CreatedAt              time.Time  `json:"created_at"`
	AcceptedAt             *time.Time `json:"accepted_at"`
	RevokedAt              *time.Time `json:"revoked_at"`
}

func newInvitationWire(inv *models.ProjectInvitation) invitationWire {
	return invitationWire{
		ID:                     inv.ID,
		ProjectID:              inv.ProjectID,
		Email:                  inv.Email,
		Role:                   inv.Role,
		State:                  inv.State,
		InvitedBy:              inv.InvitedBy,
		ValidationModeAtInvite: inv.ValidationModeAtInvite,
		SystemRole:             inv.SystemRole,
		AssignmentsJSON:        inv.AssignmentsJSON,
		ExpiresAt:              inv.ExpiresAt,
		CreatedAt:              inv.CreatedAt,
		AcceptedAt:             inv.AcceptedAt,
		RevokedAt:              inv.RevokedAt,
	}
}

func (w invitationWire) toModel() *models.ProjectInvitation {
	return &models.ProjectInvitation{
		ID:                     w.ID,
		ProjectID:              w.ProjectID,
		Email:                  w.Email,
		Role:                   w.Role,
		State:                  w.State,
		InvitedBy:              w.InvitedBy,
		ValidationModeAtInvite: w.ValidationModeAtInvite,
		SystemRole:             w.SystemRole,
		AssignmentsJSON:        w.AssignmentsJSON,
		ExpiresAt:              w.ExpiresAt,
		CreatedAt:              w.CreatedAt,
		AcceptedAt:             w.AcceptedAt,
		RevokedAt:              w.RevokedAt,
	}
}

func decodeInvitationResponse(data []byte) (*models.ProjectInvitation, error) {
	var wire invitationWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// CreateProjectInvitation persists an already-built invitation (every field —
// state, TTL, validation-mode snapshot, invited_by, ... — is computed by the
// CALLING core.KeyorixCore before this is invoked, exactly as InviteToProject
// builds one for LocalStorage) via POST /api/v1/system/invitations. This is a raw
// persist, NOT the human-facing POST /api/v1/projects/{id}/invitations (which
// wraps InviteToProjectWithLink and also provisions + delivers a setup-link
// email): mapping onto that route would re-run full invite business logic AND
// send a second, real invitation email server-side for every CLI/chained-server
// invite, since the calling core's own InviteToProjectWithLink already tries its
// own provisionSetupLinkThrottled step immediately afterward. This route does
// none of that — it only stores the row — so the caller's own subsequent
// setup-link provisioning attempt (today, always failing while SetupToken
// remains stubbed — see the package doc) reports honestly rather than masking a
// duplicate send.
func (rs *RemoteStorage) CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/invitations", newInvitationWire(inv))
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create invitation failed: %s", resp.Error.Error())
	}
	return decodeInvitationResponse(resp.Data)
}

// GetProjectInvitation retrieves an invitation by ID via GET
// /api/v1/system/invitations/{id} — a raw fetch, gated by system.read.
func (rs *RemoteStorage) GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error) {
	path := fmt.Sprintf("/api/v1/system/invitations/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get invitation: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get invitation failed: %s", resp.Error.Error())
	}
	return decodeInvitationResponse(resp.Data)
}

// UpdateProjectInvitation persists an invitation state transition via PUT
// /api/v1/system/invitations/{id}, preserving LocalStorage's exact single-use
// semantics (#412) end-to-end: the server performs the SAME conditional
// `WHERE id = ? AND state = 'pending'` write local_invitations.go's
// UpdateProjectInvitation does, and reports whether it actually matched a row —
// NOT a client-side "GET then check state then PUT" sequence, which would
// reintroduce the exact TOCTOU double-accept race this method exists to close
// (two concurrent accept requests both observing "pending" before either writes).
// One HTTP round trip maps to one atomic server-side conditional UPDATE.
func (rs *RemoteStorage) UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (bool, error) {
	path := fmt.Sprintf("/api/v1/system/invitations/%d", inv.ID)
	resp, err := rs.client.Put(ctx, path, newInvitationWire(inv))
	if err != nil {
		return false, fmt.Errorf("failed to update invitation: %w", err)
	}
	if !resp.Success {
		return false, fmt.Errorf("update invitation failed: %s", resp.Error.Error())
	}
	var result struct {
		Updated bool `json:"updated"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Updated, nil
}

// ListProjectInvitations lists a project's invitations via GET
// /api/v1/system/invitations?project_id=X.
func (rs *RemoteStorage) ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/invitations?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list invitations: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list invitations failed: %s", resp.Error.Error())
	}
	var result struct {
		Invitations []invitationWire `json:"invitations"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.ProjectInvitation, 0, len(result.Invitations))
	for _, w := range result.Invitations {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// --- Access requests (unrelated to #507; still stubs) ---

func (rs *RemoteStorage) CreateAccessRequest(_ context.Context, _ *models.AccessRequest) (*models.AccessRequest, error) {
	return nil, remoteUnsupported("CreateAccessRequest")
}

func (rs *RemoteStorage) GetAccessRequest(_ context.Context, _ uint) (*models.AccessRequest, error) {
	return nil, remoteUnsupported("GetAccessRequest")
}

func (rs *RemoteStorage) UpdateAccessRequest(_ context.Context, _ *models.AccessRequest) (bool, error) {
	return false, remoteUnsupported("UpdateAccessRequest")
}

func (rs *RemoteStorage) ListAccessRequests(_ context.Context, _ uint) ([]*models.AccessRequest, error) {
	return nil, remoteUnsupported("ListAccessRequests")
}

func (rs *RemoteStorage) CreateAccessRequestApproval(_ context.Context, _ *models.AccessRequestApproval) error {
	return remoteUnsupported("CreateAccessRequestApproval")
}

func (rs *RemoteStorage) ListAccessRequestApprovals(_ context.Context, _ uint) ([]*models.AccessRequestApproval, error) {
	return nil, remoteUnsupported("ListAccessRequestApprovals")
}
