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
// Access-request methods (#523) — CreateAccessRequest/GetAccessRequest/
// UpdateAccessRequest/ListAccessRequests/CreateAccessRequestApproval/
// ListAccessRequestApprovals — are thin passthroughs onto four new server-side
// routes under /api/v1/system/access-requests(+/{id}/approvals)
// (server/http/handlers/access_request_proxy.go), gated on the SAME
// system.read/system.write tier as everything else in this file — no new
// privilege class. No access-request POLICY decision (dual-control threshold,
// maker-checker, TTL/expiry, the role grant itself) is made in these routes —
// that stays entirely in the CALLING server's own internal/core.KeyorixCore
// (RequestProjectAccess/ApproveAccessRequestWithExpiry/RejectAccessRequest/
// WithdrawAccessRequest in internal/core/invitations.go), exactly as it does
// against a local backend.
//
// Atomicity analysis: every one of these 6 methods already resolves in exactly
// ONE storage.Storage call server-side (there is no multi-call sequence inside
// any single method that needs to become atomic). The state-transition race
// guard local_invitations.go documents for UpdateProjectInvitation applies
// identically here — UpdateAccessRequest performs a conditional
// `WHERE id = ? AND state = 'pending'` write (local_invitations.go) and reports
// whether it actually matched a row; ApproveAccessRequestWithExpiry/
// RejectAccessRequest/WithdrawAccessRequest all rely on THIS write's atomicity
// (not on spanning their own separate Get+Update calls transactionally) to
// resolve concurrent approve/reject/withdraw races — see #277. Proxying
// UpdateAccessRequest as one HTTP round trip onto the hub's own conditional
// UPDATE preserves that guarantee unchanged; there is no client-side
// "GET then check state then PUT" sequence here that could reopen it.
// CreateAccessRequestApproval similarly relies on a DB-level UNIQUE index
// (RequestID, ApproverID) plus ON CONFLICT DO NOTHING (local_invitations.go) to
// keep one sign-off per distinct approver honest under concurrent approvals;
// that constraint lives at the hub's own database and is enforced identically
// whether the INSERT arrives locally or via this proxy. Unlike the WebAuthn
// credential-counter / Machine-Identity state-transition / Secret-Dependency
// cycle-check gaps this campaign hit previously, no NEW atomic storage
// primitive was needed here — the existing conditional-UPDATE/unique-index
// primitives already do the whole read-check-write (or insert-or-noop) in one
// server-side operation, so a naive 1:1 proxy per method is correct.
//
// For the local (GORM) equivalent of everything here see local_invitations.go.
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

// --- Access requests (#523) ---

// accessRequestWire mirrors models.AccessRequest's PERSISTED fields exactly
// (snake_case). ApprovalsReceived/RequiredApprovals are deliberately excluded —
// models.AccessRequest itself tags them `gorm:"-"` (transient, never
// persisted); internal/core/invitations.go only ever populates them on a
// value it's about to return to an HTTP caller, never on one it passes INTO
// CreateAccessRequest/UpdateAccessRequest, so there is nothing for this wire
// type to carry. See invitationWire's comment above for why every field is
// named explicitly rather than relying on encoding/json's case-insensitive
// fallback onto a GORM model with no json tags of its own.
// ResolvedByMachineIdentityID (#1573/#1622 sibling) is mirrored explicitly
// for the same reason accessRequestApprovalWire's ApproverMachineIdentityID
// is -- dropping it on this wire hop silently loses which machine identity
// resolved a request for a storage.type:remote deployment (attribution-only,
// not check-defeating on its own, but the same class of gap).
type accessRequestWire struct {
	ID                          uint       `json:"id"`
	ProjectID                   uint       `json:"project_id"`
	UserID                      uint       `json:"user_id"`
	SuggestedRole               string     `json:"suggested_role"`
	GrantedRole                 string     `json:"granted_role"`
	SecretID                    *uint      `json:"secret_id"`
	State                       string     `json:"state"`
	Reason                      string     `json:"reason"`
	ResolvedBy                  uint       `json:"resolved_by"`
	ResolvedByMachineIdentityID uint       `json:"resolved_by_machine_identity_id"`
	ExpiresAt                   *time.Time `json:"expires_at"`
	CreatedAt                   time.Time  `json:"created_at"`
	ResolvedAt                  *time.Time `json:"resolved_at"`
}

func newAccessRequestWire(req *models.AccessRequest) accessRequestWire {
	return accessRequestWire{
		ID:                          req.ID,
		ProjectID:                   req.ProjectID,
		UserID:                      req.UserID,
		SuggestedRole:               req.SuggestedRole,
		GrantedRole:                 req.GrantedRole,
		SecretID:                    req.SecretID,
		State:                       req.State,
		Reason:                      req.Reason,
		ResolvedBy:                  req.ResolvedBy,
		ResolvedByMachineIdentityID: req.ResolvedByMachineIdentityID,
		ExpiresAt:                   req.ExpiresAt,
		CreatedAt:                   req.CreatedAt,
		ResolvedAt:                  req.ResolvedAt,
	}
}

func (w accessRequestWire) toModel() *models.AccessRequest {
	return &models.AccessRequest{
		ID:                          w.ID,
		ProjectID:                   w.ProjectID,
		UserID:                      w.UserID,
		SuggestedRole:               w.SuggestedRole,
		GrantedRole:                 w.GrantedRole,
		SecretID:                    w.SecretID,
		State:                       w.State,
		Reason:                      w.Reason,
		ResolvedBy:                  w.ResolvedBy,
		ResolvedByMachineIdentityID: w.ResolvedByMachineIdentityID,
		ExpiresAt:                   w.ExpiresAt,
		CreatedAt:                   w.CreatedAt,
		ResolvedAt:                  w.ResolvedAt,
	}
}

func decodeAccessRequestResponse(data []byte) (*models.AccessRequest, error) {
	var wire accessRequestWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// accessRequestApprovalWire mirrors models.AccessRequestApproval's fields
// exactly (snake_case).
// ApproverMachineIdentityID (#1622) is mirrored explicitly -- it is the
// discriminator hasAlreadyApproved's dual-control tuple check depends on to
// tell two distinct machine approvers apart (both have ApproverID==0, ADR-030).
// Dropping it on this wire hop would silently collapse every machine
// approver back to the same (RequestID, ApproverID=0) tuple for a
// storage.type:remote deployment, reopening the exact false-collision/
// false-rejection bug #1622 fixed for LocalStorage.
type accessRequestApprovalWire struct {
	ID                        uint      `json:"id"`
	RequestID                 uint      `json:"request_id"`
	ApproverID                uint      `json:"approver_id"`
	ApproverMachineIdentityID uint      `json:"approver_machine_identity_id"`
	CreatedAt                 time.Time `json:"created_at"`
}

func newAccessRequestApprovalWire(a *models.AccessRequestApproval) accessRequestApprovalWire {
	return accessRequestApprovalWire{
		ID:                        a.ID,
		RequestID:                 a.RequestID,
		ApproverID:                a.ApproverID,
		ApproverMachineIdentityID: a.ApproverMachineIdentityID,
		CreatedAt:                 a.CreatedAt,
	}
}

// CreateAccessRequest persists an already-built access request (every field —
// state, TTL, suggested role, ... — is computed by the CALLING core.KeyorixCore
// before this is invoked, exactly as RequestProjectAccess/RequestSecretAccess
// build one for LocalStorage) via POST /api/v1/system/access-requests.
func (rs *RemoteStorage) CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/access-requests", newAccessRequestWire(req))
	if err != nil {
		return nil, fmt.Errorf("failed to create access request: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create access request failed: %s", resp.Error.Error())
	}
	return decodeAccessRequestResponse(resp.Data)
}

// GetAccessRequest retrieves an access request by ID via GET
// /api/v1/system/access-requests/{id} — a raw fetch, gated by system.read.
func (rs *RemoteStorage) GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error) {
	path := fmt.Sprintf("/api/v1/system/access-requests/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get access request: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get access request failed: %s", resp.Error.Error())
	}
	return decodeAccessRequestResponse(resp.Data)
}

// UpdateAccessRequest persists an access-request state transition via PUT
// /api/v1/system/access-requests/{id}, preserving local_invitations.go's exact
// conditional `WHERE id = ? AND state = 'pending'` semantics end-to-end: the
// server performs the SAME conditional write, and reports whether it actually
// matched a row — NOT a client-side "GET then check state then PUT" sequence,
// which would reintroduce the #277 TOCTOU race ApproveAccessRequestWithExpiry/
// RejectAccessRequest/WithdrawAccessRequest all depend on this write to close.
// One HTTP round trip maps to one atomic server-side conditional UPDATE.
func (rs *RemoteStorage) UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) (bool, error) {
	path := fmt.Sprintf("/api/v1/system/access-requests/%d", req.ID)
	resp, err := rs.client.Put(ctx, path, newAccessRequestWire(req))
	if err != nil {
		return false, fmt.Errorf("failed to update access request: %w", err)
	}
	if !resp.Success {
		return false, fmt.Errorf("update access request failed: %s", resp.Error.Error())
	}
	var result struct {
		Updated bool `json:"updated"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Updated, nil
}

// ListAccessRequests lists a project's access requests via GET
// /api/v1/system/access-requests?project_id=X.
func (rs *RemoteStorage) ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/access-requests?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list access requests: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list access requests failed: %s", resp.Error.Error())
	}
	var result struct {
		AccessRequests []accessRequestWire `json:"access_requests"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.AccessRequest, 0, len(result.AccessRequests))
	for _, w := range result.AccessRequests {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// CreateAccessRequestApproval records one approver's sign-off via POST
// /api/v1/system/access-requests/{id}/approvals. The server performs the SAME
// INSERT ... ON CONFLICT (request_id, approver_id) DO NOTHING
// local_invitations.go does, backed by the DB-level unique index — a duplicate
// sign-off from the same approver (including one racing a concurrent identical
// call through this proxy) is a benign no-op here exactly as it is locally,
// keeping the M-of-K dual-control count honest.
func (rs *RemoteStorage) CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error {
	path := fmt.Sprintf("/api/v1/system/access-requests/%d/approvals", a.RequestID)
	resp, err := rs.client.Post(ctx, path, newAccessRequestApprovalWire(a))
	if err != nil {
		return fmt.Errorf("failed to create access request approval: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("create access request approval failed: %s", resp.Error.Error())
	}
	return nil
}

// ListAccessRequestApprovals lists every approval recorded for a request via
// GET /api/v1/system/access-requests/{id}/approvals — used both to annotate
// dual-control progress (ListAccessRequests) and to enforce one-sign-off-per-
// approver (ApproveAccessRequestWithExpiry).
func (rs *RemoteStorage) ListAccessRequestApprovals(ctx context.Context, requestID uint) ([]*models.AccessRequestApproval, error) {
	path := fmt.Sprintf("/api/v1/system/access-requests/%d/approvals", requestID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list access request approvals: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list access request approvals failed: %s", resp.Error.Error())
	}
	var result struct {
		Approvals []accessRequestApprovalWire `json:"approvals"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.AccessRequestApproval, 0, len(result.Approvals))
	for _, w := range result.Approvals {
		rows = append(rows, &models.AccessRequestApproval{
			ID:                        w.ID,
			RequestID:                 w.RequestID,
			ApproverID:                w.ApproverID,
			ApproverMachineIdentityID: w.ApproverMachineIdentityID,
			CreatedAt:                 w.CreatedAt,
		})
	}
	return rows, nil
}
