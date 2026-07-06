// remote_memberships.go — project membership lifecycle for RemoteStorage (ADR-022).
//
// #511: CreateProjectMembership/GetProjectMembership/UpdateProjectMembership/
// ListProjectMemberships/GetActiveProjectMembership/ListStaleInvitedMemberships/
// ListUserProjectMemberships/CountProjectMembershipsByUsers are thin passthroughs
// onto eight new server-side routes under /api/v1/system/project-memberships
// (server/http/handlers/project_memberships_proxy.go), following the SAME pattern
// #507/#510 established (remote_invitations.go, remote_auth.go): gated on the same
// broad system.read/system.write RBAC permissions a RemoteStorage credential
// already needs for every other proxied call, so this introduces no new privilege
// class. No membership-lifecycle POLICY decision (which state a new invite starts
// in, which transitions are legal, when a role grant is applied/reverted) is made
// in these routes — that stays entirely in the CALLING server's own
// internal/core.KeyorixCore (membership_lifecycle.go), exactly as it does against a
// local backend.
//
// Before this fix, every one of these methods returned ErrRemoteUnsupported, so
// applyInvitationGrants' membership-materialization step (inviteMemberWithMode →
// storage.CreateProjectMembership) hard-failed under storage.type: remote even
// after a successful invitation accept (#507) — the invitation itself would flip to
// "accepted", but the membership/role grant it's supposed to produce could never be
// persisted.
//
// Atomicity note (mirrors #507's UpdateProjectInvitation reasoning, but the
// conclusion differs): local_memberships.go's CreateProjectMembership relies on a
// REAL DB-level partial unique index (uniq_project_memberships_active, #309) to
// reject a second concurrent active membership for the same (project, user) — that
// guarantee is a property of the upstream's own database and survives this HTTP hop
// unchanged, since CreateMembershipProxy calls the identical storage.Storage
// primitive against the same table. UpdateProjectMembership, by contrast, has NO
// such conditional-write guarantee even locally — local_memberships.go's
// implementation is a plain GORM Save, and the state-machine legality check
// (canTransition) is enforced by the CALLING core.KeyorixCore before it ever calls
// storage.UpdateProjectMembership (membership_lifecycle.go's TransitionMembership),
// not by the storage layer itself. So, unlike UpdateProjectInvitation, there is no
// existing atomic "WHERE state = ?" write to preserve here — a single passthrough
// PUT that maps directly onto the same plain Save is exact behavioral parity with
// LocalStorage, not a new race introduced by this file. (A client-side
// "GET, check state, then PUT" sequence would still be strictly worse than what
// LocalStorage does today, so this deliberately issues one round trip per call,
// same as every other method here.)
//
// For the local (GORM) equivalent of everything here see local_memberships.go.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
)

// membershipWire mirrors models.ProjectMembership's fields exactly (snake_case),
// used for both the create-request body and every response — there is no
// models.ProjectMembership json tag to fall back on (a GORM model, like
// models.User before #496 and models.ProjectInvitation before #507), so a direct
// marshal/unmarshal would silently drop every field whose wire name isn't
// case-insensitively identical to its Go name. See remote_users.go's
// userWireResponse comment for the full explanation.
type membershipWire struct {
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

func newMembershipWire(m *models.ProjectMembership) membershipWire {
	return membershipWire{
		ID:          m.ID,
		ProjectID:   m.ProjectID,
		UserID:      m.UserID,
		Role:        m.Role,
		State:       m.State,
		InvitedBy:   m.InvitedBy,
		InvitedAt:   m.InvitedAt,
		ActivatedAt: m.ActivatedAt,
		RevokedAt:   m.RevokedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

func (w membershipWire) toModel() *models.ProjectMembership {
	return &models.ProjectMembership{
		ID:          w.ID,
		ProjectID:   w.ProjectID,
		UserID:      w.UserID,
		Role:        w.Role,
		State:       w.State,
		InvitedBy:   w.InvitedBy,
		InvitedAt:   w.InvitedAt,
		ActivatedAt: w.ActivatedAt,
		RevokedAt:   w.RevokedAt,
		UpdatedAt:   w.UpdatedAt,
	}
}

func decodeMembershipResponse(data []byte) (*models.ProjectMembership, error) {
	var wire membershipWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// duplicateActiveMembershipCode is the machine-readable error code
// CreateMembershipProxy returns when the upstream's own DB-level unique-index
// rejection (isUniqueViolation, local_memberships.go) fires — the wire-level
// signal RemoteStorage.CreateProjectMembership uses to reconstruct the same
// storage.ErrDuplicateActiveMembership sentinel inviteMemberWithMode's
// errors.Is check (#309) depends on, so that check-and-translate behavior is
// preserved across this HTTP hop and not silently downgraded to an opaque
// "failed to create membership" error.
const duplicateActiveMembershipCode = "DUPLICATE_ACTIVE_MEMBERSHIP"

// CreateProjectMembership persists an already-built membership row (every field —
// initial state, InvitedBy/InvitedAt, ...) is computed by the CALLING
// core.KeyorixCore before this is invoked, exactly as inviteMemberWithMode builds
// one for LocalStorage) via POST /api/v1/system/project-memberships.
func (rs *RemoteStorage) CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/project-memberships", newMembershipWire(m))
	if err != nil {
		// #501: makeRequest turns EVERY 4xx/5xx response (including
		// CreateMembershipProxy's 409 Conflict) into a non-nil error before
		// resp is ever populated, so the duplicate-membership signal must be
		// recovered from the *remote.HTTPError itself (its ErrorType, parsed
		// from the same {"error":{"code",...}} envelope this package's other
		// methods check via resp.Error.Code), not from resp.Error — reconstructing
		// the SAME storage.ErrDuplicateActiveMembership sentinel
		// inviteMemberWithMode's errors.Is check (#309) depends on, so that
		// check-and-translate behavior survives this HTTP hop rather than
		// silently downgrading to an opaque "failed to create membership" error.
		var httpErr *remote.HTTPError
		if errors.As(err, &httpErr) && httpErr.ErrorType == duplicateActiveMembershipCode {
			return nil, fmt.Errorf("%w: %s", storage.ErrDuplicateActiveMembership, httpErr.Message)
		}
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create membership failed: %s", resp.Error.Error())
	}
	return decodeMembershipResponse(resp.Data)
}

// GetProjectMembership retrieves a membership by ID via GET
// /api/v1/system/project-memberships/{id}.
func (rs *RemoteStorage) GetProjectMembership(ctx context.Context, id uint) (*models.ProjectMembership, error) {
	path := fmt.Sprintf("/api/v1/system/project-memberships/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get membership: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get membership failed: %s", resp.Error.Error())
	}
	return decodeMembershipResponse(resp.Data)
}

// UpdateProjectMembership persists a membership's current state via PUT
// /api/v1/system/project-memberships/{id} — a single round trip mapping directly
// onto local_memberships.go's plain Save (see the package doc: there is no
// conditional-write guarantee to preserve here, unlike UpdateProjectInvitation).
func (rs *RemoteStorage) UpdateProjectMembership(ctx context.Context, m *models.ProjectMembership) error {
	path := fmt.Sprintf("/api/v1/system/project-memberships/%d", m.ID)
	resp, err := rs.client.Put(ctx, path, newMembershipWire(m))
	if err != nil {
		return fmt.Errorf("failed to update membership: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update membership failed: %s", resp.Error.Error())
	}
	return nil
}

// ListProjectMemberships lists a project's memberships via GET
// /api/v1/system/project-memberships?project_id=X.
func (rs *RemoteStorage) ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/project-memberships?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list memberships failed: %s", resp.Error.Error())
	}
	return decodeMembershipList(resp.Data)
}

// GetActiveProjectMembership retrieves the (at most one) non-revoked membership
// for a (project, user) pair via GET
// /api/v1/system/project-memberships/active?project_id=X&user_id=Y — the read
// inviteMemberWithMode uses to reject a duplicate onboarding (#309).
func (rs *RemoteStorage) GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	q.Set("user_id", strconv.FormatUint(uint64(userID), 10))
	path := "/api/v1/system/project-memberships/active?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get active membership: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get active membership failed: %s", resp.Error.Error())
	}
	return decodeMembershipResponse(resp.Data)
}

// ListStaleInvitedMemberships lists still-invited memberships older than before
// via GET /api/v1/system/project-memberships/stale?before=<RFC3339Nano> (ADR-022
// stale-invite warnings).
func (rs *RemoteStorage) ListStaleInvitedMemberships(ctx context.Context, before time.Time) ([]*models.ProjectMembership, error) {
	q := url.Values{}
	q.Set("before", before.UTC().Format(time.RFC3339Nano))
	path := "/api/v1/system/project-memberships/stale?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list stale invited memberships: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list stale invited memberships failed: %s", resp.Error.Error())
	}
	return decodeMembershipList(resp.Data)
}

// ListUserProjectMemberships lists all membership rows for a single user via GET
// /api/v1/system/project-memberships/by-user/{userID} (ADR-025 per-user
// assignments view).
func (rs *RemoteStorage) ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error) {
	path := fmt.Sprintf("/api/v1/system/project-memberships/by-user/%d", userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list user memberships: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list user memberships failed: %s", resp.Error.Error())
	}
	return decodeMembershipList(resp.Data)
}

// CountProjectMembershipsByUsers returns per-user membership tallies (active and
// non-revoked total) for the given user IDs in one call via GET
// /api/v1/system/project-memberships/counts?user_ids=1,2,3 (ADR-025 user list).
func (rs *RemoteStorage) CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]storage.MembershipCounts, error) {
	if len(userIDs) == 0 {
		return map[uint]storage.MembershipCounts{}, nil
	}
	ids := make([]string, len(userIDs))
	for i, id := range userIDs {
		ids[i] = strconv.FormatUint(uint64(id), 10)
	}
	q := url.Values{}
	q.Set("user_ids", strings.Join(ids, ","))
	path := "/api/v1/system/project-memberships/counts?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to count memberships by users: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("count memberships by users failed: %s", resp.Error.Error())
	}
	// encoding/json supports unsigned-integer map keys directly (decoded from
	// their base-10 JSON string form), so this unmarshals straight into the
	// interface's own map[uint]storage.MembershipCounts shape — no intermediate
	// string-keyed map or manual strconv needed.
	var result map[uint]storage.MembershipCounts
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if result == nil {
		result = map[uint]storage.MembershipCounts{}
	}
	return result, nil
}

func decodeMembershipList(data []byte) ([]*models.ProjectMembership, error) {
	var result struct {
		Memberships []membershipWire `json:"memberships"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.ProjectMembership, 0, len(result.Memberships))
	for _, w := range result.Memberships {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}
