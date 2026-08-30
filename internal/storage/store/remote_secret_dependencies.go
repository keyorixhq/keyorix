// remote_secret_dependencies.go — secret dependency edges for RemoteStorage (ADR-052).
//
// CreateSecretDependency/GetSecretDependency/ListSecretDependenciesForProject/
// ListSecretDependenciesForProjectForUpdate/DeleteSecretDependency/
// CreateSecretDependencyExclusive are thin passthroughs onto new server-side routes
// under /api/v1/system/secret-dependencies (server/http/handlers/
// secret_dependencies_proxy.go), following the SAME #452/#507/#510/#511-class pattern
// established for login-attempts, invitations, setup tokens, and project memberships:
// gated on the SAME broad system.read/system.write RBAC tier a RemoteStorage credential
// already needs for every other proxied call, so this introduces no new privilege
// class. No dependency-graph POLICY decision (which secrets may be linked, cycle
// rejection, impact analysis, rotation ordering) is made in these routes — that stays
// entirely in the CALLING server's own internal/core.KeyorixCore
// (secret_dependencies.go), exactly as it does against a local backend, with ONE
// deliberate exception: CreateSecretDependencyExclusive's duplicate/cycle check. See
// its doc on the storage.Storage interface (internal/core/storage/interface.go) for why
// that one invariant — unlike every other check in this subsystem — has to be
// evaluated by whichever server ultimately owns the row, not by the caller.
//
// Before this fix, every one of these methods returned ErrRemoteUnsupported, so
// AddSecretDependency/RemoveSecretDependency/ListSecretDependencies/GetSecretImpact/
// GetProjectRotationOrder (ADR-052, used per ADR-053 for rotation-wave ordering and
// cascading soft-delete/restore/purge through the dependency graph) were completely
// non-functional under storage.type: remote.
//
// For the local (GORM) equivalent of everything here see local_secret_dependencies.go.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
)

// secretDependencyWire mirrors models.SecretDependency's fields exactly (snake_case) —
// a GORM model with no json tags of its own, so a direct marshal would silently drop
// every field whose wire name isn't case-insensitively identical to its Go name (see
// remote_users.go's userWireResponse comment for the full explanation).
type secretDependencyWire struct {
	ID                         uint      `json:"id"`
	ProjectID                  uint      `json:"project_id"`
	DependentSecretID          uint      `json:"dependent_secret_id"`
	DependsOnSecretID          uint      `json:"depends_on_secret_id"`
	Note                       string    `json:"note,omitempty"`
	CreatedBy                  uint      `json:"created_by,omitempty"`
	CreatedByMachineIdentityID uint      `json:"created_by_machine_identity_id,omitempty"`
	CreatedAt                  time.Time `json:"created_at"`
}

func newSecretDependencyWire(d *models.SecretDependency) secretDependencyWire {
	return secretDependencyWire{
		ID:                         d.ID,
		ProjectID:                  d.ProjectID,
		DependentSecretID:          d.DependentSecretID,
		DependsOnSecretID:          d.DependsOnSecretID,
		Note:                       d.Note,
		CreatedBy:                  d.CreatedBy,
		CreatedByMachineIdentityID: d.CreatedByMachineIdentityID,
		CreatedAt:                  d.CreatedAt,
	}
}

func (w secretDependencyWire) toModel() *models.SecretDependency {
	return &models.SecretDependency{
		ID:                         w.ID,
		ProjectID:                  w.ProjectID,
		DependentSecretID:          w.DependentSecretID,
		DependsOnSecretID:          w.DependsOnSecretID,
		Note:                       w.Note,
		CreatedBy:                  w.CreatedBy,
		CreatedByMachineIdentityID: w.CreatedByMachineIdentityID,
		CreatedAt:                  w.CreatedAt,
	}
}

func decodeSecretDependencyResponse(data []byte) (*models.SecretDependency, error) {
	var wire secretDependencyWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

func decodeSecretDependencyList(data []byte) ([]*models.SecretDependency, error) {
	var result struct {
		Dependencies []secretDependencyWire `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.SecretDependency, 0, len(result.Dependencies))
	for _, w := range result.Dependencies {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// duplicateSecretDependencyCode/secretDependencyCycleCode are the machine-readable
// error codes CreateSecretDependencyExclusiveProxy returns when
// storage.CreateSecretDependencyExclusive rejects the edge server-side — the wire-level
// signal this file uses to reconstruct the same storage.ErrDuplicateSecretDependency/
// storage.ErrSecretDependencyCycle sentinels AddSecretDependency's errors.Is checks
// depend on, so that check-and-translate behavior is preserved across this HTTP hop
// exactly as duplicateActiveMembershipCode does for CreateProjectMembership (#511).
const (
	duplicateSecretDependencyCode = "DUPLICATE_SECRET_DEPENDENCY"
	secretDependencyCycleCode     = "SECRET_DEPENDENCY_CYCLE"
)

// CreateSecretDependency used to persist an already-built edge row as-is (a
// raw storage-layer create, no duplicate/cycle check) via POST
// /api/v1/system/secret-dependencies (CreateSecretDependencyProxy), deleted
// (#1587, docs/adr-090-stale-fork-proxy-deletion.md) — no live caller:
// AddSecretDependency (internal/core/secret_dependencies.go) already calls
// CreateSecretDependencyExclusive directly, citing #260. Returns
// errUnsupportedRemote like every other known-unsupported RemoteStorage
// operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) CreateSecretDependency(_ context.Context, _ *models.SecretDependency) (*models.SecretDependency, error) {
	return nil, remoteUnsupported("CreateSecretDependency")
}

// GetSecretDependency retrieves one edge by ID via GET /api/v1/system/secret-dependencies/{id}.
func (rs *RemoteStorage) GetSecretDependency(ctx context.Context, id uint) (*models.SecretDependency, error) {
	path := fmt.Sprintf("/api/v1/system/secret-dependencies/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret dependency: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get secret dependency failed: %s", resp.Error.Error())
	}
	return decodeSecretDependencyResponse(resp.Data)
}

// ListSecretDependenciesForProject lists a project's edges via GET
// /api/v1/system/secret-dependencies?project_id=X.
func (rs *RemoteStorage) ListSecretDependenciesForProject(ctx context.Context, projectID uint) ([]*models.SecretDependency, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/secret-dependencies?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret dependencies: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list secret dependencies failed: %s", resp.Error.Error())
	}
	return decodeSecretDependencyList(resp.Data)
}

// ListSecretDependenciesForProjectForUpdate is ListSecretDependenciesForProject over
// HTTP via GET /api/v1/system/secret-dependencies/snapshot?project_id=X — kept for
// interface parity, but note there is no lock to take over this hop (each remote API
// call is already atomic server-side; see AddSecretDependency's use of
// CreateSecretDependencyExclusive instead, which — unlike this method — genuinely
// preserves #260's cycle-check-under-lock guarantee across storage.type: remote).
// The wire route is named "snapshot", not "for-update" — this Go method name stays
// aligned with LocalStorage's real, lock-holding sibling for interface parity, but no
// HTTP route can honestly promise the same across a request boundary, so the route
// itself (server/http/router.go, ListSecretDependenciesForProjectSnapshotProxy) does
// not claim to.
func (rs *RemoteStorage) ListSecretDependenciesForProjectForUpdate(ctx context.Context, projectID uint) ([]*models.SecretDependency, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/secret-dependencies/snapshot?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret dependencies for update: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list secret dependencies for update failed: %s", resp.Error.Error())
	}
	return decodeSecretDependencyList(resp.Data)
}

// DeleteSecretDependency used to proxy onto DELETE
// /api/v1/system/secret-dependencies/{id} (DeleteSecretDependencyProxy), deleted
// in the G80 liveness sweep — no live caller in either topology; see
// docs/g80-remediation-notes.md. Returns errUnsupportedRemote like every other
// known-unsupported RemoteStorage operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) DeleteSecretDependency(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteSecretDependency")
}

// CreateSecretDependencyExclusive persists an edge with the SAME duplicate/cycle
// validation LocalStorage's implementation runs, via POST
// /api/v1/system/secret-dependencies/exclusive — see the interface doc
// (internal/core/storage/interface.go) for why this, not a caller-orchestrated
// ListSecretDependenciesForProjectForUpdate + CreateSecretDependency sequence, is what
// AddSecretDependency now calls.
func (rs *RemoteStorage) CreateSecretDependencyExclusive(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/secret-dependencies/exclusive", newSecretDependencyWire(d))
	if err != nil {
		// #501-style recovery: makeRequest turns every 4xx/5xx response (including
		// CreateSecretDependencyExclusiveProxy's 409 Conflict / 400 Bad Request for a
		// rejected edge) into a non-nil error before resp is ever populated, so the
		// duplicate/cycle signal must be recovered from the *remote.HTTPError itself
		// (its ErrorType), not from resp.Error — reconstructing the SAME
		// storage.ErrDuplicateSecretDependency/storage.ErrSecretDependencyCycle
		// sentinels AddSecretDependency's errors.Is checks depend on, so that
		// check-and-translate behavior survives this HTTP hop rather than silently
		// downgrading to an opaque "failed to create secret dependency" error.
		var httpErr *remote.HTTPError
		if errors.As(err, &httpErr) {
			switch httpErr.ErrorType {
			case duplicateSecretDependencyCode:
				return nil, fmt.Errorf("%w: %s", storage.ErrDuplicateSecretDependency, httpErr.Message)
			case secretDependencyCycleCode:
				return nil, fmt.Errorf("%w: %s", storage.ErrSecretDependencyCycle, httpErr.Message)
			}
		}
		return nil, fmt.Errorf("failed to create secret dependency: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create secret dependency failed: %s", resp.Error.Error())
	}
	return decodeSecretDependencyResponse(resp.Data)
}
