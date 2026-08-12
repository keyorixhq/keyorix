// remote_machine_identities.go — machine identities, machine-token credentials,
// machine role grants, and OIDC bindings for RemoteStorage (ADR-023/ADR-030/
// ADR-031, finding #518): thin passthroughs onto new server-side routes under
// /api/v1/system/machine-identities, /machine-credentials, and
// /machine-oidc-bindings (server/http/handlers/machine_identities_proxy.go),
// mirroring the dynamic-secrets/groups proxy pattern exactly: gated on the SAME
// broad system.read/system.write RBAC permissions a RemoteStorage credential
// already needs for every other proxied call, so this introduces no new
// privilege class.
//
// No machine-identity POLICY decision (state-machine transition legality,
// role-grant authorization, token issuance/hashing, OIDC-subject federation
// policy) is made in these routes — that stays entirely in the CALLING server's
// own internal/core.KeyorixCore (machine_identities.go, machine_token.go), exactly
// as it does against a local backend.
//
// Before this fix every method here unconditionally returned
// ErrRemoteUnsupported ("machine identity management is processed server-side in
// remote mode" — the actual state was: it isn't processed anywhere at all under
// storage.type: remote), so a downstream server's ENTIRE machine-identity
// subsystem (CI/service-account provisioning, machine-token issuance/validation,
// machine role grants, Kubernetes/OIDC workload federation) was completely
// non-functional.
//
// Atomicity note (investigated, not assumed safe — see
// internal/core/storage/interface.go's TransitionMachineIdentityState doc and
// internal/core/machine_identities.go's TransitionMachineIdentity doc for the
// full reasoning): core.TransitionMachineIdentity's #388 fix relies on
// LockMachineIdentityForUpdate + a DB transaction/row-lock to keep "revoked is
// terminal" atomic against a concurrent writer of the same row. RemoteStorage.
// WithTransaction (remote_transaction.go) is a no-op passthrough — there is no
// client-side transaction to open over HTTP — so a plain two-call
// LockMachineIdentityForUpdate-then-UpdateMachineIdentity proxy pair would lose
// that guarantee entirely: two concurrent transitions on the SAME downstream
// server, both racing against this SAME upstream, could each independently
// observe the pre-transition state and each "win" a Save, silently un-revoking a
// just-revoked machine identity. TransitionMachineIdentityState exists
// specifically to close this: ONE round trip carries the already-mutated target
// row plus the fromState the caller observed, and the upstream applies the exact
// same conditional "WHERE id = ? AND state = ?" write its own LocalStorage would
// (mirroring UpdateProjectInvitation's #412 `WHERE id = ? AND state = 'pending'`
// pattern) — a lost race reports matched=false rather than silently overwriting
// the winner. LockMachineIdentityForUpdate itself remains a plain read here (see
// its doc below), exactly like LockUserForUpdate's remote equivalent
// (remote_users.go) — the ACTUAL atomicity guarantee now lives in the
// TransitionMachineIdentityState write, not in the read.
//
// Sensitive-data note: MachineIdentityCredential.TokenHash (tagged `json:"-"` on
// the model) is a SHA-256 hex digest of the one-time-displayed raw token, never
// the raw secret — see machine_identities_proxy.go's package doc for the full
// verification (its only reader, core.ValidateMachineToken, looks it up via
// GetMachineIdentityCredentialByHash(ctx, sha256Hex(raw))). This package's wire
// type carries it explicitly, like dynamicSecretConfigWire's AdminDSNEnc.
//
// CountStaleMachineIdentitiesByProject remains an intentional stub (see its own
// doc below) — the grouped hygiene-rollup query (#393) runs server-side and is
// out of this finding's scope.
//
// For the local (GORM) equivalent of everything here see
// local_machine_identities.go / local_machine_credentials.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- Wire types (mirror server/http/handlers/machine_identities_proxy.go's
// proxy-side wire types exactly) ---

type machineIdentityWire struct {
	ID             uint       `json:"id"`
	ProjectID      uint       `json:"project_id"`
	Name           string     `json:"name"`
	IdentityType   string     `json:"identity_type"`
	State          string     `json:"state"`
	Description    string     `json:"description"`
	CreatedBy      uint       `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastSeenAt     *time.Time `json:"last_seen_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	Classification string     `json:"classification"`
}

func newMachineIdentityWire(m *models.MachineIdentity) machineIdentityWire {
	return machineIdentityWire{
		ID:             m.ID,
		ProjectID:      m.ProjectID,
		Name:           m.Name,
		IdentityType:   m.IdentityType,
		State:          m.State,
		Description:    m.Description,
		CreatedBy:      m.CreatedBy,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
		LastSeenAt:     m.LastSeenAt,
		RevokedAt:      m.RevokedAt,
		Classification: m.Classification,
	}
}

func (w machineIdentityWire) toModel() *models.MachineIdentity {
	return &models.MachineIdentity{
		ID:             w.ID,
		ProjectID:      w.ProjectID,
		Name:           w.Name,
		IdentityType:   w.IdentityType,
		State:          w.State,
		Description:    w.Description,
		CreatedBy:      w.CreatedBy,
		CreatedAt:      w.CreatedAt,
		UpdatedAt:      w.UpdatedAt,
		LastSeenAt:     w.LastSeenAt,
		RevokedAt:      w.RevokedAt,
		Classification: w.Classification,
	}
}

func decodeMachineIdentityResponse(data []byte) (*models.MachineIdentity, error) {
	var wire machineIdentityWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

type machineIdentityCredentialWire struct {
	ID                uint       `json:"id"`
	MachineIdentityID uint       `json:"machine_identity_id"`
	Name              string     `json:"name"`
	TokenHash         string     `json:"token_hash"`
	TokenPrefix       string     `json:"token_prefix"`
	// AllowedCIDRs (#G80) must round-trip: omitting it here silently strips the
	// machine-token IP allowlist on every RemoteStorage read/write, and
	// ClassifyMachineToken's read-mutate-Save cycle would actively WIPE a
	// previously-set allowlist on the next classification change.
	AllowedCIDRs   string     `json:"allowed_cidrs"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
	Revoked        bool       `json:"revoked"`
	CreatedAt      time.Time  `json:"created_at"`
	Classification string     `json:"classification"`
}

func newMachineIdentityCredentialWire(c *models.MachineIdentityCredential) machineIdentityCredentialWire {
	return machineIdentityCredentialWire{
		ID:                c.ID,
		MachineIdentityID: c.MachineIdentityID,
		Name:              c.Name,
		TokenHash:         c.TokenHash,
		TokenPrefix:       c.TokenPrefix,
		AllowedCIDRs:      c.AllowedCIDRs,
		LastUsedAt:        c.LastUsedAt,
		ExpiresAt:         c.ExpiresAt,
		Revoked:           c.Revoked,
		CreatedAt:         c.CreatedAt,
		Classification:    c.Classification,
	}
}

func (w machineIdentityCredentialWire) toModel() *models.MachineIdentityCredential {
	return &models.MachineIdentityCredential{
		ID:                w.ID,
		MachineIdentityID: w.MachineIdentityID,
		Name:              w.Name,
		TokenHash:         w.TokenHash,
		TokenPrefix:       w.TokenPrefix,
		AllowedCIDRs:      w.AllowedCIDRs,
		LastUsedAt:        w.LastUsedAt,
		ExpiresAt:         w.ExpiresAt,
		Revoked:           w.Revoked,
		CreatedAt:         w.CreatedAt,
		Classification:    w.Classification,
	}
}

func decodeMachineIdentityCredentialResponse(data []byte) (*models.MachineIdentityCredential, error) {
	var wire machineIdentityCredentialWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

type machineIdentityOIDCBindingWire struct {
	ID                uint      `json:"id"`
	MachineIdentityID uint      `json:"machine_identity_id"`
	Issuer            string    `json:"issuer"`
	Subject           string    `json:"subject"`
	CreatedBy         uint      `json:"created_by"`
	CreatedAt         time.Time `json:"created_at"`
}

func newMachineIdentityOIDCBindingWire(b *models.MachineIdentityOIDCBinding) machineIdentityOIDCBindingWire {
	return machineIdentityOIDCBindingWire{
		ID:                b.ID,
		MachineIdentityID: b.MachineIdentityID,
		Issuer:            b.Issuer,
		Subject:           b.Subject,
		CreatedBy:         b.CreatedBy,
		CreatedAt:         b.CreatedAt,
	}
}

func (w machineIdentityOIDCBindingWire) toModel() *models.MachineIdentityOIDCBinding {
	return &models.MachineIdentityOIDCBinding{
		ID:                w.ID,
		MachineIdentityID: w.MachineIdentityID,
		Issuer:            w.Issuer,
		Subject:           w.Subject,
		CreatedBy:         w.CreatedBy,
		CreatedAt:         w.CreatedAt,
	}
}

func decodeMachineIdentityOIDCBindingResponse(data []byte) (*models.MachineIdentityOIDCBinding, error) {
	var wire machineIdentityOIDCBindingWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

type roleWire struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (w roleWire) toModel() *models.Role {
	return &models.Role{ID: w.ID, Name: w.Name, Description: w.Description}
}

// --- Machine identities ---

// CreateMachineIdentity persists an already-built machine identity via POST
// /api/v1/system/machine-identities.
func (rs *RemoteStorage) CreateMachineIdentity(ctx context.Context, m *models.MachineIdentity) (*models.MachineIdentity, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/machine-identities", newMachineIdentityWire(m))
	if err != nil {
		return nil, fmt.Errorf("failed to create machine identity: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create machine identity failed: %s", resp.Error.Error())
	}
	return decodeMachineIdentityResponse(resp.Data)
}

// GetMachineIdentity retrieves a machine identity by ID via GET
// /api/v1/system/machine-identities/{id}.
func (rs *RemoteStorage) GetMachineIdentity(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine identity: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get machine identity failed: %s", resp.Error.Error())
	}
	return decodeMachineIdentityResponse(resp.Data)
}

// LockMachineIdentityForUpdate has no row lock to take over HTTP — each remote
// API call is already atomic server-side, and the ACTUAL atomicity guarantee
// TransitionMachineIdentity needs (#388) is now provided by
// TransitionMachineIdentityState's conditional write below, not by this read —
// mirroring LockUserForUpdate's remote equivalent (remote_users.go). Deliberately
// NOT routed through the client's 5-minute response cache (rs.client.Request
// directly, like LockUserForUpdate), so a caller always observes the genuinely
// current row before deciding fromState/legality.
func (rs *RemoteStorage) LockMachineIdentityForUpdate(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d", id)
	resp, err := rs.client.Request(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine identity: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get machine identity failed: %s", resp.Error.Error())
	}
	return decodeMachineIdentityResponse(resp.Data)
}

// UpdateMachineIdentity persists the full row via PUT
// /api/v1/system/machine-identities/{id}. Matches LocalStorage's own
// unconditional full-row Save semantics exactly — used by
// core.ClassifyMachineIdentity, which has no state-machine invariant to protect.
// core.TransitionMachineIdentity does NOT use this method — see
// TransitionMachineIdentityState below for why.
func (rs *RemoteStorage) UpdateMachineIdentity(ctx context.Context, m *models.MachineIdentity) error {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d", m.ID)
	resp, err := rs.client.Put(ctx, path, newMachineIdentityWire(m))
	if err != nil {
		return fmt.Errorf("failed to update machine identity: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update machine identity failed: %s", resp.Error.Error())
	}
	return nil
}

// TransitionMachineIdentityState persists m's full row via a single conditional
// PUT to /api/v1/system/machine-identities/{id}/transition (mirroring
// UpdateProjectInvitation's #412 `WHERE id = ? AND state = 'pending'` pattern),
// carrying fromState alongside so the upstream applies the exact SAME
// conditional "WHERE id = ? AND state = ?" write its own LocalStorage would —
// see the package doc's atomicity note for why this exists as a single
// round-trip primitive rather than a generic Lock-then-Update proxy pair.
func (rs *RemoteStorage) TransitionMachineIdentityState(ctx context.Context, m *models.MachineIdentity, fromState string) (bool, error) {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/transition", m.ID)
	body := struct {
		MachineIdentity machineIdentityWire `json:"machine_identity"`
		FromState       string              `json:"from_state"`
	}{MachineIdentity: newMachineIdentityWire(m), FromState: fromState}
	resp, err := rs.client.Put(ctx, path, body)
	if err != nil {
		return false, fmt.Errorf("failed to transition machine identity: %w", err)
	}
	if !resp.Success {
		return false, fmt.Errorf("transition machine identity failed: %s", resp.Error.Error())
	}
	var result struct {
		Matched bool `json:"matched"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Matched, nil
}

// ListMachineIdentities lists a project's machine identities via GET
// /api/v1/system/machine-identities?project_id=X.
func (rs *RemoteStorage) ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/machine-identities?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list machine identities: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list machine identities failed: %s", resp.Error.Error())
	}
	var result struct {
		MachineIdentities []machineIdentityWire `json:"machine_identities"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.MachineIdentity, 0, len(result.MachineIdentities))
	for _, w := range result.MachineIdentities {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// ListAllMachineIdentities lists every machine identity across all projects via
// GET /api/v1/system/machine-identities/all.
func (rs *RemoteStorage) ListAllMachineIdentities(ctx context.Context) ([]*models.MachineIdentity, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/machine-identities/all")
	if err != nil {
		return nil, fmt.Errorf("failed to list all machine identities: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list all machine identities failed: %s", resp.Error.Error())
	}
	var result struct {
		MachineIdentities []machineIdentityWire `json:"machine_identities"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.MachineIdentity, 0, len(result.MachineIdentities))
	for _, w := range result.MachineIdentities {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// CountMachineIdentitiesByClassification returns install-wide counts keyed by
// classification label via GET
// /api/v1/system/machine-identities/classification-counts.
func (rs *RemoteStorage) CountMachineIdentitiesByClassification(ctx context.Context) (map[string]int, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/machine-identities/classification-counts")
	if err != nil {
		return nil, fmt.Errorf("failed to count machine identities by classification: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("count machine identities by classification failed: %s", resp.Error.Error())
	}
	var result struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Counts, nil
}

// CountStaleMachineIdentitiesByProject is not available in remote mode; the
// grouped hygiene-rollup query (#393) runs server-side.
func (rs *RemoteStorage) CountStaleMachineIdentitiesByProject(_ context.Context, _ []uint, _ time.Time) (map[uint]int, error) {
	return nil, remoteUnsupported("CountStaleMachineIdentitiesByProject")
}

// --- Machine-token credentials ---

// CreateMachineIdentityCredential persists an already-built (already-hashed)
// credential via POST /api/v1/system/machine-credentials.
func (rs *RemoteStorage) CreateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/machine-credentials", newMachineIdentityCredentialWire(c))
	if err != nil {
		return nil, fmt.Errorf("failed to create machine credential: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create machine credential failed: %s", resp.Error.Error())
	}
	return decodeMachineIdentityCredentialResponse(resp.Data)
}

// GetMachineIdentityCredentialByHash retrieves a credential by its SHA-256 hash
// via GET /api/v1/system/machine-credentials/by-hash/{hash} — backs
// core.ValidateMachineToken's machine-token authentication lookup.
func (rs *RemoteStorage) GetMachineIdentityCredentialByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, error) {
	path := fmt.Sprintf("/api/v1/system/machine-credentials/by-hash/%s", url.PathEscape(hash))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine credential by hash: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get machine credential by hash failed: %s", resp.Error.Error())
	}
	return decodeMachineIdentityCredentialResponse(resp.Data)
}

// GetMachineIdentityCredentialByID retrieves a credential by ID via GET
// /api/v1/system/machine-credentials/{id}.
func (rs *RemoteStorage) GetMachineIdentityCredentialByID(ctx context.Context, id uint) (*models.MachineIdentityCredential, error) {
	path := fmt.Sprintf("/api/v1/system/machine-credentials/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine credential: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get machine credential failed: %s", resp.Error.Error())
	}
	return decodeMachineIdentityCredentialResponse(resp.Data)
}

// ListMachineIdentityCredentials lists a machine identity's credentials via GET
// /api/v1/system/machine-identities/{id}/credentials.
func (rs *RemoteStorage) ListMachineIdentityCredentials(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error) {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/credentials", machineID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list machine credentials: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list machine credentials failed: %s", resp.Error.Error())
	}
	var result struct {
		Credentials []machineIdentityCredentialWire `json:"credentials"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.MachineIdentityCredential, 0, len(result.Credentials))
	for _, w := range result.Credentials {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// ListActiveMachineIdentityCredentials lists every non-revoked credential
// install-wide via GET /api/v1/system/machine-credentials/active.
func (rs *RemoteStorage) ListActiveMachineIdentityCredentials(ctx context.Context) ([]*models.MachineIdentityCredential, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/machine-credentials/active")
	if err != nil {
		return nil, fmt.Errorf("failed to list active machine credentials: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list active machine credentials failed: %s", resp.Error.Error())
	}
	var result struct {
		Credentials []machineIdentityCredentialWire `json:"credentials"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.MachineIdentityCredential, 0, len(result.Credentials))
	for _, w := range result.Credentials {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// UpdateMachineIdentityCredential persists the full row via PUT
// /api/v1/system/machine-credentials/{id}. Matches LocalStorage's own
// unconditional full-row Save semantics exactly — used by
// core.ClassifyMachineToken.
func (rs *RemoteStorage) UpdateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) error {
	path := fmt.Sprintf("/api/v1/system/machine-credentials/%d", c.ID)
	resp, err := rs.client.Put(ctx, path, newMachineIdentityCredentialWire(c))
	if err != nil {
		return fmt.Errorf("failed to update machine credential: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update machine credential failed: %s", resp.Error.Error())
	}
	return nil
}

// CountMachineIdentityCredentialsByClassification returns install-wide counts
// keyed by classification label via GET
// /api/v1/system/machine-credentials/classification-counts.
func (rs *RemoteStorage) CountMachineIdentityCredentialsByClassification(ctx context.Context) (map[string]int, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/machine-credentials/classification-counts")
	if err != nil {
		return nil, fmt.Errorf("failed to count machine credentials by classification: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("count machine credentials by classification failed: %s", resp.Error.Error())
	}
	var result struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Counts, nil
}

// RevokeMachineIdentityCredential revokes a credential via POST
// /api/v1/system/machine-credentials/{id}/revoke — the server applies the SAME
// atomic conditional UPDATE local_machine_credentials.go does.
func (rs *RemoteStorage) RevokeMachineIdentityCredential(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/system/machine-credentials/%d/revoke", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to revoke machine credential: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("revoke machine credential failed: %s", resp.Error.Error())
	}
	return nil
}

// TouchMachineIdentityCredential updates a credential's last-used timestamp via
// POST /api/v1/system/machine-credentials/{id}/touch — the server applies the
// SAME throttled conditional UPDATE local_machine_credentials.go does.
func (rs *RemoteStorage) TouchMachineIdentityCredential(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	path := fmt.Sprintf("/api/v1/system/machine-credentials/%d/touch", id)
	body := struct {
		UsedAt           time.Time `json:"used_at"`
		StalenessSeconds int64     `json:"staleness_seconds"`
	}{UsedAt: usedAt, StalenessSeconds: int64(staleness / time.Second)}
	resp, err := rs.client.Post(ctx, path, body)
	if err != nil {
		return fmt.Errorf("failed to touch machine credential: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("touch machine credential failed: %s", resp.Error.Error())
	}
	return nil
}

// --- Machine role grants ---

func machineRoleScopeQueryParams(scope storage.Scope) url.Values {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(scope.ProjectID), 10))
	q.Set("environment_id", strconv.FormatUint(uint64(scope.EnvironmentID), 10))
	return q
}

// AssignMachineRole grants roleID to machineID at scope via POST
// /api/v1/system/machine-identities/{id}/roles/{roleId}?project_id=&environment_id=.
func (rs *RemoteStorage) AssignMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/roles/%d?%s", machineID, roleID, machineRoleScopeQueryParams(scope).Encode())
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to assign machine role: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("assign machine role failed: %s", resp.Error.Error())
	}
	return nil
}

// RemoveMachineRole revokes roleID from machineID at scope via DELETE
// /api/v1/system/machine-identities/{id}/roles/{roleId}?project_id=&environment_id=.
func (rs *RemoteStorage) RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/roles/%d?%s", machineID, roleID, machineRoleScopeQueryParams(scope).Encode())
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to remove machine role: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("remove machine role failed: %s", resp.Error.Error())
	}
	return nil
}

// GetMachineRoleIDsAt returns the role IDs granted to machineID that apply at
// scope via GET
// /api/v1/system/machine-identities/{id}/roles/ids?project_id=&environment_id=.
func (rs *RemoteStorage) GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope storage.Scope) ([]uint, error) {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/roles/ids?%s", machineID, machineRoleScopeQueryParams(scope).Encode())
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine role ids: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get machine role ids failed: %s", resp.Error.Error())
	}
	var result struct {
		RoleIDs []uint `json:"role_ids"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.RoleIDs, nil
}

// GetMachineRoles returns every role granted to machineID (any scope) via GET
// /api/v1/system/machine-identities/{id}/roles.
func (rs *RemoteStorage) GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error) {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/roles", machineID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine roles: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get machine roles failed: %s", resp.Error.Error())
	}
	var result struct {
		Roles []roleWire `json:"roles"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.Role, 0, len(result.Roles))
	for _, w := range result.Roles {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// --- OIDC bindings ---

// CreateOIDCBinding persists an already-built binding via POST
// /api/v1/system/machine-oidc-bindings.
func (rs *RemoteStorage) CreateOIDCBinding(ctx context.Context, b *models.MachineIdentityOIDCBinding) (*models.MachineIdentityOIDCBinding, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/machine-oidc-bindings", newMachineIdentityOIDCBindingWire(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc binding: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create oidc binding failed: %s", resp.Error.Error())
	}
	return decodeMachineIdentityOIDCBindingResponse(resp.Data)
}

// GetMachineByOIDCSubject resolves the machine identity bound to (issuer,
// subject) via GET
// /api/v1/system/machine-oidc-bindings/by-subject?issuer=&subject=.
func (rs *RemoteStorage) GetMachineByOIDCSubject(ctx context.Context, issuer, subject string) (*models.MachineIdentity, error) {
	q := url.Values{}
	q.Set("issuer", issuer)
	q.Set("subject", subject)
	path := "/api/v1/system/machine-oidc-bindings/by-subject?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine by oidc subject: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get machine by oidc subject failed: %s", resp.Error.Error())
	}
	return decodeMachineIdentityResponse(resp.Data)
}

// ListOIDCBindings lists a machine identity's OIDC bindings via GET
// /api/v1/system/machine-identities/{id}/oidc-bindings.
func (rs *RemoteStorage) ListOIDCBindings(ctx context.Context, machineID uint) ([]*models.MachineIdentityOIDCBinding, error) {
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/oidc-bindings", machineID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list oidc bindings: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list oidc bindings failed: %s", resp.Error.Error())
	}
	var result struct {
		Bindings []machineIdentityOIDCBindingWire `json:"bindings"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.MachineIdentityOIDCBinding, 0, len(result.Bindings))
	for _, w := range result.Bindings {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// GetOIDCBindingByID retrieves a binding by ID via GET
// /api/v1/system/machine-oidc-bindings/{id}.
func (rs *RemoteStorage) GetOIDCBindingByID(ctx context.Context, id uint) (*models.MachineIdentityOIDCBinding, error) {
	path := fmt.Sprintf("/api/v1/system/machine-oidc-bindings/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get oidc binding: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get oidc binding failed: %s", resp.Error.Error())
	}
	return decodeMachineIdentityOIDCBindingResponse(resp.Data)
}

// DeleteOIDCBinding deletes a binding via DELETE
// /api/v1/system/machine-oidc-bindings/{id}.
func (rs *RemoteStorage) DeleteOIDCBinding(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/system/machine-oidc-bindings/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete oidc binding: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete oidc binding failed: %s", resp.Error.Error())
	}
	return nil
}
