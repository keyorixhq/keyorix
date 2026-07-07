// remote_sso.go — SSO login state for RemoteStorage.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) still
// terminates human SSO/SAML login ITSELF (BeginSSO/CompleteSSO,
// BeginSAML/CompleteSAML in internal/core/sso.go) — it just persists the
// short-lived CSRF-state/nonce row (models.SSOLoginState) against whatever
// storage backend it's configured with, which happens to be this RemoteStorage.
// Before #521 both methods here were unconditional remoteUnsupported(...) stubs,
// so BeginSSO/BeginSAML's very first step failed immediately under
// storage.type: remote — SSO login (both OIDC and SAML) was 100% broken.
//
// These are thin passthroughs onto two new routes under
// /api/v1/system/sso-state (server/http/handlers/sso_state_proxy.go), following
// the exact #510 (setup tokens) / #507 (invitations) pattern: gated on the same
// system.read/system.write RBAC tier every other proxied call already needs, and
// making no SSO policy decision server-side — that stays entirely in the
// calling server's own internal/core.KeyorixCore.
//
// Critically, ConsumeSSOLoginState proxies onto local_sso.go's OWN atomic
// read-then-conditional-delete (`WHERE id = ? AND state = ?`, RowsAffected
// checked) — the single-use-consume guarantee CompleteSSO/CompleteSAML depend
// on to reject a replayed state/RelayState. One HTTP round trip maps to one
// atomic server-side operation, not a client-side "GET, then DELETE" sequence,
// which would reopen exactly that TOCTOU race.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ssoLoginStateWire mirrors models.SSOLoginState's fields exactly (snake_case),
// the wire shape server/http/handlers/sso_state_proxy.go's
// ssoLoginStateProxyWire sends/expects. models.SSOLoginState carries no json
// tags of its own, and this is an internal system-to-system wire format gated
// on system.read/system.write, the same tier that already round-trips full
// user/secret/invitation records.
type ssoLoginStateWire struct {
	ID        uint      `json:"id"`
	State     string    `json:"state"`
	Nonce     string    `json:"nonce"`
	Provider  string    `json:"provider"`
	ReturnTo  string    `json:"return_to"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// newSSOLoginStateWire builds the CreateSSOLoginState request body. Timestamps
// are UTC-normalized for the same reason every other proxied wire type in this
// package normalizes them: LocalStorage's SQLite backend compares these
// TIMESTAMP columns as plain TEXT, not real chronological values, so a
// CreatedAt/ExpiresAt persisted with the calling server's local offset would
// sort incorrectly against a UTC-formatted comparison threshold.
func newSSOLoginStateWire(s *models.SSOLoginState) ssoLoginStateWire {
	return ssoLoginStateWire{
		ID:        s.ID,
		State:     s.State,
		Nonce:     s.Nonce,
		Provider:  s.Provider,
		ReturnTo:  s.ReturnTo,
		ExpiresAt: s.ExpiresAt.UTC(),
		CreatedAt: s.CreatedAt.UTC(),
	}
}

func (w ssoLoginStateWire) toModel() *models.SSOLoginState {
	return &models.SSOLoginState{
		ID:        w.ID,
		State:     w.State,
		Nonce:     w.Nonce,
		Provider:  w.Provider,
		ReturnTo:  w.ReturnTo,
		ExpiresAt: w.ExpiresAt,
		CreatedAt: w.CreatedAt,
	}
}

// CreateSSOLoginState persists the CSRF-state/nonce row via
// POST /api/v1/system/sso-state. BeginSSO/BeginSAML call this immediately after
// building the IdP redirect URL — before #521 this was an unconditional stub,
// so no SSO/SAML login could even start under storage.type: remote.
//
// On success, s is updated in place with the server-assigned ID, mirroring
// local_sso.go's CreateSSOLoginState (gorm's Create populates the same field on
// the caller's pointer) — no caller currently relies on the ID, but keeping the
// two backends' observable behavior identical avoids a latent surprise for a
// future one.
func (rs *RemoteStorage) CreateSSOLoginState(ctx context.Context, s *models.SSOLoginState) error {
	resp, err := rs.client.Post(ctx, "/api/v1/system/sso-state", newSSOLoginStateWire(s))
	if err != nil {
		return fmt.Errorf("failed to create SSO login state: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("create SSO login state failed: %s", resp.Error.Error())
	}
	var wire ssoLoginStateWire
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	s.ID = wire.ID
	return nil
}

// ConsumeSSOLoginState consumes the CSRF-state/nonce row via
// POST /api/v1/system/sso-state/consume, keyed on the state/RelayState value.
// CompleteSSO/CompleteSAML call this on the callback/ACS step to bind the
// returned id_token/assertion back to the login this server itself initiated,
// and to enforce single use (a replayed state/RelayState must fail). See the
// package doc above: the server performs the SAME atomic
// read-then-conditional-delete local_sso.go's own ConsumeSSOLoginState does,
// reporting a clean not-found for an unknown OR already-consumed state — that
// distinction isn't observable to a legitimate caller and shouldn't be to a
// replaying one either.
func (rs *RemoteStorage) ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error) {
	body := struct {
		State string `json:"state"`
	}{State: state}
	resp, err := rs.client.Post(ctx, "/api/v1/system/sso-state/consume", body)
	if err != nil {
		return nil, fmt.Errorf("failed to consume SSO login state: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("consume SSO login state failed: %s", resp.Error.Error())
	}
	var wire ssoLoginStateWire
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}
