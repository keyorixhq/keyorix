// sso.go — human single-sign-on via OIDC (authorization-code flow). A user clicks
// "Sign in with SSO", is redirected to their IdP, and on callback Keyorix verifies
// the id_token (signature via the issuer's JWKS, issuer, audience=client_id, expiry,
// and the nonce it issued), maps the identity to a Keyorix user (the SCIM externalId
// first, then email), and mints the SAME session a password login would — so an
// IdP-provisioned (passwordless) user can actually sign in. SSO logins bypass
// Keyorix-local MFA: the IdP is the trusted authenticator.
//
// When a provider has auto_provision enabled, a first login whose verified identity
// matches no existing account JIT-creates one (active, passwordless, default_role
// baseline) instead of being refused — so an IdP that isn't wired for SCIM push can
// still onboard users on demand. Off by default: an unknown identity is refused.
package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	ssoStateTTL          = 10 * time.Minute
	EventSSOLogin        = "auth.sso_login"
	EventSSOJITProvision = "auth.sso_jit_provisioned"
	ssoClockSkew         = 60 * time.Second
	ssoCompleteSuffix    = "/auth/sso/complete"
	ssoDefaultRole       = "system_viewer"
)

// SSOProvider is a resolved OIDC provider whose endpoints have been discovered.
type SSOProvider struct {
	Name        string
	Issuer      string
	ClientID    string
	OAuth       *oauth2.Config // ClientID/Secret + discovered Auth/Token endpoints + redirect
	CompleteURL string         // <redirect origin>/auth/sso/complete — where the browser lands

	AutoProvision bool   // JIT-create an account on first login for an unknown identity
	DefaultRole   string // baseline role for JIT-provisioned users ("" → system_viewer)
}

// SetSSOProviders wires the configured providers (built from config + discovery at
// startup) and the JWKS resolver used to verify id_tokens. nil/empty disables SSO.
func (c *KeyorixCore) SetSSOProviders(providers map[string]*SSOProvider, jwks JWKSResolver) {
	c.ssoProviders = providers
	c.ssoJWKS = jwks
}

// SSOEnabled reports whether any SSO provider is configured.
func (c *KeyorixCore) SSOEnabled() bool { return len(c.ssoProviders) > 0 }

// SSOProviderNames returns the configured provider names, sorted — for the login page.
func (c *KeyorixCore) SSOProviderNames() []string {
	names := make([]string, 0, len(c.ssoProviders))
	for n := range c.ssoProviders {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SSOCompleteURL returns the browser-facing completion URL for a provider.
func (c *KeyorixCore) SSOCompleteURL(provider string) (string, bool) {
	if p, ok := c.ssoProviders[provider]; ok {
		return p.CompleteURL, true
	}
	return "", false
}

// BeginSSO creates and stores the CSRF state + nonce and returns the IdP
// authorization URL to redirect the browser to.
func (c *KeyorixCore) BeginSSO(ctx context.Context, providerName, returnTo string) (string, error) {
	p, ok := c.ssoProviders[providerName]
	if !ok {
		return "", fmt.Errorf("unknown SSO provider %q", providerName)
	}
	state, err := randToken()
	if err != nil {
		return "", err
	}
	nonce, err := randToken()
	if err != nil {
		return "", err
	}
	if err := c.storage.CreateSSOLoginState(ctx, &models.SSOLoginState{
		State:     state,
		Nonce:     nonce,
		Provider:  providerName,
		ReturnTo:  sanitizeReturnTo(returnTo),
		ExpiresAt: c.now().Add(ssoStateTTL),
		CreatedAt: c.now(),
	}); err != nil {
		return "", err
	}
	return p.OAuth.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce)), nil
}

// CompleteSSO consumes the state, exchanges the code, verifies the id_token, maps it
// to a user, and mints a session. Returns the session, the user, and the in-app path
// to land on (ReturnTo, may be empty).
func (c *KeyorixCore) CompleteSSO(ctx context.Context, providerName, code, state, userAgent, ip string) (*models.Session, *models.User, string, error) {
	p, ok := c.ssoProviders[providerName]
	if !ok {
		return nil, nil, "", fmt.Errorf("unknown SSO provider")
	}
	st, err := c.storage.ConsumeSSOLoginState(ctx, state)
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid or expired login state")
	}
	if st.Provider != providerName {
		return nil, nil, "", fmt.Errorf("login state does not match the callback provider")
	}
	if c.now().After(st.ExpiresAt) {
		return nil, nil, "", fmt.Errorf("login state expired")
	}

	tok, err := p.OAuth.Exchange(ctx, code)
	if err != nil {
		return nil, nil, "", fmt.Errorf("authorization-code exchange failed: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, nil, "", fmt.Errorf("the token response carried no id_token")
	}
	sub, email, name, err := c.verifyIDToken(ctx, p, st.Nonce, rawID)
	if err != nil {
		return nil, nil, "", err
	}

	user, err := c.resolveSSOUser(ctx, sub, email)
	if err != nil {
		return nil, nil, "", err
	}
	if user == nil {
		// No Keyorix account matches this verified identity.
		if !p.AutoProvision {
			return nil, nil, "", fmt.Errorf("no Keyorix account matches this SSO identity")
		}
		if user, err = c.provisionSSOUser(ctx, p, sub, email, name); err != nil {
			return nil, nil, "", err
		}
	}
	if AccountLoginBlocked(user.AccountState) {
		return nil, nil, "", fmt.Errorf("account suspended")
	}

	session, err := c.mintSession(ctx, user.ID, userAgent, ip)
	if err != nil {
		return nil, nil, "", err
	}
	_ = c.RecordLogin(ctx, user.ID) // best-effort last-login stamp
	c.writeAuditEvent(ctx, EventSSOLogin, actorPtr(user.ID), nil,
		fmt.Sprintf("SSO login via %s (subject=%s)", providerName, sub))
	return session, user, st.ReturnTo, nil
}

// resolveSSOUser maps the IdP identity to a Keyorix user: the SCIM externalId
// (subject) first, then email. Returns (nil, nil) when neither matches — the caller
// decides whether to refuse the login or JIT-provision the account.
func (c *KeyorixCore) resolveSSOUser(ctx context.Context, sub, email string) (*models.User, error) {
	notFound := i18n.T("ErrorUserNotFound", nil)
	if sub != "" {
		if u, err := c.storage.GetUserByExternalID(ctx, sub); err == nil {
			return u, nil
		} else if !strings.Contains(err.Error(), notFound) {
			return nil, err
		}
	}
	if email != "" {
		if u, err := c.storage.GetUserByEmail(ctx, email); err == nil {
			return u, nil
		} else if !strings.Contains(err.Error(), notFound) {
			return nil, err
		}
	}
	return nil, nil
}

// provisionSSOUser JIT-creates a Keyorix account for a verified SSO identity that
// matches no existing user (auto_provision must be enabled — the caller gates this).
// The identity has already passed full id_token verification (signature, issuer,
// audience, expiry, nonce), so the IdP subject is trusted as the externalId. The
// account is created ACTIVE — the IdP has authenticated it and the user signs in via
// SSO — with an unusable local password; it deliberately does NOT start in
// pending_first_login (which would trap an SSO user in a password-change-only
// restricted session they can never clear). The baseline role is the provider's
// default_role (system_viewer when unset); an unknown role grants nothing.
func (c *KeyorixCore) provisionSSOUser(ctx context.Context, p *SSOProvider, sub, email, name string) (*models.User, error) {
	if strings.TrimSpace(email) == "" {
		return nil, fmt.Errorf("the IdP returned no email; cannot auto-provision an account")
	}
	// Guard against a race / case where a user materialised between the resolve and
	// here: reuse it rather than create a duplicate.
	if existing, ferr := c.FindSCIMUser(ctx, sub, email); ferr == nil && existing != nil {
		return existing, nil
	}
	username, err := c.deriveSCIMUsername(ctx, email)
	if err != nil {
		return nil, err
	}
	hash, err := randomPasswordHash()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	displayName := strings.TrimSpace(name)
	if displayName == "" {
		displayName = email
	}
	now := c.now()
	created, err := c.storage.CreateUser(ctx, &models.User{
		Username: username, Email: email, DisplayName: displayName,
		PasswordHash: hash, IsActive: true, AccountState: AccountActive, ExternalID: sub,
		PasswordChangedAt: &now, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	role := strings.TrimSpace(p.DefaultRole)
	if role == "" {
		role = ssoDefaultRole
	}
	if r, rerr := c.storage.GetRoleByName(ctx, role); rerr == nil {
		_ = c.storage.AssignRole(ctx, created.ID, r.ID, Scope{})
	}
	c.writeAuditEvent(ctx, EventSSOJITProvision, actorPtr(created.ID), nil,
		fmt.Sprintf("SSO JIT-provisioned user %d via %s (externalId=%q, role=%s)", created.ID, p.Name, sub, role))
	return created, nil
}

// verifyIDToken validates the id_token's signature (asymmetric only), issuer,
// audience (= the provider's client_id), expiry, and the nonce, returning the
// subject, email, and (best-effort) name claims.
func (c *KeyorixCore) verifyIDToken(ctx context.Context, p *SSOProvider, expectedNonce, raw string) (sub, email, name string, err error) {
	var claims struct {
		jwt.RegisteredClaims
		Email string `json:"email"`
		Name  string `json:"name"`
		Nonce string `json:"nonce"`
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}),
		jwt.WithLeeway(ssoClockSkew),
		jwt.WithExpirationRequired(),
	)
	keyfn := func(t *jwt.Token) (interface{}, error) {
		iss, ierr := t.Claims.GetIssuer()
		if ierr != nil || iss != p.Issuer {
			return nil, fmt.Errorf("issuer mismatch")
		}
		kid, _ := t.Header["kid"].(string)
		return c.ssoJWKS.Key(ctx, p.Issuer, kid)
	}
	token, err := parser.ParseWithClaims(raw, &claims, keyfn)
	if err != nil {
		return "", "", "", fmt.Errorf("id_token verification failed: %w", err)
	}
	if !token.Valid || claims.Issuer != p.Issuer {
		return "", "", "", fmt.Errorf("id_token invalid")
	}
	audOK := false
	for _, a := range claims.Audience {
		if a == p.ClientID {
			audOK = true
			break
		}
	}
	if !audOK {
		return "", "", "", fmt.Errorf("id_token audience does not match the client id")
	}
	if expectedNonce == "" || claims.Nonce != expectedNonce {
		return "", "", "", fmt.Errorf("id_token nonce mismatch")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return "", "", "", fmt.Errorf("id_token has no subject")
	}
	return claims.Subject, claims.Email, claims.Name, nil
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// sanitizeReturnTo allows only a same-origin in-app path (leading single slash), so
// the post-login redirect can't be turned into an open redirect.
func sanitizeReturnTo(s string) string {
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		return s
	}
	return ""
}
