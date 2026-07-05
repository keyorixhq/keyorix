// sso.go — human single-sign-on via OIDC (authorization-code flow). A user clicks
// "Sign in with SSO", is redirected to their IdP, and on callback Keyorix verifies
// the id_token (signature via the issuer's JWKS, issuer, audience=client_id, expiry,
// and the nonce it issued), maps the identity to a Keyorix user (this provider's
// scoped externalId first, then a provider-gated email fallback), and mints the SAME
// session a password login would — so an
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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	ssoStateTTL          = 10 * time.Minute
	EventSSOLogin        = "auth.sso_login"
	EventSSOJITProvision = "auth.sso_jit_provisioned"
	EventSSOGroupsSynced = "auth.sso_groups_synced"
	EventSSORolesSynced  = "auth.sso_roles_synced"
	ssoClockSkew         = 60 * time.Second
	ssoCompleteSuffix    = "/auth/sso/complete"
	ssoDefaultRole       = "system_viewer"
	ssoDefaultGroupClaim = "groups"
)

// SAMLAuthn is the slice of a SAML Service Provider the SSO flow needs (satisfied by
// *saml.Provider). It is an interface so the SAML login path is unit-tested without a
// live IdP or a signed response.
type SAMLAuthn interface {
	AuthnRequest(relayState string) (redirectURL, requestID string, err error)
	ParseResponse(r *http.Request, possibleRequestIDs []string) (*samlpkg.AssertionInfo, error)
	Metadata() ([]byte, error)
}

// SSOProvider is a resolved SSO provider. Type is "oidc" (the default) or "saml"; the
// type-specific fields (OAuth/JWKS for OIDC, SAML for SAML) are set accordingly, while
// the provisioning + group/role-mapping fields below are shared by both.
type SSOProvider struct {
	Name        string
	Type        string // "oidc" (default) | "saml"
	Issuer      string
	ClientID    string
	OAuth       *oauth2.Config // OIDC: ClientID/Secret + discovered Auth/Token endpoints + redirect
	CompleteURL string         // <redirect origin>/auth/sso/complete — where the browser lands
	SAML        SAMLAuthn      // SAML: the Service Provider (nil for OIDC providers)

	AutoProvision bool   // JIT-create an account on first login for an unknown identity
	DefaultRole   string // baseline role for JIT-provisioned users ("" → system_viewer)

	// TrustAssertedEmail opts a SAML provider into treating its asserted email as
	// verified for resolveSSOUser's email-fallback account linking. SAML carries no
	// per-assertion equivalent of OIDC's email_verified claim — the assertion being
	// IdP-signed only proves the IdP sent it, not that the IdP itself verified
	// ownership of that address (a self-service/low-trust IdP could let a user set
	// any email). Off by default: without it, CompleteSAML's email fallback can
	// still seed a brand-new JIT account (nothing to take over) but cannot claim an
	// EXISTING one — closing a SAML-specific account-takeover path (#89) that
	// OIDC's real email_verified claim already closes. Ignored for OIDC providers.
	TrustAssertedEmail bool

	GroupSync   bool   // reconcile native group memberships from the IdP groups claim on login
	GroupsClaim string // id_token claim carrying group names ("" → "groups")

	// GroupRoleMap maps an IdP group-claim value to a Keyorix (system) role name. When
	// non-empty, each login reconciles the user's grants of the MAPPED roles to match
	// their asserted groups — the IdP drives those role assignments. Roles outside the
	// map are never touched (so manual grants are safe).
	GroupRoleMap map[string]string
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

// oidcProvider resolves a configured OIDC provider by name. buildSSOProviders
// (server/main.go) never sets Type for an OIDC provider — it's left as the zero
// value, "" — so "not saml" is treated as OIDC here, mirroring samlProvider's
// reciprocal check. This guards the OIDC flow (which dereferences OAuth
// unconditionally) against being invoked for a provider configured with
// Type: "saml", whose OAuth field is always nil.
func (c *KeyorixCore) oidcProvider(name string) (*SSOProvider, error) {
	p, ok := c.ssoProviders[name]
	if !ok || p.Type == "saml" || p.OAuth == nil {
		return nil, fmt.Errorf("unknown SSO provider %q", name)
	}
	return p, nil
}

// BeginSSO creates and stores the CSRF state + nonce and returns the IdP
// authorization URL to redirect the browser to.
func (c *KeyorixCore) BeginSSO(ctx context.Context, providerName, returnTo string) (string, error) {
	p, err := c.oidcProvider(providerName)
	if err != nil {
		return "", err
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
	p, err := c.oidcProvider(providerName)
	if err != nil {
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
	sub, email, name, emailVerified, err := c.verifyIDToken(ctx, p, st.Nonce, rawID)
	if err != nil {
		return nil, nil, "", err
	}

	user, err := c.resolveSSOUser(ctx, p.Name, sub, email, emailVerified)
	if err != nil {
		return nil, nil, "", err
	}
	if user == nil {
		// No Keyorix account matches this verified identity.
		if !p.AutoProvision {
			return nil, nil, "", fmt.Errorf("no Keyorix account matches this SSO identity")
		}
		if user, err = c.provisionSSOUser(ctx, p, sub, email, emailVerified, name); err != nil {
			return nil, nil, "", err
		}
	}
	if AccountLoginBlocked(user.AccountState) {
		return nil, nil, "", fmt.Errorf("account suspended")
	}

	// Reconcile native group memberships and/or mapped role grants from the IdP's
	// groups claim (best-effort — a sync failure must not block an otherwise-valid
	// login).
	if p.GroupSync {
		c.syncSSOGroups(ctx, p, user.ID, rawID)
	}
	if len(p.GroupRoleMap) > 0 {
		c.syncSSORoles(ctx, p, user.ID, rawID)
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

// samlProvider resolves a configured SAML provider by name.
func (c *KeyorixCore) samlProvider(name string) (*SSOProvider, error) {
	p, ok := c.ssoProviders[name]
	if !ok || p.Type != "saml" || p.SAML == nil {
		return nil, fmt.Errorf("unknown SAML provider")
	}
	return p, nil
}

// SAMLMetadata returns the SP metadata XML for a provider (served at the metadata route).
func (c *KeyorixCore) SAMLMetadata(name string) ([]byte, error) {
	p, err := c.samlProvider(name)
	if err != nil {
		return nil, err
	}
	return p.SAML.Metadata()
}

// BeginSAML starts an SP-initiated login: it builds a signed-or-unsigned AuthnRequest,
// stores the login state (RelayState key + the request ID for InResponseTo matching),
// and returns the IdP redirect URL. Mirrors BeginSSO for OIDC.
func (c *KeyorixCore) BeginSAML(ctx context.Context, name, returnTo string) (string, error) {
	p, err := c.samlProvider(name)
	if err != nil {
		return "", err
	}
	relayState, err := randToken()
	if err != nil {
		return "", err
	}
	redirectURL, requestID, err := p.SAML.AuthnRequest(relayState)
	if err != nil {
		return "", fmt.Errorf("build SAML request: %w", err)
	}
	// Reuse the SSO login-state row: State is the RelayState lookup key, Nonce carries
	// the AuthnRequest ID (matched against InResponseTo at the ACS).
	if err := c.storage.CreateSSOLoginState(ctx, &models.SSOLoginState{
		State:     relayState,
		Nonce:     requestID,
		Provider:  name,
		ReturnTo:  sanitizeReturnTo(returnTo),
		ExpiresAt: c.now().Add(ssoStateTTL),
		CreatedAt: c.now(),
	}); err != nil {
		return "", err
	}
	return redirectURL, nil
}

// CompleteSAML consumes the RelayState, validates the SAMLResponse on r (signature,
// audience, recipient, time, InResponseTo — via the vetted library), maps the assertion
// to a user, reconciles groups/roles, and mints a session. Mirrors CompleteSSO.
func (c *KeyorixCore) CompleteSAML(ctx context.Context, name string, r *http.Request, relayState, userAgent, ip string) (*models.Session, *models.User, string, error) {
	p, err := c.samlProvider(name)
	if err != nil {
		return nil, nil, "", err
	}
	st, err := c.storage.ConsumeSSOLoginState(ctx, relayState)
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid or expired login state")
	}
	if st.Provider != name {
		return nil, nil, "", fmt.Errorf("login state does not match the callback provider")
	}
	if c.now().After(st.ExpiresAt) {
		return nil, nil, "", fmt.Errorf("login state expired")
	}

	info, err := p.SAML.ParseResponse(r, []string{st.Nonce})
	if err != nil {
		return nil, nil, "", err
	}
	if strings.TrimSpace(info.Subject) == "" && strings.TrimSpace(info.Email) == "" {
		return nil, nil, "", fmt.Errorf("the assertion carried no subject or email")
	}

	// The assertion being IdP-signed proves the IdP sent this email, not that the
	// IdP verified the user OWNS it — SAML has no per-assertion equivalent of
	// OIDC's email_verified claim. Trusting it unconditionally let a self-service/
	// low-trust SAML IdP claim an EXISTING account (up to a native admin) merely
	// by asserting its address (#89). Gate on the provider's explicit opt-in
	// instead; see SSOProvider.TrustAssertedEmail.
	user, err := c.resolveSSOUser(ctx, p.Name, info.Subject, info.Email, p.TrustAssertedEmail)
	if err != nil {
		return nil, nil, "", err
	}
	if user == nil {
		if !p.AutoProvision {
			return nil, nil, "", fmt.Errorf("no Keyorix account matches this SSO identity")
		}
		if user, err = c.provisionSSOUser(ctx, p, info.Subject, info.Email, true, info.Name); err != nil {
			return nil, nil, "", err
		}
	}
	if AccountLoginBlocked(user.AccountState) {
		return nil, nil, "", fmt.Errorf("account suspended")
	}

	// Reconcile only when the assertion actually carried groups — an IdP that omits the
	// groups attribute must not strip a user's memberships/roles (matches the OIDC
	// absent-claim no-op).
	if len(info.Groups) > 0 {
		if p.GroupSync {
			c.reconcileSSOGroups(ctx, p, user.ID, info.Groups)
		}
		if len(p.GroupRoleMap) > 0 {
			c.reconcileSSORoles(ctx, p, user.ID, info.Groups)
		}
	}

	session, err := c.mintSession(ctx, user.ID, userAgent, ip)
	if err != nil {
		return nil, nil, "", err
	}
	_ = c.RecordLogin(ctx, user.ID) // best-effort last-login stamp
	c.writeAuditEvent(ctx, EventSSOLogin, actorPtr(user.ID), nil,
		fmt.Sprintf("SAML login via %s (subject=%s)", name, info.Subject))
	return session, user, st.ReturnTo, nil
}

// ssoExternalIDScheme namespaces an SSO-provider-managed identity inside the shared
// external_id column. A scoped value "sso:<provider>:<subject>" binds the account to
// exactly ONE SSO provider, so a second IdP that asserts the same subject — or the same
// email — cannot claim it (see resolveSSOUser). Bare external_ids (SCIM externalId,
// RFC 7644) and empty values (local accounts) are deliberately left unscoped so they
// stay interoperable; only JIT-provisioned SSO accounts carry the scheme.
const ssoExternalIDScheme = "sso:"

// ssoExternalID builds the provider-scoped external_id for an SSO identity. Provider
// names are configuration keys (no ':'), so the scheme + provider form a stable prefix.
func ssoExternalID(provider, subject string) string {
	return ssoExternalIDScheme + provider + ":" + subject
}

// ssoBoundToOtherProvider reports whether externalID is an SSO-scoped identity owned by
// a provider OTHER than `provider`. An account in that state must never be linked to
// `provider`'s assertion — doing so is exactly the cross-provider account takeover this
// guards against. Bare/empty external_ids are not provider-bound and return false.
func ssoBoundToOtherProvider(externalID, provider string) bool {
	return strings.HasPrefix(externalID, ssoExternalIDScheme) &&
		!strings.HasPrefix(externalID, ssoExternalID(provider, ""))
}

// resolveSSOUser maps a verified IdP identity from `provider` to a Keyorix user: this
// provider's own scoped external_id first, then email. Returns (nil, nil) when neither
// matches — the caller decides whether to refuse the login or JIT-provision the account.
//
// The email fallback carries two guards that close a cross-provider account-takeover
// vector when more than one SSO provider is trusted (e.g. a corporate IdP plus a
// weaker/partner IdP). (1) The email must be EXPLICITLY verified: an IdP that lets a
// user self-assert an address — or merely omits email_verified — cannot use it to
// claim an EXISTING account (a brand-new JIT account is still provisionable, since
// there is nothing to take over). (2) The matched account must not already be bound to
// a scoped identity owned by a DIFFERENT provider (see ssoBoundToOtherProvider);
// otherwise a second IdP asserting the same email could take over an account owned by
// the first. A never-federated (native or SCIM-by-email) account is claimed for THIS
// provider+subject on first link, so a later provider can't re-link it by asserting the
// same address.
func (c *KeyorixCore) resolveSSOUser(ctx context.Context, provider, sub, email string, emailVerified bool) (*models.User, error) {
	if sub != "" {
		if u, err := c.storage.GetUserByExternalID(ctx, ssoExternalID(provider, sub)); err == nil {
			return u, nil
		} else if !storage.IsUserNotFound(err) {
			return nil, err
		}
	}
	if email == "" || !emailVerified {
		return nil, nil
	}
	u, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		if storage.IsUserNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if ssoBoundToOtherProvider(u.ExternalID, provider) {
		return nil, fmt.Errorf("the email %q is already linked to a different SSO provider", email)
	}
	if u.ExternalID == "" && sub != "" {
		// Claim this never-federated account for the verifying provider+subject so a
		// later provider can't re-link it by asserting the same email. Best-effort: a
		// failed update just means we re-link on the next login.
		u.ExternalID = ssoExternalID(provider, sub)
		if updated, uerr := c.storage.UpdateUser(ctx, u); uerr == nil {
			u = updated
		}
	}
	return u, nil
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
func (c *KeyorixCore) provisionSSOUser(ctx context.Context, p *SSOProvider, sub, email string, emailVerified bool, name string) (*models.User, error) {
	if strings.TrimSpace(email) == "" {
		return nil, fmt.Errorf("the IdP returned no email; cannot auto-provision an account")
	}
	// Guard against a race / case where a user materialised between the resolve and here:
	// reuse it rather than create a duplicate. This MUST go through resolveSSOUser (not a
	// raw email lookup), so the same guards apply — an EXISTING account is reused via an
	// email match ONLY when the email is verified, and never when it is bound to a
	// different provider's federated identity. Re-running the SAME gated resolution
	// means the race path cannot bypass either check.
	if existing, ferr := c.resolveSSOUser(ctx, p.Name, sub, email, emailVerified); ferr != nil {
		return nil, ferr
	} else if existing != nil {
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
		PasswordHash: hash, IsActive: true, AccountState: AccountActive, ExternalID: ssoExternalID(p.Name, sub),
		PasswordChangedAt: &now, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		// #117: the FindSCIMUser reuse-check above races with a concurrent JIT-provision
		// (or any other create) for the identical email — both can pass it before either
		// commits. The DB-level partial unique index catches the loser here and CreateUser
		// wraps it in ErrDuplicateEmail; surface a clean error instead of a raw
		// constraint-violation message.
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("a user with this email already exists")
		}
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

// syncSSOGroups reconciles the user's NATIVE group memberships to the groups the IdP
// asserts in the (already-verified) id_token's configured groups claim. The IdP is
// the source of truth: the user is added to native groups whose name matches an
// asserted group and removed from native groups it didn't assert — so revoking a
// group at the IdP deprovisions the corresponding Keyorix access on next login. It
// only ever touches MEMBERSHIPS of groups that already exist natively (provisioned by
// SCIM or an admin); it never creates or deletes groups, and an asserted group with
// no native counterpart is ignored.
//
// Crucially, if the groups claim is ABSENT from the token (vs present-but-empty), the
// sync is a no-op: many IdPs only emit groups in the userinfo endpoint or under a
// specific scope, and treating "absent" as "assert no groups" would strip every
// membership on login. Best-effort: errors are swallowed (the caller must not fail an
// otherwise-valid login on a sync hiccup), but the net change is audited.
func (c *KeyorixCore) syncSSOGroups(ctx context.Context, p *SSOProvider, userID uint, rawID string) {
	claim := strings.TrimSpace(p.GroupsClaim)
	if claim == "" {
		claim = ssoDefaultGroupClaim
	}
	asserted, present := extractTokenStringList(rawID, claim)
	if !present {
		return // IdP did not assert groups in the id_token — leave memberships untouched.
	}
	c.reconcileSSOGroups(ctx, p, userID, asserted)
}

// reconcileSSOGroups reconciles native group memberships to match the asserted group
// names — shared by the OIDC (id_token claim) and SAML (assertion attribute) paths.
func (c *KeyorixCore) reconcileSSOGroups(ctx context.Context, p *SSOProvider, userID uint, asserted []string) {
	assertedSet := make(map[string]bool, len(asserted))
	for _, g := range asserted {
		if g = strings.TrimSpace(g); g != "" {
			assertedSet[g] = true
		}
	}

	nativeGroups, err := c.storage.ListGroups(ctx)
	if err != nil {
		return
	}
	// Desired native group IDs = native groups whose name the IdP asserted.
	desired := make(map[uint]bool)
	for _, g := range nativeGroups {
		if assertedSet[g.Name] {
			desired[g.ID] = true
		}
	}
	current, err := c.storage.GetUserGroups(ctx, userID)
	if err != nil {
		return
	}
	currentSet := make(map[uint]bool, len(current))
	for _, g := range current {
		currentSet[g.ID] = true
	}

	added, removed, blocked := 0, 0, 0
	for id := range desired {
		if currentSet[id] {
			continue
		}
		// Refuse to ESCALATE into an admin-conferring group via an IdP group assertion —
		// the same guard SCIM applies (scimGroupConfersAdmin; the predicate is not
		// SCIM-specific). IdP group membership/names are often self-service or governed by
		// people who are not Keyorix admins, so silently inheriting an admin role from a
		// name match would be a privilege escalation. scimGroupConfersAdmin fails CLOSED on
		// a lookup error, so an unverifiable group is treated as admin-bearing and skipped.
		if c.scimGroupConfersAdmin(ctx, id) {
			blocked++
			continue
		}
		if err := c.storage.AddUserToGroup(ctx, userID, id); err == nil {
			added++
		}
	}
	// De-escalating removals are unconditional (dropping a group only reduces privilege).
	for id := range currentSet {
		if !desired[id] {
			if err := c.storage.RemoveUserFromGroup(ctx, userID, id); err == nil {
				removed++
			}
		}
	}
	if added > 0 || removed > 0 || blocked > 0 {
		msg := fmt.Sprintf("SSO group sync via %s: user %d (+%d/-%d native group memberships)", p.Name, userID, added, removed)
		if blocked > 0 {
			msg += fmt.Sprintf("; %d admin-conferring group(s) refused (IdP assertion cannot grant admin)", blocked)
		}
		c.writeAuditEvent(ctx, EventSSOGroupsSynced, actorPtr(userID), nil, msg)
	}
}

// syncSSORoles reconciles the user's grants of the MAPPED (system) roles to match the
// roles their asserted IdP groups map to via GroupRoleMap — so the IdP drives those
// role assignments. It is authoritative ONLY over the set of roles named in the map
// (the "managed" roles): a managed role is granted when an asserted group maps to it
// and removed when none do; a role NOT in the map is never touched, so manual grants
// survive. Like group sync, an ABSENT groups claim is a no-op (so an IdP that omits
// groups can't strip a user's roles), and it is best-effort (never blocks login).
// Roles are bound at global scope (system roles); an unknown mapped role is skipped.
func (c *KeyorixCore) syncSSORoles(ctx context.Context, p *SSOProvider, userID uint, rawID string) {
	claim := strings.TrimSpace(p.GroupsClaim)
	if claim == "" {
		claim = ssoDefaultGroupClaim
	}
	asserted, present := extractTokenStringList(rawID, claim)
	if !present {
		return // IdP did not assert groups in the id_token — leave roles untouched.
	}
	c.reconcileSSORoles(ctx, p, userID, asserted)
}

// reconcileSSORoles reconciles the user's grants of the MAPPED roles to match the roles
// their asserted groups map to — shared by the OIDC and SAML paths. Authoritative only
// over roles named in GroupRoleMap (manual grants survive).
func (c *KeyorixCore) reconcileSSORoles(ctx context.Context, p *SSOProvider, userID uint, asserted []string) {
	assertedSet := make(map[string]bool, len(asserted))
	for _, g := range asserted {
		if g = strings.TrimSpace(g); g != "" {
			assertedSet[g] = true
		}
	}

	// desiredRoles = role names an asserted group maps to; managedRoles = every role
	// name the map can grant (the authoritative scope).
	desiredRoles := make(map[string]bool)
	managedRoles := make(map[string]bool)
	for group, role := range p.GroupRoleMap {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		managedRoles[role] = true
		if assertedSet[group] {
			desiredRoles[role] = true
		}
	}

	// The user's current global-scope role names.
	current, err := c.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return
	}
	currentSet := make(map[string]bool, len(current))
	for _, r := range current {
		currentSet[r.Name] = true
	}

	// Route through the audited RBAC choke point (assignUserRoleSystemGrant/
	// RemoveUserRole) so each individual role change lands in the RBAC audit trail
	// with a structured RoleID, not just the coarse aggregate-count event below
	// (#297). The acting principal is the logging-in user themself — the same
	// attribution the aggregate auth.sso_roles_synced event below already used —
	// since the grant is driven by their own IdP-asserted groups against the
	// admin-configured map. The grant deliberately uses assignUserRoleSystemGrant,
	// not AssignUserRole: the #93/#107/#141 grant-ceiling check would require the
	// logging-in user to already hold every permission of the role they're being
	// auto-provisioned — impossible for their FIRST SSO-driven grant, and beside
	// the point, since authorization here is rooted in the admin-configured
	// GroupRoleMap and the verified IdP assertion, not in the user's own
	// roles.assign-derived authority.
	added, removed, blocked := 0, 0, 0
	for role := range managedRoles {
		r, rerr := c.storage.GetRoleByName(ctx, role)
		if rerr != nil {
			continue // unknown role — skip rather than fail the login
		}
		switch {
		case desiredRoles[role] && !currentSet[role]:
			// Refuse to grant an admin-tier role from an IdP group mapping (#96) —
			// the same escalation-by-proxy guard reconcileSSOGroups already applies to
			// admin-conferring GROUPS. GroupRoleMap is configured once by an admin, but
			// IdP group membership is frequently self-service or governed by people
			// who are not Keyorix admins, so a mapping intended for a routine role must
			// not double as a path to global admin for anyone who can join the group.
			if isAdminRoleName(role) {
				blocked++
				continue
			}
			if c.assignUserRoleSystemGrant(ctx, userID, userID, r.ID, Scope{}) == nil {
				added++
			}
		case !desiredRoles[role] && currentSet[role]:
			if c.RemoveUserRole(ctx, userID, userID, r.ID, Scope{}) == nil {
				removed++
			}
		}
	}
	if added > 0 || removed > 0 || blocked > 0 {
		msg := fmt.Sprintf("SSO role mapping via %s: user %d (+%d/-%d mapped role grants)", p.Name, userID, added, removed)
		if blocked > 0 {
			msg += fmt.Sprintf("; %d admin-tier role grant(s) refused (IdP group mapping cannot grant admin)", blocked)
		}
		c.writeAuditEvent(ctx, EventSSORolesSynced, actorPtr(userID), nil, msg)
	}
}

// extractTokenStringList pulls a string-list claim from an ALREADY-VERIFIED id_token
// (verifyIDToken ran on the same raw token immediately before). The claim name is
// configurable, so it can't be a static struct tag; the verified payload is decoded
// into a map and the claim coerced from []string, []any (of strings), or a single
// string. Returns (values, present) — present distinguishes an absent claim from an
// empty list.
func extractTokenStringList(raw, claim string) ([]string, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	raw2, ok := claims[claim]
	if !ok {
		return nil, false
	}
	// Try []string, then []any (coerce string elements), then a single string.
	var list []string
	if err := json.Unmarshal(raw2, &list); err == nil {
		return list, true
	}
	var anyList []any
	if err := json.Unmarshal(raw2, &anyList); err == nil {
		out := make([]string, 0, len(anyList))
		for _, v := range anyList {
			if s, isStr := v.(string); isStr {
				out = append(out, s)
			}
		}
		return out, true
	}
	var single string
	if err := json.Unmarshal(raw2, &single); err == nil {
		return []string{single}, true
	}
	return nil, true // claim present but an unrecognised shape — treat as empty assertion
}

// ssoBool unmarshals a JSON boolean OR the strings "true"/"false" — some IdPs send
// email_verified as a string rather than a bool, and a strict bool field would fail
// the whole token parse. A pointer to it distinguishes "absent" (nil) from "false".
type ssoBool bool

func (b *ssoBool) UnmarshalJSON(data []byte) error {
	*b = ssoBool(strings.Trim(string(data), `"`) == "true")
	return nil
}

// verifyIDToken validates the id_token's signature (asymmetric only), issuer,
// audience (= the provider's client_id), expiry, and the nonce, returning the
// subject, email, (best-effort) name, and whether the email was EXPLICITLY verified.
// The email is dropped only when the IdP explicitly marks it unverified
// (email_verified: false). An absent email_verified claim is treated as trusted for
// JIT-provisioning — it is OPTIONAL in OIDC and common enterprise IdPs (e.g. Entra ID)
// omit it — but emailVerified is reported true only when the claim is present and true,
// so resolveSSOUser can refuse to MATCH AN EXISTING account on a merely-asserted email.
func (c *KeyorixCore) verifyIDToken(ctx context.Context, p *SSOProvider, expectedNonce, raw string) (sub, email, name string, emailVerified bool, err error) {
	var claims struct {
		jwt.RegisteredClaims
		Email         string   `json:"email"`
		EmailVerified *ssoBool `json:"email_verified"`
		Name          string   `json:"name"`
		Nonce         string   `json:"nonce"`
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
		return "", "", "", false, fmt.Errorf("id_token verification failed: %w", err)
	}
	if !token.Valid || claims.Issuer != p.Issuer {
		return "", "", "", false, fmt.Errorf("id_token invalid")
	}
	audOK := false
	for _, a := range claims.Audience {
		if a == p.ClientID {
			audOK = true
			break
		}
	}
	if !audOK {
		return "", "", "", false, fmt.Errorf("id_token audience does not match the client id")
	}
	if expectedNonce == "" || claims.Nonce != expectedNonce {
		return "", "", "", false, fmt.Errorf("id_token nonce mismatch")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return "", "", "", false, fmt.Errorf("id_token has no subject")
	}
	email = claims.Email
	if email != "" && claims.EmailVerified != nil && !bool(*claims.EmailVerified) {
		// The IdP explicitly says this address is unverified — don't trust it for
		// identity. The subject (externalId) match still works; only the email
		// fallback / JIT-provisioning lose this untrusted address.
		email = ""
	}
	emailVerified = claims.EmailVerified != nil && bool(*claims.EmailVerified)
	return claims.Subject, email, claims.Name, emailVerified, nil
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
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return ""
	}
	// A backslash right after the leading slash — e.g. "/\evil.com" — is rejected
	// outright: several browsers normalize a leading "\" to "/", turning this into
	// "//evil.com", the exact protocol-relative open-redirect the "//" check above
	// is meant to block, just spelled with a backslash to slip past a naive
	// HasPrefix(s, "//") check. Reject a backslash anywhere in the value, not just
	// right after the leading slash — a normalized-later backslash deeper in the
	// string (e.g. "/ok/\/evil.com") could still be re-interpreted as a host
	// boundary by a permissive parser downstream.
	if strings.ContainsRune(s, '\\') {
		return ""
	}
	// Belt-and-suspenders: confirm this really parses as a schemeless, hostless
	// relative reference. Guards against any other scheme/host-smuggling trick
	// (e.g. an embedded "://") that the prefix checks above don't anticipate.
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return s
}
