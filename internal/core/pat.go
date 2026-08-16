// pat.go — Personal Access Tokens (ADR-027, ADR-042).
//
// A PAT is a long-lived bearer credential a user creates from the My Account page.
// It authenticates API requests AS that user. By default it inherits the owner's
// full permission set; optionally (ADR-042) it carries a least-privilege
// restriction — a permission allowlist and/or a single-project or single-
// environment scope — that narrows it below the owner (never above). The raw
// token is returned once on
// creation; only its SHA-256 hash is stored. Raw tokens carry the patPrefix so the
// auth middleware can route them to ValidatePATToken and secret scanners can detect
// leaks.
package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	// patPrefix marks a raw PAT. Load-bearing: middleware routing + secret scanning.
	patPrefix = "kx_pat_"
	// patTouchInterval throttles last_used_at writes on the auth hot path.
	patTouchInterval = 30 * time.Second
)

// CreatePATResult carries the freshly created token plus its one-time plaintext.
// The plaintext is never persisted and never returned again.
type CreatePATResult struct {
	Token      *models.PersonalAccessToken
	PlainToken string
}

// CreateOwnPAT generates a new personal access token for the caller. expiresAt may
// be nil for a non-expiring token. scopes, when non-empty, is a least-privilege
// permission allowlist (ADR-042); projectScope/environmentScope, when non-zero,
// confine the token to a single project / environment. All only ever NARROW the
// token below its owner — they are enforced at request time as a filter
// intersected with the owner's live permissions, so a token can never grant more
// than its owner currently holds.
func (c *KeyorixCore) CreateOwnPAT(ctx context.Context, userID uint, name string, expiresAt *time.Time, scopes []string, projectScope, environmentScope uint, allowedCIDRs []string) (*CreatePATResult, error) { // NOSONAR -- domain-driven parameter count
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%s: token name is required", i18n.T("ErrorValidation", nil))
	}

	scopesJSON, err := encodePATScopes(scopes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	cidrsJSON, err := encodePATCIDRs(allowedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	raw := patPrefix + base64.RawURLEncoding.EncodeToString(b)

	pat := &models.PersonalAccessToken{
		UserID:           userID,
		Name:             strings.TrimSpace(name),
		TokenHash:        sha256Hex(raw),
		TokenPrefix:      raw[:len(patPrefix)+6], // e.g. "kx_pat_ab12cd" for display
		Scopes:           scopesJSON,
		ProjectScope:     projectScope,
		EnvironmentScope: environmentScope,
		AllowedCIDRs:     cidrsJSON,
		ExpiresAt:        expiresAt,
		CreatedAt:        c.now(),
	}
	created, err := c.storage.CreatePersonalAccessToken(ctx, pat)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return &CreatePATResult{Token: created, PlainToken: raw}, nil
}

// ListOwnPATs returns the caller's tokens (hashes are never exposed by the HTTP DTO).
func (c *KeyorixCore) ListOwnPATs(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.ListPersonalAccessTokensByUser(ctx, userID)
}

// RevokeOwnPAT revokes one of the caller's tokens after verifying ownership. A token
// owned by another user is reported as not found to prevent ID enumeration. On success
// it returns the token's hash so the caller can evict the auth cache immediately: the
// HTTP token cache is keyed by SHA-256(raw token), which equals the stored TokenHash,
// so without eviction a revoked PAT would keep authenticating until the cache TTL.
func (c *KeyorixCore) RevokeOwnPAT(ctx context.Context, userID, tokenID uint) (tokenHash string, err error) {
	if userID == 0 || tokenID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user and token IDs are required")
	}
	pat, err := c.storage.GetPersonalAccessTokenByID(ctx, tokenID)
	if err != nil || pat.UserID != userID {
		return "", fmt.Errorf("%s: token not found", i18n.T("ErrorNotFound", nil))
	}
	if err := c.storage.RevokePersonalAccessToken(ctx, tokenID); err != nil {
		return "", err
	}
	return pat.TokenHash, nil
}

// ValidatePATToken resolves a raw PAT to its owning user, role names, any
// least-privilege restriction (ADR-042; nil when the token is unrestricted),
// and the PAT's row id, mirroring the shape of ValidateSessionToken so the
// auth middleware can use either. It rejects revoked/expired tokens and
// inactive users. The caller (middleware) is expected to gate on the
// patPrefix.
//
// #G60: this deliberately does NOT touch last_used_at itself. A PAT's network
// allowlist (the restriction's AllowedCIDRs) is evaluated by the CALLER
// (server/middleware, server/grpc/interceptors), strictly after this function
// returns — stamping last_used_at in here would record the token as "used"
// even for a request the caller is about to reject outright for arriving
// from a disallowed network, making the timestamp lie about whether the
// token actually succeeded from that request's source. The returned PAT id
// lets the caller invoke TouchPATLastUsed itself, once its own restriction
// check has actually passed.
func (c *KeyorixCore) ValidatePATToken(ctx context.Context, raw string) (*models.User, []string, *PATRestriction, uint, error) {
	if !strings.HasPrefix(raw, patPrefix) {
		return nil, nil, nil, 0, fmt.Errorf("not a personal access token")
	}
	pat, err := c.storage.GetPersonalAccessTokenByHash(ctx, sha256Hex(raw))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("invalid token")
	}
	if pat.Revoked {
		return nil, nil, nil, 0, ErrPATRevoked
	}
	if IsPATExpired(pat, c.now()) {
		c.emitPATExpiredNotification(ctx, pat)
		return nil, nil, nil, 0, ErrPATExpired
	}
	user, err := c.storage.GetUser(ctx, pat.UserID)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("user not found")
	}
	if !user.IsActive {
		return nil, nil, nil, 0, fmt.Errorf("user inactive")
	}
	// A suspended/blocked account must not authenticate via a PAT either. SuspendUser sets
	// account_state but deliberately leaves is_active untouched (and kills sessions), so
	// without this an admin's suspend would cut off session access yet leave the user's
	// personal access tokens fully working. Mirror ValidateSessionToken's account-state
	// gate so suspension is immediately effective on every credential type.
	if AccountLoginBlocked(user.AccountState) {
		return nil, nil, nil, 0, fmt.Errorf("account is not active")
	}

	restriction := patRestrictionFrom(pat)

	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return user, []string{}, restriction, pat.ID, nil
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return user, roleNames, restriction, pat.ID, nil
}

// TouchPATLastUsed records that PAT patID was just used, subject to the same
// patTouchInterval throttle the inline stamp always used. Split out of
// ValidatePATToken (#G60) so the caller only stamps last_used_at AFTER its
// own network-restriction (CIDR allowlist) check has passed — see
// ValidatePATToken's doc comment for why touching unconditionally during
// validation was misleading. Best-effort: never fails the caller's request.
func (c *KeyorixCore) TouchPATLastUsed(ctx context.Context, patID uint) {
	if patID == 0 {
		return
	}
	_ = c.storage.TouchPersonalAccessToken(ctx, patID, c.now(), patTouchInterval)
}

// encodePATScopes normalises and JSON-encodes a permission allowlist for storage.
// Blank entries are dropped and duplicates removed; an all-blank/empty list
// encodes to "" so the token stays unrestricted (the back-compat default).
func encodePATScopes(scopes []string) (string, error) {
	cleaned := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		cleaned = append(cleaned, s)
	}
	if len(cleaned) == 0 {
		return "", nil
	}
	b, err := json.Marshal(cleaned)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodePATScopes parses a stored scopes column back into a permission list.
// An empty column yields nil (unrestricted) — a PAT created without an explicit
// scope allowlist inherits its owner's full permission set, so nil is the
// correct "no restriction" signal.
//
// A non-empty column that fails JSON parsing is treated as corrupted rather than
// unrestricted: the token was created WITH a scope restriction that is now
// unreadable, so we return a sentinel that patRestrictionFrom interprets as
// "deny everything" rather than accidentally widening a previously-restricted
// token to full owner access (#r124 PAT scope fail-open).
var patScopeCorrupted = []string{"__corrupted__"}

func DecodePATScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		// Non-empty but unparseable: fail CLOSED — return a sentinel that no
		// real permission string will ever match, so the PAT is denied everywhere
		// rather than silently granted full owner access on a corrupted row.
		return patScopeCorrupted
	}
	return out
}

// CurrentPATRestriction re-fetches a PAT's restriction fresh from storage by its
// raw token, bypassing any cached UserContext snapshot the auth middleware may be
// holding (#146). The middleware's short-circuit cache holds a validated token's
// full UserContext — including PATRestriction.AllowedCIDRs — for up to
// validTokenTTL; on a cache HIT the network-allowlist check would otherwise be
// enforced against that stale snapshot, not the token's current restriction. This
// lets the network check re-verify fresh on every request regardless of cache
// state, at the cost of one extra lightweight lookup per PAT-authenticated
// request (session/machine tokens carry no such per-request-narrowable
// restriction and are unaffected). Returns an error on any lookup failure — the
// caller must NOT treat that as "unrestricted" (that would fail OPEN on the exact
// check this exists to keep honest); falling back to the last-known (possibly
// stale, but still a real, previously-enforced) restriction is the correct
// degraded behavior on a transient storage error.
//
// #G18: also surfaces ErrPATRevoked/ErrPATExpired — previously this only ever
// read Permissions/ProjectID/EnvironmentID/AllowedCIDRs off the freshly-read
// row and silently discarded Revoked/ExpiresAt, so a cache-hit request kept
// authenticating with a PAT that had been revoked or had expired since the
// cache entry was written, for up to validTokenTTL. The caller must now treat
// these two sentinels as "deny the request", not as a transient lookup
// failure to degrade past (see serveAuthCacheHit).
func (c *KeyorixCore) CurrentPATRestriction(ctx context.Context, raw string) (*PATRestriction, error) {
	pat, err := c.storage.GetPersonalAccessTokenByHash(ctx, sha256Hex(raw))
	if err != nil {
		return nil, err
	}
	if pat.Revoked {
		return nil, ErrPATRevoked
	}
	if IsPATExpired(pat, c.now()) {
		return nil, ErrPATExpired
	}
	return patRestrictionFrom(pat), nil
}

// patRestrictionFrom builds the request-time restriction for a token, or nil when
// the token is unrestricted (no scopes and no project confinement).
func patRestrictionFrom(pat *models.PersonalAccessToken) *PATRestriction {
	scopes := DecodePATScopes(pat.Scopes)
	cidrs := DecodePATCIDRs(pat.AllowedCIDRs)
	if len(scopes) == 0 && pat.ProjectScope == 0 && pat.EnvironmentScope == 0 && len(cidrs) == 0 {
		return nil
	}
	return &PATRestriction{Permissions: scopes, ProjectID: pat.ProjectScope, EnvironmentID: pat.EnvironmentScope, AllowedCIDRs: cidrs}
}

// encodePATCIDRs validates and JSON-encodes a CIDR allowlist for storage. Each entry must
// be a parseable CIDR (e.g. "10.0.0.0/8"); a bare IP is accepted and normalised to a /32
// or /128 host route. Blanks are dropped and duplicates removed; an empty result encodes to
// "" (no network restriction, the back-compat default).
func encodePATCIDRs(cidrs []string) (string, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	cleaned := make([]string, 0, len(cidrs))
	seen := make(map[string]struct{}, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Accept a bare IP by promoting it to a host route.
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil {
				if ip.To4() != nil {
					c += "/32"
				} else {
					c += "/128"
				}
			}
		}
		if _, _, err := net.ParseCIDR(c); err != nil {
			return "", fmt.Errorf("invalid CIDR %q", c)
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		cleaned = append(cleaned, c)
	}
	if len(cleaned) == 0 {
		return "", nil
	}
	b, err := json.Marshal(cleaned)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// patCIDRCorrupted is returned by DecodePATCIDRs when the stored column is non-empty
// but fails JSON parsing — the token was created WITH a CIDR allowlist that is now
// unreadable. Returning nil would silently widen the token to global network access
// (#r125 PAT CIDR fail-open). The sentinel contains no valid CIDR, so IPInCIDRs
// will return false for any source IP, blocking all network access until the
// column is repaired or the token is re-issued.
var patCIDRCorrupted = []string{"<corrupted>"}

// DecodePATCIDRs parses a stored CIDR allowlist back into a slice. An empty column
// yields nil (no restriction). A non-empty column that fails JSON parsing returns a
// sentinel that blocks ALL source IPs rather than failing OPEN to global network access.
func DecodePATCIDRs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		// Non-empty but unparseable: fail CLOSED — return a sentinel that no real
		// CIDR will ever match, so the PAT is denied from all networks rather than
		// silently granted global network access on a corrupted row.
		return patCIDRCorrupted
	}
	return out
}
