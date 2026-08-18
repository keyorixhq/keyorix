// connect.go — Keyorix Connect (ADR-043): authorized, audited read-through to
// external secret stores. The HTTP layer gates access with RBAC; this layer resolves
// the named connector, proxies the read, and audits it. Values are never persisted.
package core

import (
	"context"
	"fmt"
	"log"
	"path"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventConnectSecretRead is audited on every federated read (success or failure is
// distinguished by the description).
const EventConnectSecretRead = "connect.secret_read"

// Per-reference grant management events (ADR-045).
const (
	EventConnectRefGrantCreate = "connect.ref_grant_create"
	EventConnectRefGrantDelete = "connect.ref_grant_delete"
)

// SetConnectManager wires the configured external-store connectors (ADR-043). nil
// (the default) leaves Keyorix Connect disabled.
func (c *KeyorixCore) SetConnectManager(m *connect.Manager) {
	c.connectManager = m
}

// ConnectOwnership is one connector's resolved tenant-scoping data (ADR-082 §A),
// built by server/main.go's boot-time resolution and set via SetConnectOwnership —
// see connectManager's own doc comment for why this lives here rather than on
// *connect.Manager or the Connector interface. Exported so server/main.go (a
// different package) can construct it.
type ConnectOwnership struct {
	// Scope is "project" or "platform" (ADR-082 §B) — boot validation
	// (internal/config.validateConnectScopes) already guarantees no other value
	// reaches here.
	Scope string
	// ProjectID is the connector's owning Keyorix project, resolved via the
	// connector→project binding (ADR-082, ConnectorProjectBinding). Meaningless
	// (zero) when Scope is "platform".
	ProjectID uint
}

// SetConnectOwnership wires each connector's resolved tenant-scoping data
// (ADR-082), built in the same boot pass as SetConnectManager's *connect.Manager,
// from the same config. Must be called with an ownership entry for EVERY connector
// name SetConnectManager was given — server/main.go enforces this key-set match at
// boot (a mismatch fails boot, aggregated) before either setter is called, so this
// is a precondition, not something re-checked here.
func (c *KeyorixCore) SetConnectOwnership(ownership map[string]ConnectOwnership) {
	c.connectOwnership = ownership
}

// ConnectEnabled reports whether any external-store connector is configured.
func (c *KeyorixCore) ConnectEnabled() bool {
	return c.connectManager != nil && len(c.connectManager.Names()) > 0
}

// ConnectConnectorNames lists every configured connector name, unfiltered — used
// internally by boot-time resolution (server/main.go) and tests. Caller-facing
// discovery (HTTP/gRPC ListConnectors) must use ConnectReadableConnectorNames
// instead (ADR-082 §E): this method does not filter by ownership, and would leak
// the existence of connectors the caller cannot reach.
func (c *KeyorixCore) ConnectConnectorNames() []string {
	if c.connectManager == nil {
		return nil
	}
	return c.connectManager.Names()
}

// ConnectReadableConnectorNames lists the configured connectors the caller can
// actually reach (ADR-082 §E) — the caller-facing discovery surface for both HTTP
// and gRPC ListConnectors, so both transports filter identically through this one
// core method rather than duplicating the ownership comparison per transport. A
// connector the caller cannot reach is omitted entirely, not merely marked
// unreachable — the existing behavior for a caller with no readable connectors at
// all is an empty list, not an error.
func (c *KeyorixCore) ConnectReadableConnectorNames(ctx context.Context, actorType string, principalID uint) ([]string, error) {
	if c.connectManager == nil {
		return nil, nil
	}
	var readable []string
	for _, name := range c.connectManager.Names() {
		owned, err := c.connectOwnershipSatisfied(ctx, actorType, principalID, name)
		if err != nil {
			return nil, err
		}
		if owned {
			readable = append(readable, name)
			continue
		}
		// Not owned — a connector reachable only via an explicit ConnectRefGrant
		// still belongs in discovery; ReadSecret still applies the ref-prefix match
		// per-read. actorRoleIDs (not connectRefGrantDelegates) is the right check
		// here: delegation for LISTING purposes only needs "does the caller hold a
		// role with ANY grant on this connector," not a specific ref match.
		delegated, err := c.connectorHasAnyDelegationForActor(ctx, actorType, principalID, name)
		if err != nil {
			return nil, err
		}
		if delegated {
			readable = append(readable, name)
		}
	}
	return readable, nil
}

// connectOwnershipSatisfied reports whether principalID owns the connector's
// project (ADR-082 §E) — the same comparison every caller's ownership check runs
// through, admin included: a global-scoped role's {0,0} entry (see below) is a
// wildcard in the INPUT, not a different code path. A connector absent from
// connectOwnership is denied, never silently skipped or treated as owned (a
// structural invariant server/main.go's boot-time key-set check exists to
// guarantee never happens in a correctly-booted server; this is the runtime
// backstop).
func (c *KeyorixCore) connectOwnershipSatisfied(ctx context.Context, actorType string, principalID uint, connectorName string) (bool, error) {
	owner, ok := c.connectOwnership[connectorName]
	if !ok {
		return false, nil
	}
	if owner.Scope == "platform" {
		// TODO(ADR-082 branch 4): gate platform connectors on connect.platform.use,
		// not connect.read alone. Every caller who reaches this function has
		// already cleared connect.read (checked by the transport layer before
		// ReadFederatedSecret/ConnectReadableConnectorNames is ever called), so this
		// is a deliberate interim "any connect.read holder" pass-through, not an
		// oversight.
		return true, nil
	}
	// scope == "project": raw scope set, NOT GetReadableScopes (D) — the {0,0}
	// global entry must survive so the loop below can match it as the wildcard
	// (E), not be stripped before comparison.
	var scopes []Scope
	var err error
	if actorType == ActorTypeMachine {
		scopes, err = c.storage.GetMachineRoleScopes(ctx, principalID)
	} else {
		scopes, err = c.storage.GetUserRoleScopes(ctx, principalID)
	}
	if err != nil {
		return false, fmt.Errorf("connect ownership: enumerate role scopes: %w", err)
	}
	for _, sc := range scopes {
		if sc.ProjectID == owner.ProjectID || sc.ProjectID == 0 {
			return true, nil
		}
	}
	return false, nil
}

// ReadFederatedSecret proxies a read of ref from the named external-store connector
// and audits it. The caller (transport layer) must have already enforced the global
// connect.read permission; actorType ("user" / "machine_identity") and principalID
// identify the caller for per-reference RBAC (ADR-045). The audit events this writes
// are stamped with actorType directly (via WithActorType) rather than trusting that
// the caller's ctx already carries the matching tag — a machine-identity read must be
// attributed as ActorTypeMachine (ADR-023) even if a future/CLI caller reaches this
// function with an untagged context, not silently default to "user". The value is
// returned to the caller and never persisted.
func (c *KeyorixCore) ReadFederatedSecret(ctx context.Context, actorType string, principalID uint, connectorName, ref string) (string, error) {
	if c.connectManager == nil {
		return "", ErrConnectDisabled
	}
	conn, ok := c.connectManager.Get(connectorName)
	if !ok {
		return "", fmt.Errorf("%w %q", ErrConnectUnknownConnector, connectorName)
	}
	ctx = WithActorType(ctx, actorType)
	uid := principalID

	// ADR-082 §E authorization order: connect.read (enforced by the transport layer
	// before this function is ever called) → ownership → ConnectRefGrant delegation
	// → deny. No audit call on either branch below — audit is branch 3 (ADR-082);
	// this branch's denials are deliberately unaudited, same as ADR-082 itself notes.
	owned, err := c.connectOwnershipSatisfied(ctx, actorType, principalID, connectorName)
	if err != nil {
		return "", err
	}
	if owned {
		// Per-reference RBAC (ADR-045): once a connector has any ref-grant, the read
		// is permitted only if one of the caller's roles holds a matching grant. A
		// connector with no grants is governed solely by connect.read + allowed_refs
		// (unchanged) — this still applies to an OWNED caller exactly as it did
		// before ownership existed; ownership does not bypass ADR-045's own
		// per-ref narrowing.
		allowed, err := c.connectRefAllowed(ctx, actorType, principalID, connectorName, ref)
		if err != nil {
			return "", err
		}
		if !allowed {
			c.writeAuditEvent(ctx, EventConnectSecretRead, &uid, nil,
				fmt.Sprintf("federated read DENIED by per-reference policy: connector %q (%s) ref %q", connectorName, conn.Type(), ref))
			return "", fmt.Errorf("ref %q %w %q", ref, ErrConnectRefNotPermitted, connectorName)
		}
	} else {
		// Not owned — ConnectRefGrant is the explicit cross-project delegation path
		// (ADR-082 §F). connectRefGrantDelegates (unlike connectRefAllowed) treats
		// "no grants configured" as "no delegation," not "allow": that shortcut only
		// makes sense for an already-owned caller.
		delegated, err := c.connectRefGrantDelegates(ctx, actorType, principalID, connectorName, ref)
		if err != nil {
			return "", err
		}
		if !delegated {
			// Ownership denied and no delegation grant: reuse the unknown-connector
			// shape (ADR-082) — do not confirm this connector's existence to a caller
			// who cannot reach it. ListConnectors already omits it from discovery;
			// this keeps the single-connector read path consistent with that.
			return "", fmt.Errorf("%w %q", ErrConnectUnknownConnector, connectorName)
		}
	}

	value, err := conn.GetSecret(ctx, ref)
	if err != nil {
		// The upstream connector's raw error (e.g. a Vault/AWS SDK error) can carry
		// internal detail — hostname, credential hints, driver messages — that must
		// not be persisted into the audit trail unredacted (backlog #116). Log the
		// original err server-side and persist a generic description instead; the
		// HTTP layer separately applies clientSafe()/isSafeConnectError to what it
		// returns to the caller.
		log.Printf("federated read failed via connector %q (%s) ref %q: %v", connectorName, conn.Type(), ref, err)
		c.writeAuditEvent(ctx, EventConnectSecretRead, &uid, nil,
			fmt.Sprintf("federated read FAILED via connector %q (%s) ref %q: an internal error occurred; see server logs", connectorName, conn.Type(), ref))
		return "", err
	}
	c.writeAuditEvent(ctx, EventConnectSecretRead, &uid, nil,
		fmt.Sprintf("federated read via connector %q (%s) ref %q", connectorName, conn.Type(), ref))
	return value, nil
}

// ListConnectRefGrants returns every per-reference grant (ADR-045), for management.
func (c *KeyorixCore) ListConnectRefGrants(ctx context.Context) ([]*models.ConnectRefGrant, error) {
	return c.storage.ListConnectRefGrants(ctx)
}

// CreateConnectRefGrant adds a per-reference grant (ADR-045): role roleID may read any
// ref under refPrefix ("" = all) on connectorName. The connector must be configured —
// scoping a non-existent (typo'd) connector is rejected so an operator can't believe
// they restricted a connector that is in fact still unscoped. expiresAt makes the
// grant time-bound (nil = permanent), mirroring UserRole.ExpiresAt / ShareRecord.
// ExpiresAt — a Connect grant is otherwise permanent with no way to make it JIT.
// Audited.
func (c *KeyorixCore) CreateConnectRefGrant(ctx context.Context, actorID, roleID uint, connectorName, refPrefix string, expiresAt *time.Time) (*models.ConnectRefGrant, error) {
	if c.connectManager == nil {
		return nil, ErrConnectDisabled
	}
	if _, ok := c.connectManager.Get(connectorName); !ok {
		return nil, fmt.Errorf("%w %q", ErrConnectUnknownConnector, connectorName)
	}
	if roleID == 0 {
		return nil, ErrConnectRoleRequired
	}
	g, err := c.storage.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{
		RoleID:    roleID,
		Connector: connectorName,
		RefPrefix: refPrefix,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, err
	}
	uid := actorID
	c.writeAuditEvent(ctx, EventConnectRefGrantCreate, &uid, nil,
		fmt.Sprintf("connect ref-grant: role %d may read ref-prefix %q on connector %q", roleID, refPrefix, connectorName))
	return g, nil
}

// DeleteConnectRefGrant removes a per-reference grant by id. Audited.
func (c *KeyorixCore) DeleteConnectRefGrant(ctx context.Context, actorID, id uint) error {
	if err := c.storage.DeleteConnectRefGrant(ctx, id); err != nil {
		return err
	}
	uid := actorID
	c.writeAuditEvent(ctx, EventConnectRefGrantDelete, &uid, nil,
		fmt.Sprintf("connect ref-grant %d deleted", id))
	return nil
}

// connectRefAllowed applies the per-reference RBAC policy (ADR-045) for a federated
// read. It returns true when the connector has no ref-grants (the policy is opt-in,
// per connector), or when one of the caller's roles holds a grant whose RefPrefix is a
// prefix of ref. Otherwise the read is denied — deny-by-default once a connector is
// scoped, so a principal whose roles do not match (including one with no resolvable
// roles) cannot read from a grant-scoped connector.
func (c *KeyorixCore) connectRefAllowed(ctx context.Context, actorType string, principalID uint, connectorName, ref string) (bool, error) {
	grants, err := c.storage.ListConnectRefGrantsByConnector(ctx, connectorName)
	if err != nil {
		return false, fmt.Errorf("connect ref-grant lookup: %w", err)
	}
	if len(grants) == 0 {
		return true, nil // no per-ref policy for this connector
	}
	roleSet, err := c.actorRoleIDs(ctx, actorType, principalID)
	if err != nil {
		return false, err
	}
	now := time.Now()
	for _, g := range grants {
		if roleSet[g.RoleID] && connectGrantActive(g, now) && refMatches(g.RefPrefix, ref) {
			return true, nil
		}
	}
	return false, nil
}

// connectRefGrantDelegates reports whether principalID may read ref from
// connectorName via an explicit ConnectRefGrant (ADR-082 §F), for a caller who did
// NOT satisfy ownership (connectOwnershipSatisfied). This is deliberately a
// SEPARATE function from connectRefAllowed, not a modified version of it: for an
// OWNED caller, connectRefAllowed's "no grants configured on this connector" case
// correctly means "no additional per-ref narrowing — allow" (ADR-045's original,
// unchanged semantics). For a NOT-owned caller, "no grants configured" means there
// is no delegation path at all — the opposite polarity. Reusing connectRefAllowed
// for both would either wrongly grant a non-owned caller access to every
// grant-less connector, or wrongly narrow an owned caller's existing access;
// ConnectRefGrant's own schema, matching rules (refMatches), and expiry logic
// (connectGrantActive) are unchanged (ADR-082) — only which caller populations
// reach this delegation check is new.
func (c *KeyorixCore) connectRefGrantDelegates(ctx context.Context, actorType string, principalID uint, connectorName, ref string) (bool, error) {
	grants, err := c.storage.ListConnectRefGrantsByConnector(ctx, connectorName)
	if err != nil {
		return false, fmt.Errorf("connect ref-grant lookup: %w", err)
	}
	if len(grants) == 0 {
		return false, nil // no delegation grant configured — no delegation path
	}
	roleSet, err := c.actorRoleIDs(ctx, actorType, principalID)
	if err != nil {
		return false, err
	}
	now := time.Now()
	for _, g := range grants {
		if roleSet[g.RoleID] && connectGrantActive(g, now) && refMatches(g.RefPrefix, ref) {
			return true, nil
		}
	}
	return false, nil
}

// connectorHasAnyDelegationForActor reports whether principalID holds a role with
// ANY active ConnectRefGrant on connectorName, regardless of ref prefix — used only
// by ConnectReadableConnectorNames (listing), where there is no specific ref to
// match against; a per-read call still applies the exact ref-prefix match via
// connectRefGrantDelegates.
func (c *KeyorixCore) connectorHasAnyDelegationForActor(ctx context.Context, actorType string, principalID uint, connectorName string) (bool, error) {
	grants, err := c.storage.ListConnectRefGrantsByConnector(ctx, connectorName)
	if err != nil {
		return false, fmt.Errorf("connect ref-grant lookup: %w", err)
	}
	if len(grants) == 0 {
		return false, nil
	}
	roleSet, err := c.actorRoleIDs(ctx, actorType, principalID)
	if err != nil {
		return false, err
	}
	now := time.Now()
	for _, g := range grants {
		if roleSet[g.RoleID] && connectGrantActive(g, now) {
			return true, nil
		}
	}
	return false, nil
}

// connectGrantActive reports whether a Connect ref-grant still authorizes at time now:
// a nil ExpiresAt is permanent, otherwise the grant stops authorizing the instant it
// passes — mirroring shareActive / UserRole.ExpiresAt. An expired grant is denied
// immediately here; a background sweep is not required for correctness.
func connectGrantActive(g *models.ConnectRefGrant, now time.Time) bool {
	return g.ExpiresAt == nil || now.Before(*g.ExpiresAt)
}

// refMatches reports whether ref is covered by a grant's pattern (ADR-045). A pattern
// with no glob metacharacters (*, ?, [) is matched on a path-segment boundary:
// ref must equal pattern exactly, or extend it starting with '/'. An empty pattern
// ("") matches everything (the grant is connector-wide). This prevents a grant with
// RefPrefix="db/prod" from authorizing the sibling namespace "db/production-other"
// — a bypass that a bare strings.HasPrefix check would allow.
//
// A pattern containing a metacharacter is matched as a shell-style glob via
// path.Match, where * does not cross '/'. So "metrics/" still grants everything
// under metrics/, "metrics/*" grants exactly one further path segment, and
// "prod/*/db" matches prod/<env>/db. A malformed glob matches nothing.
//
// A ref containing a "." or ".." path segment (e.g. "myapp/../otherapp") is rejected
// outright before either comparison: connect.RefHasDotSegment — see its doc comment —
// covers the same prefix-boundary gap this per-reference RBAC grant would otherwise
// be vulnerable to, mirroring the guard on prefixAllowed for the coarser allowed_refs
// check.
func refMatches(pattern, ref string) bool {
	if connect.RefHasDotSegment(ref) {
		return false
	}
	if !strings.ContainsAny(pattern, "*?[") {
		if pattern == "" {
			return true // empty pattern = connector-wide grant
		}
		return connect.RefWithinPrefix(pattern, ref)
	}
	ok, err := path.Match(pattern, ref)
	return err == nil && ok
}

// actorRoleIDs resolves the caller's EFFECTIVE role IDs the same way canonical
// authorization does, so the per-reference policy matches the rest of RBAC: machine
// identities resolve from machine_identity_roles; users resolve their direct roles
// PLUS group-derived roles (scopedRoleIDs). Resolving only direct roles would deny a
// user whose granted role comes via a group even though connect.read itself honors it.
//
// CONN-005: roles are resolved at global scope AND at every project scope the actor
// holds a grant in, so a user with only project-scoped role grants can match a
// ConnectRefGrant that references one of those roles. Connect ref grants reference a
// role by ID — if a user has that role at any scope, they should be permitted.
//
// G33: the machine branch below originally queried ONLY the global scope
// (GetMachineRoleIDsAt(ctx, principalID, Scope{})), unlike the user branch's
// project-scope sweep just below it — a machine identity holding a
// ConnectRefGrant-referenced role ONLY at a project scope was silently denied
// even though the equivalent human user was correctly permitted.
//
// The fix uses GetMachineRoles (any-scope, flattened — the same primitive
// ValidateMachineToken/IssueMachineToken already resolve a machine's role NAMES
// from) rather than replicating the user branch's enumerate-scopes-then-requery
// dance: machine identities have no group-membership concept to union in (the
// reason the user branch needs scopedRoleIDs instead of a flat query in the
// first place), and — per this function's own CONN-005 doc above — a Connect
// ref-grant is already resolved role-ID-at-ANY-scope for humans (it carries no
// project/environment field of its own), so "does the machine hold this role
// ANYWHERE" is the exact semantics needed, not a per-scope breakdown. This also
// keeps actorRoleIDs working against a RemoteStorage-backed downstream Connect
// node (ADR-043): GetMachineRoles is proxied over HTTP (unlike a per-scope
// enumeration primitive, which — mirroring GetUserRoleScopes's own remote
// status — would need to be a server-internal-only primitive).
func (c *KeyorixCore) actorRoleIDs(ctx context.Context, actorType string, principalID uint) (map[uint]bool, error) {
	set := map[uint]bool{}
	if actorType == ActorTypeMachine {
		roles, err := c.storage.GetMachineRoles(ctx, principalID)
		if err != nil {
			return nil, fmt.Errorf("connect ref-grant: load machine roles: %w", err)
		}
		for _, r := range roles {
			set[r.ID] = true
		}
		return set, nil
	}
	// Global scope first.
	ids, err := c.scopedRoleIDs(ctx, principalID, Scope{})
	if err != nil {
		return nil, fmt.Errorf("connect ref-grant: load actor roles: %w", err)
	}
	for _, id := range ids {
		set[id] = true
	}
	// Also include roles assigned at any project scope — a project-scoped role
	// assignment for a role that appears in a ConnectRefGrant should be honoured.
	scopes, err := c.storage.GetUserRoleScopes(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("connect ref-grant: enumerate role scopes: %w", err)
	}
	for _, sc := range scopes {
		if sc.ProjectID == 0 {
			continue // already covered by global query above
		}
		projectIDs, err := c.scopedRoleIDs(ctx, principalID, sc)
		if err != nil {
			return nil, fmt.Errorf("connect ref-grant: load actor roles at scope %v: %w", sc, err)
		}
		for _, id := range projectIDs {
			set[id] = true
		}
	}
	return set, nil
}
