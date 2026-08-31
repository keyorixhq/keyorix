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
// distinguished by Success and by the description's reason= token — see
// ConnectOwnershipReason and the deny-path reason constants below).
const EventConnectSecretRead = "connect.secret_read"

// connectEffectiveNow returns a wall-clock reading that never regresses
// relative to what this KeyorixCore has already observed for Connect
// ref-grant resolution (#1653, follow-up to #1632): max(now,
// connectClockWatermark). connectRefAllowed/connectRefGrantDelegates/
// connectorHasAnyDelegationForActor are reached on every federated read —
// see rbacEffectiveNow's doc comment (internal/storage/store/local_rbac.go)
// for why this clamps rather than refuses.
func (c *KeyorixCore) connectEffectiveNow() time.Time {
	c.connectClockWatermarkMu.Lock()
	defer c.connectClockWatermarkMu.Unlock()
	now := c.now()
	if now.Before(c.connectClockWatermark) {
		return c.connectClockWatermark
	}
	c.connectClockWatermark = now
	return now
}

// Per-reference grant management events (ADR-045).
const (
	EventConnectRefGrantCreate = "connect.ref_grant_create"
	EventConnectRefGrantDelete = "connect.ref_grant_delete"
)

// EventConnectorProjectBindingCreate is audited on every persisted
// ConnectorProjectBinding write (ADR-082 branch 3, issue #1477's audit half) —
// the boot-time first-resolution write (server/main.go's
// resolveConnectorOwnership). Used to also be audited from a second door, the
// RemoteStorage proxy write (CreateConnectorProjectBindingProxy); that route
// was removed (#1480) — no server process can be configured with
// storage.type: remote (ADR-083), so it was never reachable in that topology.
// The binding is an authorization input (it feeds connectOwnershipSatisfied),
// which is why the event type stays even with a single call site now.
const EventConnectorProjectBindingCreate = "connect.project_binding_create" // #nosec G101 -- audit event type, not a credential

// ConnectOwnershipReason and the deny-path reason values below form ONE closed
// set (ADR-082 §E) that appears as a "reason=<value>" token at a fixed position
// in every ReadFederatedSecret audit Description — allow and deny outcomes
// alike. There is no structured column for this (AuditEvent has none, and
// ADR-075's "closed key_source enum" describing one was never actually
// implemented — see backlog issue filed alongside this branch), so the fixed
// token format is what keeps this parseable, and what makes a future
// structured column a parse-and-backfill rather than a rewrite.
type ConnectOwnershipReason string

const (
	// ConnectOwnershipReasonProjectMembership: caller holds a role scoped to
	// the connector's owning project specifically.
	ConnectOwnershipReasonProjectMembership ConnectOwnershipReason = "project_membership"
	// ConnectOwnershipReasonGlobalScope: caller holds a role at the true
	// global ({0,0}) scope, which wildcards every project-scoped connector.
	ConnectOwnershipReasonGlobalScope ConnectOwnershipReason = "global_scope"
	// ConnectOwnershipReasonPlatformScope: the connector itself is
	// platform-scoped (ADR-082 §B) — ownership passes for any connect.read
	// holder, independent of the caller's role scopes (TODO ADR-082 branch 4:
	// connect.platform.use narrows this).
	ConnectOwnershipReasonPlatformScope ConnectOwnershipReason = "platform_scope"
)

// Deny-path reason values (ADR-082 §E), same closed set / same token
// convention as ConnectOwnershipReason above, kept as plain strings rather
// than folded into ConnectOwnershipReason since they describe a DENIAL, not an
// ownership outcome connectOwnershipSatisfied itself produces.
const (
	connectDenyReasonDisabled         = "connect_disabled"
	connectDenyReasonUnknownConnector = "unknown_connector"
	connectDenyReasonRefNotPermitted  = "ref_not_permitted"
	// connectDenyReasonOwnershipDenied: caller is not owned AND the connector
	// has no ConnectRefGrant at all — no delegation path exists.
	connectDenyReasonOwnershipDenied = "ownership_denied"
	// connectDenyReasonDelegationDenied: caller is not owned; the connector
	// DOES have ConnectRefGrant(s), but none matched this caller's roles/ref.
	// Distinguishing this from connectDenyReasonOwnershipDenied is the reason
	// this audit event exists at all (ADR-082): the HTTP/gRPC response is the
	// same opaque unknown-connector shape either way, so the audit trail is
	// the only place an operator can learn which gate closed.
	connectDenyReasonDelegationDenied = "delegation_denied"
	// connectDenyReasonPlatformPermissionDenied: connector is scope: platform,
	// but the caller lacks connect.platform.use (ADR-082 branch 4). Deliberately
	// terminal — does NOT fall through to ConnectRefGrant delegation the way a
	// project-scope ownership miss does. See connectOwnershipSatisfied's
	// platform branch and ADR-082 §H: ConnectRefGrant is keyed on role +
	// connector name + ref-prefix alone, with no scope awareness, so treating it
	// as a fallback here would let anyone able to create a grant against a
	// platform connector's name bypass connect.platform.use for anyone else —
	// that would be a bypass, not a narrowing. This fork is deliberate; do not
	// "reconcile" it toward the project-scope delegation path later.
	connectDenyReasonPlatformPermissionDenied = "platform_permission_denied"
	connectDenyReasonBackendError             = "backend_error"
	// connectAllowReasonDelegation: caller is not owned, but an explicit
	// ConnectRefGrant covering their role and this ref allows the read
	// (ADR-082 §F).
	connectAllowReasonDelegation = "delegation"
)

// connectAuditProjectID returns the connector's owning project for the audit
// trail, or nil when the connector is platform-scoped (ADR-082: ProjectID is
// meaningless there — see ConnectOwnership's own doc comment) or has no
// ownership entry at all (e.g. an unknown connector, audited before any
// ownership lookup is possible).
func connectAuditProjectID(owner ConnectOwnership) *uint {
	if owner.Scope != "project" || owner.ProjectID == 0 {
		return nil
	}
	p := owner.ProjectID
	return &p
}

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
		owned, _, err := c.connectOwnershipSatisfied(ctx, actorType, principalID, name)
		if err != nil {
			return nil, err
		}
		if owned {
			readable = append(readable, name)
			continue
		}
		if c.connectOwnership[name].Scope == "platform" {
			// ADR-082 branch 4: a platform-scope caller who lacks connect.platform.use
			// is a TERMINAL deny in ReadFederatedSecret — it never attempts
			// ConnectRefGrant delegation for platform scope (see
			// connectDenyReasonPlatformPermissionDenied's doc comment for why a
			// delegation fallback there would be a bypass). Discovery must agree: the
			// delegation-fallback branch below exists for project-scope connectors,
			// where it's true that ReadFederatedSecret would also honor it — reaching
			// it for a platform connector here would show a connector in ListConnectors
			// that an actual read will always deny, the exact leak ADR-082 §E exists to
			// prevent. (A ConnectRefGrant CAN currently be created against a platform
			// connector's name regardless — that's dead configuration, not a live
			// delegation path; see the issue filed alongside this branch.)
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
// The second return value names WHICH check satisfied ownership (meaningless
// when the first return is false) — ADR-082 branch 3 needs this for the audit
// trail's three-way allow reason. It is a named type, not a string, precisely
// so the string formatting stays at the audit call site (ReadFederatedSecret),
// not here: this function reports a fact, not a description.
func (c *KeyorixCore) connectOwnershipSatisfied(ctx context.Context, actorType string, principalID uint, connectorName string) (bool, ConnectOwnershipReason, error) {
	owner, ok := c.connectOwnership[connectorName]
	if !ok {
		return false, "", nil
	}
	if owner.Scope == "platform" {
		// ADR-082 branch 4: platform connectors need connect.platform.use, not just
		// connect.read (which the transport layer already enforced before this
		// function was ever called, and which still gates the whole Connect surface
		// — connect.read alone was only ever a fail-open interim for platform scope
		// specifically, through branch 3). Checked at Scope{} (global), matching
		// connect.read's own scope — a platform connector has no owning project to
		// check against. A denial here is terminal, not a fall-through to
		// ConnectRefGrant delegation — see connectDenyReasonPlatformPermissionDenied
		// and ADR-082 §H for why.
		allowed, err := c.AuthorizePrincipal(ctx, actorType, principalID, "connect.platform.use", Scope{})
		if err != nil {
			return false, "", fmt.Errorf("connect ownership: check connect.platform.use: %w", err)
		}
		if !allowed {
			return false, "", nil
		}
		return true, ConnectOwnershipReasonPlatformScope, nil
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
		return false, "", fmt.Errorf("connect ownership: enumerate role scopes: %w", err)
	}
	for _, sc := range scopes {
		if sc.ProjectID == owner.ProjectID {
			return true, ConnectOwnershipReasonProjectMembership, nil
		}
		if sc.ProjectID == 0 {
			return true, ConnectOwnershipReasonGlobalScope, nil
		}
	}
	return false, "", nil
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
	ctx = WithActorType(ctx, actorType)
	uid := principalID

	if c.connectManager == nil {
		c.writeAuditEventFailed(ctx, EventConnectSecretRead, &uid, nil, "",
			fmt.Sprintf("federated read DENIED: connect is disabled ref %q reason=%s", ref, connectDenyReasonDisabled))
		return "", ErrConnectDisabled
	}
	conn, ok := c.connectManager.Get(connectorName)
	if !ok {
		c.writeAuditEventFailed(ctx, EventConnectSecretRead, &uid, nil, "",
			fmt.Sprintf("federated read DENIED: unknown connector %q ref %q reason=%s", connectorName, ref, connectDenyReasonUnknownConnector))
		return "", fmt.Errorf("%w %q", ErrConnectUnknownConnector, connectorName)
	}
	// Every outcome below (allow or deny) is for a KNOWN connector, so its owning
	// project (nil for platform scope) is the audit ProjectID throughout —
	// resolved once here rather than per-branch. This is a direct map read on the
	// SAME connectOwnership data connectOwnershipSatisfied consults below, not a
	// second authorization decision.
	owner := c.connectOwnership[connectorName]
	projectID := connectAuditProjectID(owner)

	// ADR-082 §E authorization order: connect.read (enforced by the transport layer
	// before this function is ever called) → ownership → ConnectRefGrant delegation
	// → deny. Every branch below is now audited (ADR-082 branch 3) — the deny
	// branches were deliberately unaudited through branch 2; that gap is what this
	// branch closes.
	owned, ownReason, err := c.connectOwnershipSatisfied(ctx, actorType, principalID, connectorName)
	if err != nil {
		return "", err
	}
	var allowReason ConnectOwnershipReason
	switch {
	case owned:
		allowReason = ownReason
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
			c.writeAuditEventFailed(ctx, EventConnectSecretRead, &uid, projectID, "",
				fmt.Sprintf("federated read DENIED by per-reference policy: connector %q (%s) ref %q reason=%s", connectorName, conn.Type(), ref, connectDenyReasonRefNotPermitted))
			return "", fmt.Errorf("ref %q %w %q", ref, ErrConnectRefNotPermitted, connectorName)
		}
	case owner.Scope == "platform":
		// ADR-082 branch 4: caller lacks connect.platform.use. TERMINAL — no
		// ConnectRefGrant delegation attempt, deliberately (see
		// connectDenyReasonPlatformPermissionDenied's doc comment). This is its own
		// case, not folded into the not-owned/delegation branch below, precisely so
		// it never reaches connectRefGrantDelegates.
		c.writeAuditEventFailed(ctx, EventConnectSecretRead, &uid, projectID, "",
			fmt.Sprintf("federated read DENIED: connector %q (%s) ref %q reason=%s", connectorName, conn.Type(), ref, connectDenyReasonPlatformPermissionDenied))
		return "", fmt.Errorf("%w %q", ErrConnectUnknownConnector, connectorName)
	default:
		// Not owned, project scope (or a connector absent from the ownership map
		// entirely — the structural-invariant edge case, unchanged from before this
		// branch) — ConnectRefGrant is the explicit cross-project delegation path
		// (ADR-082 §F). connectRefGrantDelegates (unlike connectRefAllowed) treats
		// "no grants configured" as "no delegation," not "allow": that shortcut only
		// makes sense for an already-owned caller.
		delegated, hasGrants, err := c.connectRefGrantDelegates(ctx, actorType, principalID, connectorName, ref)
		if err != nil {
			return "", err
		}
		if !delegated {
			// Ownership denied and no delegation grant: reuse the unknown-connector
			// shape in the RETURNED ERROR (ADR-082) — do not confirm this connector's
			// existence to a caller who cannot reach it. The audit event is the only
			// place the real reason is recorded; it distinguishes "no grants at all"
			// from "grants exist, none matched" (the two denial reasons ADR-082
			// branch 3 requires), which the opaque response deliberately does not.
			reason := connectDenyReasonOwnershipDenied
			if hasGrants {
				reason = connectDenyReasonDelegationDenied
			}
			c.writeAuditEventFailed(ctx, EventConnectSecretRead, &uid, projectID, "",
				fmt.Sprintf("federated read DENIED: connector %q (%s) ref %q reason=%s", connectorName, conn.Type(), ref, reason))
			return "", fmt.Errorf("%w %q", ErrConnectUnknownConnector, connectorName)
		}
		allowReason = connectAllowReasonDelegation
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
		c.writeAuditEventFailed(ctx, EventConnectSecretRead, &uid, projectID, "",
			fmt.Sprintf("federated read FAILED via connector %q (%s) ref %q: an internal error occurred; see server logs reason=%s", connectorName, conn.Type(), ref, connectDenyReasonBackendError))
		return "", err
	}
	c.writeAuditEventFull(ctx, EventConnectSecretRead, &uid, nil, projectID, "",
		fmt.Sprintf("federated read via connector %q (%s) ref %q reason=%s", connectorName, conn.Type(), ref, allowReason))
	return value, nil
}

// ListConnectRefGrants returns every per-reference grant (ADR-045), for management.
func (c *KeyorixCore) ListConnectRefGrants(ctx context.Context) ([]*models.ConnectRefGrant, error) {
	return c.storage.ListConnectRefGrants(ctx)
}

// CreateConnectRefGrant adds a per-reference grant (ADR-045): role roleID may read any
// ref under refPrefix ("" = all) on connectorName. The connector must be configured —
// scoping a non-existent (typo'd) connector is rejected so an operator can't believe
// they restricted a connector that is in fact still unscoped. A platform-scoped
// connector is also rejected (#1479): its ownership check is a terminal deny in
// ReadFederatedSecret, so a grant against it would never be consulted — see
// ErrConnectRefGrantAgainstPlatformConnector's own doc comment. expiresAt makes the
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
	if c.connectOwnership[connectorName].Scope == "platform" {
		return nil, fmt.Errorf("%w %q", ErrConnectRefGrantAgainstPlatformConnector, connectorName)
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
	c.writeAuditEventFull(ctx, EventConnectRefGrantCreate, &uid, nil, connectAuditProjectID(c.connectOwnership[connectorName]), "",
		fmt.Sprintf("connect ref-grant: role %d may read ref-prefix %q on connector %q", roleID, refPrefix, connectorName))
	return g, nil
}

// DeleteConnectRefGrant removes a per-reference grant by id. Audited.
func (c *KeyorixCore) DeleteConnectRefGrant(ctx context.Context, actorID, id uint) error {
	// Best-effort lookup of the grant's connector (for the audit ProjectID) BEFORE
	// deleting — the storage interface has no fetch-by-id or delete-returning-row
	// primitive, and adding one is out of scope here (ADR-082 branch 3 must not
	// change ConnectRefGrant's own storage shape). If this lookup fails or finds
	// nothing, the event is still written, just without a ProjectID.
	var projectID *uint
	if grants, gerr := c.storage.ListConnectRefGrants(ctx); gerr == nil {
		for _, g := range grants {
			if g.ID == id {
				projectID = connectAuditProjectID(c.connectOwnership[g.Connector])
				break
			}
		}
	}
	if err := c.storage.DeleteConnectRefGrant(ctx, id); err != nil {
		return err
	}
	uid := actorID
	c.writeAuditEventFull(ctx, EventConnectRefGrantDelete, &uid, nil, projectID, "",
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
	now := c.connectEffectiveNow()
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
// The second return value reports whether the connector had ANY ConnectRefGrant
// configured at all (regardless of whether one matched) — ADR-082 branch 3
// needs this to distinguish the audit trail's two deny reasons
// (connectDenyReasonOwnershipDenied vs connectDenyReasonDelegationDenied),
// which a bare "delegated bool" cannot.
func (c *KeyorixCore) connectRefGrantDelegates(ctx context.Context, actorType string, principalID uint, connectorName, ref string) (bool, bool, error) {
	grants, err := c.storage.ListConnectRefGrantsByConnector(ctx, connectorName)
	if err != nil {
		return false, false, fmt.Errorf("connect ref-grant lookup: %w", err)
	}
	if len(grants) == 0 {
		return false, false, nil // no delegation grant configured — no delegation path
	}
	roleSet, err := c.actorRoleIDs(ctx, actorType, principalID)
	if err != nil {
		return false, true, err
	}
	now := c.connectEffectiveNow()
	for _, g := range grants {
		if roleSet[g.RoleID] && connectGrantActive(g, now) && refMatches(g.RefPrefix, ref) {
			return true, true, nil
		}
	}
	return false, true, nil
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
	now := c.connectEffectiveNow()
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
