package livereplay

import "slices"

import "strings"

// Verdict is what the in-test authorization model says an actor may do with a
// request.
type Verdict int

const (
	// Unknown: the model has no opinion (self-service route, least-privilege
	// listing, admin-tier read for a role whose permissions are not modelled).
	// Unknown requests are never status-judged; only the leak and effect
	// oracles apply.
	Unknown Verdict = iota
	// Deny: the request must be refused (401/403/404 style) and must not
	// change state or leak data.
	Deny
	// Allow: the request is within the actor's authority. A refusal is a
	// MODEL/availability divergence (informational), never a security finding.
	Allow
)

func (v Verdict) String() string {
	switch v {
	case Deny:
		return "deny"
	case Allow:
		return "allow"
	}
	return "unknown"
}

// Actor is one credential the replay speaks with.
type Actor struct {
	Name string
	// Token is the bearer value; "" sends no Authorization header.
	Token string
	// Tenant is the project tenant the actor belongs to ("A", "B") or "" for
	// none.
	Tenant string
	// Role is the actor's authority inside its tenant: "admin" (project_admin),
	// "viewer" (project_viewer, secrets.read + users.read), or "" for none.
	Role string
	// DenyAll marks a credential that must be refused everywhere: absent,
	// garbage, tampered, logged-out/revoked or expired.
	DenyAll bool
	// Machine marks a machine-identity token.
	Machine bool
}

// knownPublic lists the operations that answer without a session by design.
// Anything else answering an unauthenticated request is a candidate finding.
func knownPublic(op Op) bool {
	if !strings.HasPrefix(op.Path, "/api/v1/") {
		return true // /auth/*, /system/init, /health, /metrics, /openapi.yaml: separate perimeter
	}
	switch op.Path {
	case "/api/v1/version":
		return true
	}
	return false
}

// adminTierSegments are path segments whose reads need more than
// project_viewer's secrets.read + users.read; the model does not judge a
// viewer's GET on them.
var adminTierSegments = []string{
	"access-review", "break-glass", "memberships", "members", "invitations",
	"machine-identities", "audit", "roles", "groups", "access-requests",
	"user-roles", "admin", "hygiene", "access-log", "access", "acl", "shares",
}

func isAdminTier(path string) bool {
	for s := range strings.SplitSeq(strings.Trim(path, "/"), "/") {
		if slices.Contains(adminTierSegments, s) {
			return true
		}
	}
	return false
}

// globalMutation reports mutating operations with no object id that act on
// install-wide state (users, roles, settings, admin jobs). A project-scoped
// actor is not expected to perform them; project_admin is left Unknown
// because the FIX-1 ceiling rules let it do some of them inside its scope.
func globalMutation(op Op) bool {
	if op.Method == "GET" {
		return false
	}
	p := op.Path
	return strings.HasPrefix(p, "/api/v1/admin/") ||
		strings.HasPrefix(p, "/api/v1/system/") ||
		p == "/api/v1/users" || p == "/api/v1/roles" ||
		strings.HasPrefix(p, "/api/v1/retention") ||
		strings.HasPrefix(p, "/api/v1/audit/")
}

// Expect is the in-test authorization model (compare internal/core/authz.go and
// the role table in internal/core/auth_bootstrap.go: project_admin bypasses
// per-permission checks inside its project; project_viewer holds
// secrets.read and users.read). objTenant is the tenant that owns the object
// ids carried by the request: "A", "B", or "" when the request carries none.
func Expect(a *Actor, op Op, objTenant string) Verdict {
	if a.DenyAll {
		if knownPublic(op) {
			return Unknown
		}
		return Deny
	}
	if knownPublic(op) {
		return Unknown
	}
	if selfService(op) {
		return Unknown
	}
	if objTenant == "" {
		// No object ids: self-service, or an install-wide route.
		if globalMutation(op) {
			if a.Role == "" || a.Role == "viewer" {
				return Deny
			}
		}
		return Unknown
	}
	if a.Tenant != objTenant || a.Role == "" {
		return Deny
	}
	switch a.Role {
	case "admin":
		return Allow
	case "viewer":
		if op.Method != "GET" {
			if readLikePOST(op) {
				return Unknown
			}
			return Deny
		}
		if isAdminTier(op.Path) {
			return Unknown
		}
		return Allow
	}
	return Unknown
}

// readLikePOST are POST routes that read or compute without storing; whether a
// viewer may call them is a product decision the model does not make.
func readLikePOST(op Op) bool {
	for _, s := range []string{"/render", "/simulate", "/search", "/preview", "/dry-run", "/validate"} {
		if strings.HasSuffix(op.Path, s) {
			return true
		}
	}
	return false
}

// selfService lists routes any signed-in user may call about themselves: asking
// for access to a secret and removing oneself from a share. A project viewer
// succeeding there is the feature, not a hole; the model has no opinion and
// only the leak and effect oracles apply.
func selfService(op Op) bool {
	return (op.Method == "POST" && op.Path == "/api/v1/secret-access-requests") ||
		(op.Method == "DELETE" && strings.HasSuffix(op.Path, "/self-share"))
}

// authorityChanging reports operations that change who may do what (role
// bindings, memberships, group members). Their positive control is a legitimate
// run by the project admin that really succeeds, so it moves other actors'
// authority (the model's table) under the replay. The control is skipped for
// them: a harness that changes the world must not keep judging with the old
// table.
func authorityChanging(op Op) bool {
	if op.Method == "GET" {
		return false
	}
	for s := range strings.SplitSeq(strings.Trim(op.Path, "/"), "/") {
		switch s {
		case "roles", "user-roles", "members", "memberships", "invitations", "groups":
			return true
		}
	}
	return false
}
