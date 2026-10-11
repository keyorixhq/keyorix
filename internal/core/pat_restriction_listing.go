// pat_restriction_listing.go — applying a PAT restriction (ADR-042) to reads whose
// visibility is decided OUTSIDE Authorize/AuthorizeSecret.
//
// The restriction is enforced at the authorization chokepoint, so a read gated by
// Authorize at a scope that covers every row it returns honours it for free. A read
// that decides visibility itself — "what this user personally owns, was shared or
// was granted", "this user's notifications" — never reaches that chokepoint for the
// rows it returns, and so ignored the restriction entirely: an environment-confined
// or users.read-only token listed the owner's secrets in every project, and every
// restricted token read notifications naming secrets in other projects (PAT-GUARD-1;
// the same class as #3018's GET /shares/owned).
//
// Each filter here keeps a row only if the restriction would let the token read it
// at the row's OWN scope — the exact check AuthorizeSecret makes before it honours
// an ACL grant (PAT-SCOPE-002). A nil restriction (session, machine, unrestricted
// PAT) keeps everything, so these are no-ops for every caller but a restricted PAT.
//
// The family-wide guard is server/http/pat_restriction_read_family_test.go's
// TestEveryGETRouteHonoursPATRestriction (and its gRPC twin): it calls every GET
// route with restricted tokens against a canary project and fails on any response
// that discloses it.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrRestrictedPATCannotMintPAT refuses a PAT-creation request authenticated by a
// restricted PAT. A child token is created unrestricted unless the request asks
// otherwise, so allowing it would let a leaked confined token mint the owner's full
// authority — the one outcome ADR-042's restriction exists to prevent.
var ErrRestrictedPATCannotMintPAT = errors.New("a restricted personal access token cannot create personal access tokens")

// patAllowsSecretRead reports whether the request's PAT restriction permits
// secrets.read on secret at the secret's own project/environment.
func patAllowsSecretRead(ctx context.Context, secret *models.SecretNode) bool {
	r := patRestrictionFromContext(ctx)
	if r == nil {
		return true
	}
	if secret == nil {
		return false
	}
	return r.Allows(permSecretsRead, Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID})
}

// filterSecretsByPATRestriction drops every secret the request's PAT restriction
// does not let it read. It returns in unchanged when there is no restriction.
func filterSecretsByPATRestriction(ctx context.Context, in []*models.SecretWithSharingInfo) []*models.SecretWithSharingInfo {
	if patRestrictionFromContext(ctx) == nil {
		return in
	}
	out := make([]*models.SecretWithSharingInfo, 0, len(in))
	for _, s := range in {
		if s != nil && patAllowsSecretRead(ctx, s.SecretNode) {
			out = append(out, s)
		}
	}
	return out
}

// patAllowsNotification reports whether the request's PAT restriction lets it see
// n. A notification names the resource it is about (a secret, an access request, a
// break-glass activation), so it is treated as a read of its project's secrets:
// secrets.read at the notification's project scope.
//
// A notification with no project is refused to every restricted token. Several of
// them still name project resources (read-quota alerts name the secret), and
// nothing on the row says which project, so there is no scope to check them
// against. Fail closed: the restricted token sees fewer notifications, never ones
// from outside its restriction.
func patAllowsNotification(ctx context.Context, n *models.Notification) bool {
	r := patRestrictionFromContext(ctx)
	if r == nil {
		return true
	}
	if n == nil || n.ProjectID == nil {
		return false
	}
	return r.Allows(permSecretsRead, Scope{ProjectID: *n.ProjectID})
}

// requireAccessRequestAuthorityAt is requireAdminAuthorityAt for the secret
// access-request family (list pending, get, approve, reject). Those routes carry no
// permission gate — the admin-authority check IS their authorization — and
// requireAdminAuthorityAt resolves roles directly, never through Authorize, so a
// project-confined admin token could see and resolve requests in every project.
// The restriction is checked as roles.assign at the request's project: approving a
// secret access request is the same decision as resolving a project access request,
// which the router gates on roles.assign.
func (c *KeyorixCore) requireAccessRequestAuthorityAt(ctx context.Context, actorID, projectID uint) error {
	if !patRestrictionFromContext(ctx).Allows(permRolesAssign, Scope{ProjectID: projectID}) {
		return fmt.Errorf("admin authority is required")
	}
	return c.requireAdminAuthorityAt(ctx, actorID, projectID)
}

// patAllowsOwnAccessRequest reports whether a restricted PAT may see one of its
// owner's own secret access requests: secrets.read at the request's project, since
// the request is about reading a secret there.
func patAllowsOwnAccessRequest(ctx context.Context, req *models.AccessRequest) bool {
	return patRestrictionFromContext(ctx).Allows(permSecretsRead, Scope{ProjectID: req.ProjectID})
}
