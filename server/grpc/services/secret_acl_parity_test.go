// secret_acl_parity_test.go — GRPC track backlog step 6's "gRPC denies what
// REST allows" shape (the reverse of the security-relevant direction, so no
// FINDINGS-inbox entry -- gRPC failing closed is not an escalation -- but a
// real functional-parity bug: an ACL-only-granted caller simply could not
// use the gRPC API for a secret they can reach over REST).
//
// REST's per-secret routes (server/http/router.go, RequireScopedSecretPermission)
// consult per-secret SecretACL grants (RBAC Phase 3) via core.AuthorizeSecretPrincipal
// in addition to project-wide roles. Every gRPC SecretService RPC (and
// ShareService's ShareSecret/ListSecretShares) routed through the shared
// authorizeSecretScoped helper, which called the plain, role-only
// AuthorizePrincipal -- never consulting SecretACL. A caller whose role(s)
// grant NO permission on this secret, relying entirely on a per-secret ACL
// grant, could therefore reach the secret over REST but was denied the
// identical action over gRPC.
package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// TestSecretService_GetSecret_ACLOnlyGrant_MatchesRESTParity proves a caller
// whose project role grants nothing on this secret, but who holds a per-secret
// SecretACL grant, can GetSecret over gRPC -- exactly as
// RequireScopedSecretPermission already lets them do over REST.
func TestSecretService_GetSecret_ACLOnlyGrant_MatchesRESTParity(t *testing.T) {
	r := newSecretTestRig(t)
	ownerCtx := authCtx(1, "owner", "secrets.write", "secrets.read")
	sec := r.createSecret(t, ownerCtx, "acl-only-secret", "s3cr3t")

	const aclOnlyUserID = 5
	require.NoError(t, r.db.Create(&models.User{ID: aclOnlyUserID, Username: "acl-user", Email: "acl-user@example.com"}).Error)
	// aclGrantsPermission requires the grantee to still be a "live member" of the
	// grant's project (#G13, internal/core/secret_acl.go) -- IsProjectMember only
	// checks for ANY project-scoped UserRole row, not what it grants, so a
	// placeholder role with no permissions (RoleID 999, unused elsewhere) is
	// enough to represent "this user is a project member via some other route"
	// without itself conferring secrets.read (matching internal/core/secret_acl_test.go's
	// newACLCore fixture exactly). The SecretACL row below is what actually grants
	// secrets.read on this ONE secret.
	require.NoError(t, r.db.Create(&models.UserRole{UserID: aclOnlyUserID, RoleID: 999, ProjectID: 1}).Error)
	require.NoError(t, r.db.Create(&models.SecretACL{
		SecretID: uint(sec.GetId()), UserID: aclOnlyUserID, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}).Error)

	// authCtx's fake Permissions list is ignored by the real
	// authorizeSecretScoped/AuthorizePrincipal gate, so this context carries no
	// ambient permission of its own -- only the ACL grant above authorizes it.
	aclCtx := authCtx(aclOnlyUserID, "acl-user")

	got, err := r.svc.GetSecret(aclCtx, &pb.GetSecretRequest{Id: sec.GetId()})
	require.NoError(t, err, "an ACL-only grant must authorize GetSecret over gRPC, matching REST's RequireScopedSecretPermission")
	assert.Equal(t, sec.GetId(), got.GetId())
}

// TestSecretService_GetSecret_NoGrantAtAll_StillDenied is the negative
// control: a user with neither a role NOR an ACL grant must still be denied
// -- the fix adds ACL as an alternative path to authorization, not a bypass.
func TestSecretService_GetSecret_NoGrantAtAll_StillDenied(t *testing.T) {
	r := newSecretTestRig(t)
	ownerCtx := authCtx(1, "owner", "secrets.write", "secrets.read")
	sec := r.createSecret(t, ownerCtx, "no-grant-secret", "s3cr3t")

	const strangerID = 6
	require.NoError(t, r.db.Create(&models.User{ID: strangerID, Username: "stranger", Email: "stranger@example.com"}).Error)
	strangerCtx := authCtx(strangerID, "stranger")

	_, err := r.svc.GetSecret(strangerCtx, &pb.GetSecretRequest{Id: sec.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
