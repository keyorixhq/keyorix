// secret_403_convention_test.go — ADR-096: gRPC RPCs that resolve a scoped
// resource by ID (secret_service.go's authorizeSecretScoped,
// dynamic_secret_service.go's loadConfigScoped/loadLeaseScoped, both backed
// by conversions.go's shared authorizeScopedTarget) must not let a denied
// caller distinguish "doesn't exist" from "exists, you can't touch it" via
// the response code or message — the gRPC analogue of the HTTP
// 403-for-both proof in server/http/dynamic_secrets_403_convention_test.go.
package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// TestGetSecret_403ForBoth_UnprivilegedCallerCannotDistinguish is the core
// property for authorizeSecretScoped: an unprivileged caller gets the SAME
// PermissionDenied, with the SAME message, for a real secret they can't see
// and a secret ID that doesn't exist at all.
func TestGetSecret_403ForBoth_UnprivilegedCallerCannotDistinguish(t *testing.T) {
	r := newSecretTestRig(t)
	owner := authCtx(1, "owner", "secrets.write", "secrets.read")
	sec := r.createSecret(t, owner, "probe-target", "v")

	nobody := authCtx(999, "nobody") // no RBAC role anywhere, not even globally
	_, errReal := r.svc.GetSecret(nobody, &pb.GetSecretRequest{Id: sec.GetId()})
	_, errFake := r.svc.GetSecret(nobody, &pb.GetSecretRequest{Id: sec.GetId() + 999999})

	require.Error(t, errReal)
	require.Error(t, errFake)
	assert.Equal(t, codes.PermissionDenied, status.Code(errReal), "real secret, no access")
	assert.Equal(t, codes.PermissionDenied, status.Code(errFake), "nonexistent secret")
	assert.Equal(t, errReal.Error(), errFake.Error(), "the two cases must be byte-identical, not just same code")
}

// TestGetSecret_403ForBoth_GloballyPrivilegedCallerGetsRealNotFound is the
// narrow exception ADR-096 specifies: a caller who holds secrets.read at
// GLOBAL scope gets a genuine NotFound for an ID that truly doesn't exist —
// distinct from the PermissionDenied an unprivileged caller sees for the
// same nonexistent ID.
func TestGetSecret_403ForBoth_GloballyPrivilegedCallerGetsRealNotFound(t *testing.T) {
	r := newSecretTestRig(t)
	owner := authCtx(1, "owner", "secrets.write", "secrets.read") // global per newSecretTestRig's seed

	_, err := r.svc.GetSecret(owner, &pb.GetSecretRequest{Id: 999999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestGetConfig_403ForBoth_UnprivilegedCallerCannotDistinguish is the same
// property for loadConfigScoped (dynamic_secret_service.go).
func TestGetConfig_403ForBoth_UnprivilegedCallerCannotDistinguish(t *testing.T) {
	svc := newDynamicTestRig(t)
	owner := authCtx(1, "owner")
	cfg, err := svc.CreateConfig(owner, &pb.CreateDynamicConfigRequest{
		Name: "probe-target", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://admin@db/x",
	})
	require.NoError(t, err)

	nobody := authCtx(999, "nobody")
	_, errReal := svc.GetConfig(nobody, &pb.GetDynamicConfigRequest{Id: cfg.GetId()})
	_, errFake := svc.GetConfig(nobody, &pb.GetDynamicConfigRequest{Id: cfg.GetId() + 999999})

	require.Error(t, errReal)
	require.Error(t, errFake)
	assert.Equal(t, codes.PermissionDenied, status.Code(errReal), "real config, no access")
	assert.Equal(t, codes.PermissionDenied, status.Code(errFake), "nonexistent config")
	assert.Equal(t, errReal.Error(), errFake.Error(), "the two cases must be byte-identical, not just same code")
}

// TestGetConfig_403ForBoth_GloballyPrivilegedCallerGetsRealNotFound is the
// narrow exception for loadConfigScoped: a caller holding secrets.read at
// GLOBAL scope gets a genuine NotFound for a config ID that truly doesn't
// exist.
func TestGetConfig_403ForBoth_GloballyPrivilegedCallerGetsRealNotFound(t *testing.T) {
	svc := newDynamicTestRig(t)
	owner := authCtx(1, "owner") // global per newDynamicTestRig's seed

	_, err := svc.GetConfig(owner, &pb.GetDynamicConfigRequest{Id: 999999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
