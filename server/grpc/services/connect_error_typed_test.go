package services

// ERRSTRING-CLASS-1 item 2: isSafeConnectError decides whether a connect error's text
// may reach the caller. It matched five phrases inside err.Error(), so an upstream
// connector error (or a storage error) that merely echoed a caller-controlled ref or
// prefix containing one of those phrases was forwarded verbatim. It now matches the
// core sentinels (errors.Is), like the REST twin in server/http/handlers/connect.go.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// echoConnector fails like an upstream store that quotes the requested ref back.
type echoConnector struct{ name string }

func (e echoConnector) Name() string { return e.name }
func (e echoConnector) Type() string { return "fake" }
func (e echoConnector) GetSecret(_ context.Context, ref string) (string, error) {
	return "", errors.New("upstream: cannot read " + ref + " at https://vault.internal:8200/v1/secret/data")
}

func newEchoConnectService(t *testing.T) *ConnectGRPCService {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil)
	h.CoreService.SetConnectManager(connect.NewManager([]connect.Connector{echoConnector{name: "aws"}}))
	h.CoreService.SetConnectOwnership(map[string]core.ConnectOwnership{"aws": {Scope: "platform"}})
	return NewConnectService(h.CoreService)
}

func TestConnectService_ReadSecret_UpstreamErrorEchoingSafePhraseIsSanitized(t *testing.T) {
	svc := newEchoConnectService(t)
	for _, ref := range []string{
		"unknown connector",
		"keyorix connect is not enabled",
		"is not permitted for your roles on connector",
		"a role is required for a connect ref-grant",
		"connector is platform-scoped",
	} {
		t.Run(ref, func(t *testing.T) {
			_, err := svc.ReadSecret(connCtx(), readReq("aws", ref))
			require.Error(t, err)
			assert.Equal(t, codes.Internal, status.Code(err), err.Error())
			assert.NotContains(t, err.Error(), "vault.internal", "raw upstream text must not reach the caller")
		})
	}
}

func TestConnectService_TypedRefusalsKeepTheirClassAndText(t *testing.T) {
	svc := newConnectService(t)

	_, err := svc.ReadSecret(connCtx(), readReq("nope", "x"))
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
	assert.Contains(t, status.Convert(err).Message(), "unknown connector")

	_, err = svc.CreateRefGrant(authCtx(1, "admin", "roles.write"), &pb.CreateConnectRefGrantRequest{
		RoleId: 1, Connector: "nope", RefPrefix: "p/",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
	assert.Contains(t, status.Convert(err).Message(), "unknown connector")

	_, err = svc.CreateRefGrant(authCtx(1, "admin", "roles.write"), &pb.CreateConnectRefGrantRequest{
		RoleId: 1, Connector: "aws", RefPrefix: "p/",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
	assert.Contains(t, status.Convert(err).Message(), "connector is platform-scoped")
}
