package services

// PASSWORD-POLICY-FAMILY-1: the gRPC half of the family guard (the HTTP half is
// server/http/handlers/password_policy_family_test.go). A new password that breaks
// the password policy is InvalidArgument with the rule text, never Internal and
// never the blanket "invalid request parameters" GRPC-003 uses for other
// validation failures.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// grpcPasswordPolicyRPCs is every RPC whose request carries a password the server
// stores. The completeness test below fails when a proto RPC with a password-ish
// request field is in neither this map nor grpcPasswordNotNew.
var grpcPasswordPolicyRPCs = map[string]struct{}{
	"/keyorix.v1.UserService/CreateUser": {},
}

// grpcPasswordNotNew lists RPCs whose request has a password-named field that is
// not a new credential, with the reason.
var grpcPasswordNotNew = map[string]string{}

// It sweeps every proto RPC, so it reports through guardrules.Rollout
// (docs/guard-rollout-contract.md rule 2): report-only on pull requests while
// docs/guard-rollout.d/TestGRPCPasswordPolicyRPCsAreAllListed.tsv exists,
// blocking on main.
func TestGRPCPasswordPolicyRPCsAreAllListed(t *testing.T) {
	g := guardrules.Rollout(t)
	var found []string
	services := pb.File_keyorix_proto.Services()
	for i := range services.Len() {
		svc := services.Get(i)
		methods := svc.Methods()
		for j := range methods.Len() {
			m := methods.Get(j)
			if !messageHasPasswordField(m.Input(), 0) {
				continue
			}
			full := "/" + string(svc.FullName()) + "/" + string(m.Name())
			found = append(found, full)
			_, listed := grpcPasswordPolicyRPCs[full]
			_, excused := grpcPasswordNotNew[full]
			assert.True(g, listed || excused,
				"%s takes a password but is not in grpcPasswordPolicyRPCs: add it with a policy-violating case to TestGRPCPasswordPolicyRefusalIsInvalidArgument (or to grpcPasswordNotNew with the reason)", full)
		}
	}
	for full := range grpcPasswordPolicyRPCs {
		assert.Contains(g, found, full, "%s is listed but the proto has no such RPC with a password field", full)
	}
}

func messageHasPasswordField(md protoreflect.MessageDescriptor, depth int) bool {
	fields := md.Fields()
	for i := range fields.Len() {
		f := fields.Get(i)
		switch strings.ToLower(string(f.Name())) {
		case "password", "new_password", "current_password":
			return true
		}
		if f.Message() != nil && depth < 2 && !f.IsMap() && messageHasPasswordField(f.Message(), depth+1) {
			return true
		}
	}
	return false
}

func TestGRPCPasswordPolicyRefusalIsInvalidArgument(t *testing.T) {
	cases := []struct {
		name string
		pw   string
		rule string
	}{
		{"length", "Sh0rt!aB", "at least 16 characters"},
		{"contains_username", "Alicia-Str0ng-Passw0rd!x", "not contain your username, email, or display name"},
		{"common", "Password1!", "not be a commonly-used password"},
	}
	for _, tc := range cases {
		t.Run("CreateUser/"+tc.name, func(t *testing.T) {
			svc := newUserService(t)
			pw := tc.pw
			_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
				Username: "alicia", Email: "alicia@example.com", Password: &pw,
			})
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.InvalidArgument, st.Code(), st.Message())
			assert.Contains(t, st.Message(), tc.rule)
			assert.NotContains(t, strings.ToLower(st.Message()), "internal error")
			assert.NotContains(t, st.Message(), tc.pw, "the response must not echo the candidate")
		})
	}
}
