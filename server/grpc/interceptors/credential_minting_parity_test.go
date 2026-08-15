package interceptors

import (
	"regexp"
	"testing"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

// allServiceDescs lists every gRPC service this server registers (server/grpc/server.go).
// It's a fixed enumeration of SERVICES (rarely added — a new one means a new .proto
// service block), not of individual RPC methods, so this list needs updating far less
// often than credentialMintingMethods itself would if it were hand-maintained per method.
var allServiceDescs = []grpc.ServiceDesc{
	pb.SecretService_ServiceDesc,
	pb.ShareService_ServiceDesc,
	pb.UserService_ServiceDesc,
	pb.RoleService_ServiceDesc,
	pb.AuditService_ServiceDesc,
	pb.SystemService_ServiceDesc,
	pb.BreakGlassService_ServiceDesc,
	pb.GroupService_ServiceDesc,
	pb.ProjectService_ServiceDesc,
	pb.MachineIdentityService_ServiceDesc,
	pb.DynamicSecretService_ServiceDesc,
	pb.ComplianceService_ServiceDesc,
	pb.ConnectService_ServiceDesc,
}

// credentialMintingNamePattern flags an RPC method name that, by naming convention,
// mints a durable credential (a token/secret the caller can use again later, as
// opposed to a read or a bounded action). It is intentionally broader than the
// literal set of methods blocked today — the point of this test is to catch a
// FUTURE method that looks like it mints a credential but was never added to
// credentialMintingMethods, closing the drift risk between this gRPC-side list and
// the HTTP canonical routes (server/http/router.go, BlockWhenImpersonating) that
// the comment on credentialMintingMethods says to "keep in sync" by hand.
var credentialMintingNamePattern = regexp.MustCompile(`(?i)^(Issue|Create|Generate|Mint)\w*Token$`)

// TestCredentialMintingMethods_CoversNamingConvention enforces that
// credentialMintingMethods (the gRPC-side impersonation block-list) stays in sync
// with its own naming convention automatically, instead of relying solely on the
// "keep in sync with HTTP" comment: any RPC across every registered gRPC service
// whose name matches credentialMintingNamePattern MUST already be blocked while
// impersonating. Today the only such method is IssueMachineToken; if a future PR
// adds e.g. CreatePATToken or GenerateServiceAccountToken over gRPC without also
// adding it here, this test fails instead of silently shipping an
// impersonation-escapable credential mint.
func TestCredentialMintingMethods_CoversNamingConvention(t *testing.T) {
	var found []string
	for _, desc := range allServiceDescs {
		for _, m := range desc.Methods {
			if !credentialMintingNamePattern.MatchString(m.MethodName) {
				continue
			}
			full := "/" + desc.ServiceName + "/" + m.MethodName
			found = append(found, full)
			assert.Truef(t, credentialMintingMethods[full],
				"gRPC method %q looks like it mints a durable credential (matches %s) but is missing from credentialMintingMethods — add it so BlockWhenImpersonating parity with HTTP holds",
				full, credentialMintingNamePattern.String())
		}
	}
	// Sanity check the test itself isn't vacuous (the pattern must match at least
	// the one method we know is blocked today).
	assert.Contains(t, found, pb.MachineIdentityService_IssueMachineToken_FullMethodName)
}

// TestCredentialMintingMethods_IncludesActivateBreakGlass is the #G07 direct
// regression: ActivateBreakGlass mints a durable, time-bound role grant
// attributed to whoever the session currently acts as, but its method name
// ("ActivateBreakGlass") doesn't match credentialMintingNamePattern (it
// doesn't end in "Token"), so the naming-convention test above can't catch
// this specific gap — it was missing from credentialMintingMethods despite
// IssueMachineToken (the same class of action) already being blocked.
func TestCredentialMintingMethods_IncludesActivateBreakGlass(t *testing.T) {
	assert.True(t, credentialMintingMethods[pb.BreakGlassService_ActivateBreakGlass_FullMethodName],
		"ActivateBreakGlass mints a durable role grant and must be blocked while impersonating, the same as IssueMachineToken")
}

// TestCredentialMintingMethods_NoUnknownEntries is the converse check: every entry
// in credentialMintingMethods must correspond to an RPC that actually exists across
// the registered services, so a stale/typo'd entry (e.g. after a method rename)
// doesn't silently stop blocking anything while still looking like it's enforced.
func TestCredentialMintingMethods_NoUnknownEntries(t *testing.T) {
	known := map[string]bool{}
	for _, desc := range allServiceDescs {
		for _, m := range desc.Methods {
			known["/"+desc.ServiceName+"/"+m.MethodName] = true
		}
	}
	for method := range credentialMintingMethods {
		assert.Truef(t, known[method], "credentialMintingMethods entry %q does not match any registered gRPC method", method)
	}
}
