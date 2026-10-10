// share_authz_rpc_guard_test.go — #2941 guard, gRPC half: every SecretService RPC that
// acts on one existing secret must be authorized by authorizeSecretScoped, and
// authorizeSecretScoped must decide with core.AuthorizeSecretPrincipalForSecret (role +
// per-secret ACL + the share term) — never the role-only AuthorizePrincipal, which is
// what it used, so a share-elevated member was allowed on HTTP and denied on gRPC.
//
// The RPC list is derived from the generated service descriptor
// (pb.SecretService_ServiceDesc), not hand-listed: a new RPC is checked the moment it
// is generated. Each must call authorizeSecretScoped in its method body or be listed
// in secretRPCShareGuardExempt with a reason. The share-management RPCs that take a
// secret ID (ShareService.ShareSecret, ListSecretShares) are held to the same rule.
//
// What it does NOT cover: RPCs whose authorization is delegated to a helper other than
// authorizeSecretScoped would have to be added here explicitly (none exist today).
// The behavioural proof is share_elevation_2941_test.go.
package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

var secretRPCShareGuardExempt = map[string]string{
	"CreateSecret": "no secret exists yet: authorized against the project/environment in the request body.",
	"ListSecrets":  "a listing, not one secret: authorized against the list scope; rows are filtered per caller.",
}

func TestEverySecretRPC_UsesShareAwareGate(t *testing.T) {
	bodies := methodBodies(t, "secret_service.go", "SecretGRPCService")
	checked := 0
	for _, m := range pb.SecretService_ServiceDesc.Methods {
		name := m.MethodName
		if _, exempt := secretRPCShareGuardExempt[name]; exempt {
			continue
		}
		body, ok := bodies[name]
		require.True(t, ok, "SecretService RPC %s has no method on SecretGRPCService in secret_service.go", name)
		checked++
		assert.True(t, callsFunc(body, "authorizeSecretScoped"),
			"SecretService.%s acts on one secret but does not call authorizeSecretScoped, so it would ignore "+
				"shares (#2941) and per-secret ACLs. Call it, or add a justified secretRPCShareGuardExempt entry.", name)
	}
	assert.Greater(t, checked, 8, "calibration: expected the per-secret RPC family, checked %d", checked)
	for name := range secretRPCShareGuardExempt {
		found := false
		for _, m := range pb.SecretService_ServiceDesc.Methods {
			found = found || m.MethodName == name
		}
		assert.True(t, found, "stale exemption %q: no such SecretService RPC", name)
	}

	shareBodies := methodBodies(t, "share_service.go", "ShareGRPCService")
	for _, name := range []string{"ShareSecret", "ListSecretShares"} {
		assert.True(t, callsFunc(shareBodies[name], "authorizeSecretScoped"),
			"ShareService.%s takes a secret ID and must authorize with authorizeSecretScoped", name)
	}
}

func TestAuthorizeSecretScoped_CallsShareAwareCheck(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "secret_service.go", nil, 0)
	require.NoError(t, err)
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "authorizeSecretScoped" {
			body = fd.Body
		}
	}
	require.NotNil(t, body, "secret_service.go must declare authorizeSecretScoped")
	assert.True(t, callsFunc(body, "AuthorizeSecretPrincipalForSecret"),
		"authorizeSecretScoped must decide with core.AuthorizeSecretPrincipalForSecret (role + ACL + share term)")
	assert.False(t, callsFunc(body, "AuthorizePrincipal"),
		"authorizeSecretScoped must not make a role-only AuthorizePrincipal decision for a found secret")
}

// methodBodies parses file (in this package directory) and returns recvType's method
// bodies by name.
func methodBodies(t *testing.T, file, recvType string) map[string]*ast.BlockStmt {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	require.NoError(t, err)
	out := map[string]*ast.BlockStmt{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Body == nil {
			continue
		}
		star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if id, ok := star.X.(*ast.Ident); ok && id.Name == recvType {
			out[fd.Name.Name] = fd.Body
		}
	}
	return out
}

// callsFunc reports whether body contains a call to name, either as a bare identifier
// (name(...)) or a selector (x.name(...)).
func callsFunc(body *ast.BlockStmt, name string) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			found = found || fn.Name == name
		case *ast.SelectorExpr:
			found = found || fn.Sel.Name == name
		}
		return !found
	})
	return found
}
