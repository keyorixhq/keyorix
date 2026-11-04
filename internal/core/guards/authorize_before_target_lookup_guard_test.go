// authorize_before_target_lookup_guard_test.go — OWNERSHIP-ORACLE-1 item 3.
//
// A core operation that takes a target user ID must authorize the ACTOR before it
// looks the target up: a lookup that runs first answers "user not found" / "email
// domain is not on the allowlist" / "already owned" to a caller with no right to the
// operation, so the refusal says which IDs exist (#3794, and the onboarding paths
// fixed with it). This guard parses the core family sources and fails on a call to
// a target-user lookup that has no authorization call before it in the same
// function.
//
// What it recognises:
//   - target lookups: a call to domainAllowedForUser or domainAllowedForGroupJoin
//     (both load the target user), and a GetUser call whose ID argument is an
//     identifier named newOwnerID, toOwnerID or targetUserID (this package's names
//     for an operation's target user);
//   - authorization: a call to one of authorizeCalls below.
//
// What it does NOT check, by design: whether the authorization call dominates the
// lookup (it compares source positions only, so a check in an earlier sibling
// branch satisfies it); target lookups through any other helper or variable name;
// target STATE checks that are not lookups (a role-set "already holds" compare, an
// owner-ID compare); route gates in the transports. Those were swept by hand in
// OWNERSHIP-ORACLE-1 and AUTHZ-ORACLE-1 (#3815); the sweep tables are in those PRs.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// targetLookupHelpers load the target user.
var targetLookupHelpers = []string{"domainAllowedForUser", "domainAllowedForGroupJoin"}

// targetUserIdents are the argument names that mark a GetUser call as a target lookup.
var targetUserIdents = []string{"newOwnerID", "toOwnerID", "targetUserID"}

// authorizeCalls are the actor authorization checks a target lookup must follow.
var authorizeCalls = []string{
	"requireGranterHoldsRolePermissions",
	"requireGranterHoldsRoleSet",
	"validateGroupJoinRoles",
	"AuthorizePrincipal",
	"Authorize",
}

// targetLookupBeforeAuthorizeAllowlist maps "file.go:FuncName" to why its target
// lookup needs no authorization call of its own. Every key must still exist.
var targetLookupBeforeAuthorizeAllowlist = map[string]string{
	"groups.go:domainAllowedForGroupJoin": "the lookup helper itself: it calls domainAllowedForUser " +
		"for its caller, and its caller (AddUserToGroup) is checked",
	"permission_change_audit.go:resolvePermChangeTarget": "names the target of an already-recorded " +
		"audit row for the permission-change report; no operation on the target, the report's " +
		"own route gate is the authorization",
}

func TestTargetLookupsFollowActorAuthorization(t *testing.T) {
	g := guardrules.Rollout(t)
	fset := token.NewFileSet()
	seen := map[string]bool{}
	var findings []string
	for _, path := range coreFamilySources(g) {
		rel := srcpath.CoreFamilyRel(path)
		src, err := os.ReadFile(path) // #nosec G304 -- core family source file from srcpath.CoreFamilyGoFiles
		if err != nil {
			g.Fatalf("read %s: %v", path, err)
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			g.Fatalf("parse %s: %v", path, err)
		}
		for _, f := range targetLookupsBeforeAuthorize(fset, rel, file) {
			if _, ok := targetLookupBeforeAuthorizeAllowlist[f.key]; ok {
				seen[f.key] = true
				continue
			}
			findings = append(findings, f.String())
		}
	}
	sort.Strings(findings)
	for _, f := range findings {
		g.Errorf("%s: target lookup with no actor authorization before it in the same function; "+
			"authorize the actor first, so a refused caller gets one answer for every target "+
			"(OWNERSHIP-ORACLE-1), or add the function to targetLookupBeforeAuthorizeAllowlist with the reason", f)
	}
	for key := range targetLookupBeforeAuthorizeAllowlist {
		if !seen[key] {
			g.Errorf("allowlist entry %s matches no target lookup any more: delete it", key)
		}
	}
}

type targetLookupFinding struct {
	key  string // file.go:FuncName
	pos  token.Position
	call string
}

func (f targetLookupFinding) String() string {
	return f.key + " (" + f.pos.String() + ", " + f.call + ")"
}

// targetLookupsBeforeAuthorize returns, for each function declaration in file, every
// target lookup with no authorization call at an earlier position in that function
// (function literals inside it included).
func targetLookupsBeforeAuthorize(fset *token.FileSet, rel string, file *ast.File) []targetLookupFinding {
	var out []targetLookupFinding
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		firstAuth := token.NoPos
		type lookup struct {
			pos  token.Pos
			call string
		}
		var lookups []lookup
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := calleeName(call.Fun)
			switch {
			case slices.Contains(authorizeCalls, name):
				if !firstAuth.IsValid() || call.Pos() < firstAuth {
					firstAuth = call.Pos()
				}
			case slices.Contains(targetLookupHelpers, name):
				lookups = append(lookups, lookup{call.Pos(), name})
			case name == "GetUser" && len(call.Args) == 2:
				if id, ok := call.Args[1].(*ast.Ident); ok && slices.Contains(targetUserIdents, id.Name) {
					lookups = append(lookups, lookup{call.Pos(), "GetUser(" + id.Name + ")"})
				}
			}
			return true
		})
		for _, l := range lookups {
			if firstAuth.IsValid() && firstAuth < l.pos {
				continue
			}
			out = append(out, targetLookupFinding{key: rel + ":" + fn.Name.Name, pos: fset.Position(l.pos), call: l.call})
		}
	}
	return out
}

// TestTargetLookupsFollowActorAuthorization_SelfTest runs the detector on known-bad
// and known-good shapes, including the pre-fix shapes of transferOwnership and
// addProjectMember.
func TestTargetLookupsFollowActorAuthorization_SelfTest(t *testing.T) {
	t.Parallel()
	const src = `package core
func (c *KeyorixCore) transferBefore(ctx context.Context, secretID, newOwnerID, actorID uint) error {
	if _, err := c.storage.GetUser(ctx, newOwnerID); err != nil { return err }
	ok, _ := c.AuthorizePrincipal(ctx, "user", actorID, "roles.assign", Scope{})
	_ = ok
	return nil
}
func (c *KeyorixCore) transferAfter(ctx context.Context, secretID, newOwnerID, actorID uint) error {
	ok, _ := c.AuthorizePrincipal(ctx, "user", actorID, "roles.assign", Scope{})
	_ = ok
	_, err := c.storage.GetUser(ctx, newOwnerID)
	return err
}
func (c *KeyorixCore) addMemberBefore(ctx context.Context, actorID, userID, roleID uint) error {
	if err := c.domainAllowedForUser(ctx, userID); err != nil { return err }
	return c.requireGranterHoldsRolePermissions(ctx, actorID, roleID, Scope{}, false)
}
func (c *KeyorixCore) addMemberAfter(ctx context.Context, actorID, userID, roleID uint) error {
	if err := c.requireGranterHoldsRolePermissions(ctx, actorID, roleID, Scope{}, false); err != nil { return err }
	return c.domainAllowedForUser(ctx, userID)
}
func (c *KeyorixCore) joinInClosure(ctx context.Context, actorID, userID, groupID uint) error {
	return c.storage.WithNamedLock(ctx, "k", func(ctx context.Context) error {
		if err := c.validateGroupJoinRoles(ctx, actorID, false, userID, groupID); err != nil { return err }
		return c.domainAllowedForGroupJoin(ctx, userID, groupID, 0)
	})
}
func (c *KeyorixCore) joinNoAuth(ctx context.Context, userID, groupID uint) error {
	return c.domainAllowedForGroupJoin(ctx, userID, groupID, 0)
}
func (c *KeyorixCore) plainUserRead(ctx context.Context, userID uint) error {
	_, err := c.storage.GetUser(ctx, userID)
	return err
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic-src", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range targetLookupsBeforeAuthorize(fset, "synthetic-src", file) {
		got[f.key] = f.call
	}
	want := map[string]string{
		"synthetic-src:transferBefore":  "GetUser(newOwnerID)",
		"synthetic-src:addMemberBefore": "domainAllowedForUser",
		"synthetic-src:joinNoAuth":      "domainAllowedForGroupJoin",
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("finding for %s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}
