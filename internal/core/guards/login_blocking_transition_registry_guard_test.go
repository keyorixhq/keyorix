package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// REVOKE-GUARDS-NOV-1 item 1, the completeness half of
// internal/core/login_blocking_revoke_family_test.go.
//
// That table proves every login-blocking transition it lists revokes every
// credential of the user. This guard makes sure the list is the whole
// population: every core family function that writes a user's login state is
// found here and must be classified in loginStateWriters, either as a row of the
// table (the value names the row literal, which must appear in the table file)
// or with the reason it never blocks login / is only reached through a listed
// function. A new transition is red here until it is one or the other, so it
// cannot ship without the sweep being proven for it.
//
// What counts as "writes a user's login state" (the shapes recognised):
//   - a call to a method named SetAccountState, SetAccountStateIfMatches or
//     UpdateUserIfActiveStateMatches (any receiver: c.storage, tx, sp);
//   - a call to a storage method named DeleteUser (soft-delete blocks login) on a
//     receiver other than the core itself (c.DeleteUser is a core call);
//   - a call to core's own setAccountState, setAccountStateUnsettled or
//     setAccountStateInTx;
//   - an assignment to a field named IsActive.
//
// Function literals count toward their enclosing declaration (the writes run
// inside WithTransaction closures). Blind spots: a write through a raw gorm
// handle or a storage method of another name, and a writer outside the core
// family (coreFamilySources).

const loginBlockingTableFile = "../login_blocking_revoke_family_test.go"

// loginStateWriters classifies every discovered writer, keyed "file.go:Func".
// "row:<literal>": a row of the table; <literal> must appear, quoted, in
// loginBlockingTableFile. "never:<reason>": the write never blocks login.
// "via:<reason>": a helper reached only through classified functions.
var loginStateWriters = map[string]string{
	// The login-blocking transitions: each one is a row of the table.
	"account_state.go:SuspendUser":                    "row:SuspendUser",
	"account_state.go:setAccountState":                "row:setAccountState/",
	"users.go:DeleteUser":                             "row:DeleteUser",
	"users.go:UpdateUser":                             "row:UpdateUser/deactivate",
	"scim.go:DeprovisionSCIMUser":                     "row:DeprovisionSCIMUser",
	"scim.go:scimUpdateUserTx":                        "row:UpdateSCIMUser/deactivate",
	"migrate_user_to_machine.go:MigrateUserToMachine": "row:MigrateUserToMachine/suspendSource",

	// Helpers of the rows above.
	"account_state.go:setAccountStateUnsettled": "via:the body of setAccountState and SuspendUser",
	"account_state.go:setAccountStateInTx":      "via:setAccountStateUnsettled, MigrateUserToMachine and ReissueOneTimePassword; the caller picks the state",
	"scim.go:applySCIMActiveState":              "via:scimUpdateUserTx, which persists what it derives",

	// Writes that never block login.
	"account_state.go:ReactivateUser":                "never:target state is active",
	"account_state.go:RequirePasswordReset":          "never:target state is password_reset_required (restricted, still logs in)",
	"account.go:applyNewPassword":                    "never:clearRestrictionOnPasswordChange only clears a restriction or keeps the state",
	"account.go:setPasswordResetRequiredAfterMatch":  "never:target state is password_reset_required",
	"mfa_reset_effect.go:ResetMFACredentialsInTx":    "never:target state is password_reset_required",
	"reissue_otp.go:ReissueOneTimePassword":          "never:target state is password_reset_required",
	"setup_consume.go:completePasswordSetup":         "never:clearRestrictionOnPasswordChange only clears a restriction or keeps the state",
	"setup_consume.go:removeInvitationAcceptAccount": "never:soft-deletes an account created by the same failed invitation accept, before any session is minted; it holds no credential",
	"sso.go:completeIdPFirstLogin":                   "never:pending_first_login to active",
	"users.go:RestoreUser":                           "never:restores to is_active=true, password_reset_required",
	"users.go:persistInactiveOnCreate":               "never:a just-created account, inside its create transaction, holds no credential",
	"rotation_policies.go:UpdateRotationPolicy":      "never:writes a rotation policy's IsActive, not a user's",
}

// loginStateWriteMethods are the storage methods whose call is a login-state write.
var loginStateWriteMethods = map[string]bool{
	"SetAccountState": true, "SetAccountStateIfMatches": true, "UpdateUserIfActiveStateMatches": true,
}

// loginStateCoreHelpers are core's own account-state helpers.
var loginStateCoreHelpers = map[string]bool{
	"setAccountState": true, "setAccountStateUnsettled": true, "setAccountStateInTx": true,
}

// loginStateWriterSites returns "rel:Func" for every function in files that
// writes a user's login state (shapes in the file comment).
func loginStateWriterSites(t testing.TB, files []string, rel func(string) string) []string {
	t.Helper()
	var out []string
	for _, path := range files {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if writesLoginState(fd) {
				out = append(out, rel(path)+":"+fd.Name.Name)
			}
		}
	}
	slices.Sort(out)
	return out
}

func writesLoginState(fd *ast.FuncDecl) bool {
	recv := ""
	if fd.Recv != nil && len(fd.Recv.List) == 1 && len(fd.Recv.List[0].Names) == 1 {
		recv = fd.Recv.List[0].Names[0].Name
	}
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			x, isIdent := sel.X.(*ast.Ident)
			onCore := isIdent && recv != "" && x.Name == recv
			switch {
			case loginStateWriteMethods[name]:
				found = true
			case name == "DeleteUser" && !onCore:
				found = true
			case loginStateCoreHelpers[name] && onCore:
				found = true
			}
		case *ast.AssignStmt:
			for _, l := range v.Lhs {
				if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "IsActive" {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// TestLoginBlockingTransitions_EveryLoginStateWriterIsClassified: every core
// family function that writes a user's login state is in loginStateWriters,
// every entry is still a writer, and every "row:" names a row of the table.
func TestLoginBlockingTransitions_EveryLoginStateWriterIsClassified(t *testing.T) {
	g := guardrules.Rollout(t)
	sites := loginStateWriterSites(t, coreFamilySources(t), srcpath.CoreFamilyRel)
	if len(sites) < 8 {
		t.Fatalf("found only %d login-state writers in the core family (want at least the 8 known ones): the scan is broken", len(sites))
	}
	table, err := os.ReadFile(filepath.FromSlash(loginBlockingTableFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sites {
		class, ok := loginStateWriters[s]
		if !ok {
			g.Errorf("%s writes a user's account_state/is_active (or soft-deletes the user) and is not classified in loginStateWriters: "+
				"if it can block login, add it as a row of %s (it must revoke sessions, PATs, step-up grants, tombstone the cache and audit once) "+
				"and classify it \"row:<row name>\"; otherwise classify it \"never:<why it never blocks login>\"", s, loginBlockingTableFile)
			continue
		}
		kind, arg, _ := strings.Cut(class, ":")
		switch kind {
		case "row":
			if !strings.Contains(string(table), `"`+arg+`"`) {
				g.Errorf("%s is classified %q, but %s has no row literal %q", s, class, loginBlockingTableFile, arg)
			}
		case "never", "via":
			if strings.TrimSpace(arg) == "" {
				g.Errorf("%s is classified %q with no reason", s, class)
			}
		default:
			g.Errorf("%s: unknown class %q (row:, never: or via:)", s, class)
		}
	}
	for k := range loginStateWriters {
		if !slices.Contains(sites, k) {
			g.Errorf("loginStateWriters lists %s, which no longer writes a user's login state (or was renamed): remove or re-key the entry", k)
		}
	}
}

// TestLoginBlockingTransitions_WriterScanCalibration: the scan finds a planted
// new transition in every recognised shape, and spares a function that only
// reads.
func TestLoginBlockingTransitions_WriterScanCalibration(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"planted.go": `package core

func (c *KeyorixCore) NewLockout(ctx context.Context, id uint) error {
	return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return tx.SetAccountState(ctx, id, "suspended", c.now())
	})
}

func (c *KeyorixCore) NewBan(ctx context.Context, id uint) error {
	return c.setAccountState(ctx, 0, id, "suspended", "x")
}

func (c *KeyorixCore) NewSoftDelete(ctx context.Context, id uint) error {
	return c.storage.DeleteUser(ctx, id)
}

func (c *KeyorixCore) NewDeactivate(u *models.User) {
	u.IsActive = false
}

func (c *KeyorixCore) CallsCoreDelete(ctx context.Context, id uint) error {
	return c.DeleteUser(ctx, 0, id)
}

func (c *KeyorixCore) ReadsOnly(ctx context.Context, id uint) bool {
	u, _ := c.storage.GetUser(ctx, id)
	return u.IsActive
}
`})
	got := loginStateWriterSites(t, []string{filepath.Join(root, "planted.go")}, filepath.Base)
	want := []string{"planted.go:NewBan", "planted.go:NewDeactivate", "planted.go:NewLockout", "planted.go:NewSoftDelete"}
	if !slices.Equal(got, want) {
		t.Fatalf("scan found %v, want %v", got, want)
	}
}
