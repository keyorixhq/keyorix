package faultops

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3225: POST /api/v1/users/ whose create transaction COMMITS and then reports an
// error (a lost acknowledgement) used to answer 500 while the user, its baseline
// role and its user.created row were all committed, and skipped the post-commit
// password-history seed: a client that retried got a duplicate-user conflict on a
// create that had worked, and the committed state matched neither the pre-fault
// state nor the fault-free one (oracle (d)). The answer must reflect the commit:
// the create is read back, and a row that landed is delivered as a success with
// the rest of the success path (password history) done.
func TestPartialCommit_UserCreateLostAckAnswersSuccess(t *testing.T) {
	in, outcome, why := driveFaultCase(t, "REST POST /api/v1/users/", "WithTransaction", 1, faultstorage.KindEffectThenError)
	require.Equal(t, driveObserved, outcome, "premise: the fault must fire: %s", why)
	require.Equal(t, 1, len(in.after.Tables["User"].Rows)-len(in.before.Tables["User"].Rows),
		"premise: the create transaction committed its user row")

	require.True(t, in.result.Success, "a committed create must be answered as a success, got: %s", in.result.Detail)

	sink := &driveSink{t: t}
	checkOraclesReporting(sink, in)
	require.Empty(t, sink.findings, "no oracle may flag the lost-ack create")
}

// The read-back must not turn a real failure into a success: when the create
// transaction rolls back (a plain error, nothing committed), the error stands and
// no user exists.
func TestPartialCommit_UserCreateRolledBackStaysAnError(t *testing.T) {
	in, outcome, why := driveFaultCase(t, "REST POST /api/v1/users/", "WithTransaction", 1, faultstorage.KindError)
	require.Equal(t, driveObserved, outcome, "premise: the fault must fire: %s", why)
	require.False(t, in.result.Success, "a rolled-back create must be answered as an error")
	require.Equal(t, 0, len(in.after.Tables["User"].Rows)-len(in.before.Tables["User"].Rows),
		"a rolled-back create must leave no user row")
}

// userCreateLostAckSite is one row of userCreateLostAckSites: an internal/core
// function that inserts a user inside a transaction. One file per row
// (user_create_lost_ack_entry_<func>_test.go, REGISTRY-ENTRIES.md).
type userCreateLostAckSite struct {
	fn string // set by registerUserCreateLostAckSite
	// op drives the site through a real transport: an opCatalog key whose
	// WithTransaction#1 is the site's create transaction (found by driving the op
	// at ordinals 1..6, docs/design/user-create-lost-ack-2026-11.md).
	op string
	// outOfScope, when non-empty, says why the site does not read its lost ack back
	// yet and where that is tracked. Such a row is not driven, and it fails as soon
	// as the function does call userCreateLanded (delete the reason then).
	outOfScope string
}

// userCreateLostAckSites is populated one file per row; never add a row here.
var userCreateLostAckSites []userCreateLostAckSite

// userInsertMethods derives the storage.Storage methods that insert a user from the
// interface itself: the name starts with Create, Insert, Upsert or Provision and the
// first result is *models.User. Today CreateUser and CreateUserWithRoleGrants; a new
// one is picked up without editing this test.
func userInsertMethods() map[string]bool {
	verbs := []string{"Create", "Insert", "Upsert", "Provision"}
	userPtr := reflect.TypeFor[*models.User]()
	out := map[string]bool{}
	st := reflect.TypeFor[storage.Storage]()
	for m := range st.Methods() {
		if m.Type.NumOut() == 0 || m.Type.Out(0) != userPtr {
			continue
		}
		for _, v := range verbs {
			if strings.HasPrefix(m.Name, v) {
				out[m.Name] = true
			}
		}
	}
	return out
}

// userInsertSites parses every non-test Go file under internal/core and returns,
// per enclosing function, the position of each call X.M(...) with M a user-insert
// method and X anything but the core receiver c (c.CreateUser is the core wrapper,
// whose own insert is the createUser site). Excluded and therefore not seen:
// internal/core/storage/storagetest (the in-memory double implements the methods,
// it is not a caller), and a call through a func value or interface conversion that
// does not name the method in a selector. calls reports whether the function also
// calls userCreateLanded.
func userInsertSites(t *testing.T, insert map[string]bool) (sites map[string]string, calls map[string]bool) {
	t.Helper()
	root := filepath.Join("..", "..", "internal", "core")
	sites, calls = map[string]string{}, map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "storagetest" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "userCreateLanded" {
					calls[fd.Name.Name] = true
				}
				if recv, isIdent := sel.X.(*ast.Ident); insert[sel.Sel.Name] && (!isIdent || recv.Name != "c") {
					pos := fset.Position(call.Pos()).String()
					if prev := sites[fd.Name.Name]; prev != "" {
						pos = prev + ", " + pos
					}
					sites[fd.Name.Name] = pos
				}
				return true
			})
		}
		return nil
	})
	require.NoError(t, err)
	return sites, calls
}

// TestPartialCommit_EveryUserCreateSiteHandlesLostAck is the family guard for
// #3225: every internal/core function that inserts a user (derived from the code,
// userInsertMethods + userInsertSites) has a userCreateLostAckSites row, and every
// row names a live site. A row in scope must call userCreateLanded on its
// transaction error AND, driven through its op with the create transaction
// committing and then erroring, answer success; a plain error on the same
// transaction must still answer an error and leave no user. A new creator without
// a row, or with a row but no lost-ack handling, fails here.
//
// What it does not check: that the success answer is complete for the path (the
// per-path TestPartialCommit_* tests pin that: audit rows, session, 201 body), and
// sites whose insert does not go through a selector naming the method (see
// userInsertSites).
func TestPartialCommit_EveryUserCreateSiteHandlesLostAck(t *testing.T) {
	insert := userInsertMethods()
	require.True(t, insert["CreateUser"] && insert["CreateUserWithRoleGrants"],
		"premise: the derivation must find the known insert methods, got %v", insert)
	sites, calls := userInsertSites(t, insert)
	require.Contains(t, sites, "createUser", "premise: the scan must find #4208's createUser insert")

	rows := map[string]userCreateLostAckSite{}
	for _, r := range userCreateLostAckSites {
		rows[r.fn] = r
	}
	for fn, pos := range sites {
		_, ok := rows[fn]
		assert.True(t, ok, "internal/core %s inserts a user (%s) and has no userCreateLostAckSites row: "+
			"read its transaction error back with userCreateLanded and add user_create_lost_ack_entry_%s_test.go "+
			"(docs/design/user-create-lost-ack-2026-11.md)", fn, pos, strings.ToLower(fn))
	}
	for _, r := range userCreateLostAckSites {
		t.Run(r.fn, func(t *testing.T) {
			if _, live := sites[r.fn]; !live {
				t.Fatalf("row %s names no user-insert site in internal/core: delete its file", r.fn)
			}
			if r.outOfScope != "" {
				require.False(t, calls[r.fn], "%s now calls userCreateLanded: drop its outOfScope reason and give it an op", r.fn)
				t.Logf("%s: out of scope: %s", r.fn, r.outOfScope)
				return
			}
			require.True(t, calls[r.fn], "%s must read its create transaction's error back with userCreateLanded", r.fn)
			require.NotEmpty(t, r.op, "an in-scope row needs an op that drives it")

			t.Run("lost ack answers success", func(t *testing.T) {
				in, outcome, why := driveFaultCase(t, r.op, "WithTransaction", 1, faultstorage.KindEffectThenError)
				require.Equal(t, driveObserved, outcome, "premise: the fault must fire: %s", why)
				require.Equal(t, 1, len(in.after.Tables["User"].Rows)-len(in.before.Tables["User"].Rows),
					"premise: WithTransaction#1 of %s is the create and it committed", r.op)
				require.True(t, in.result.Success, "a committed create must be answered as a success, got: %s", in.result.Detail)
			})
			t.Run("rollback stays an error", func(t *testing.T) {
				in, outcome, why := driveFaultCase(t, r.op, "WithTransaction", 1, faultstorage.KindError)
				require.Equal(t, driveObserved, outcome, "premise: the fault must fire: %s", why)
				require.False(t, in.result.Success, "a rolled-back create must be answered as an error")
				require.Equal(t, 0, len(in.after.Tables["User"].Rows)-len(in.before.Tables["User"].Rows),
					"a rolled-back create must leave no user row")
			})
		})
	}
}
