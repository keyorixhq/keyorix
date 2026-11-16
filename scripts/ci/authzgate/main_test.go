package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const repoRoot = "../../.."

// diskTree reads treeDirs from the working tree (so the tests judge
// uncommitted changes too).
func diskTree(t *testing.T) tree {
	t.Helper()
	tr := tree{}
	for _, d := range treeDirs {
		err := filepath.WalkDir(filepath.Join(repoRoot, d), func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(repoRoot, p)
			rel = filepath.ToSlash(rel)
			if !strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, ".sql") && rel != "server/authzdiff/matrix.json" {
				return nil
			}
			b, err := os.ReadFile(p) //nolint:gosec // repo files
			tr[rel] = b
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return tr
}

func realModel(t *testing.T) (*model, tree) {
	t.Helper()
	tr := diskTree(t)
	m, err := newModel(tr)
	if err != nil {
		t.Fatal(err)
	}
	return m, tr
}

func TestParseDiff(t *testing.T) {
	out := []byte(`diff --git a/internal/core/a.go b/internal/core/a.go
--- a/internal/core/a.go
+++ b/internal/core/a.go
@@ -10,2 +10,3 @@ func x() {
-a
-b
+a
+b
+c
@@ -30 +31,0 @@ func y() {
-gone
diff --git a/internal/core/old.go b/internal/core/old.go
--- a/internal/core/old.go
+++ /dev/null
@@ -1,3 +0,0 @@
-package core
-
-func z() {}
diff --git a/internal/core/new.go b/internal/core/new.go
--- /dev/null
+++ b/internal/core/new.go
@@ -0,0 +1 @@
+package core
`)
	h, err := parseDiff(out)
	if err != nil {
		t.Fatal(err)
	}
	a := h["internal/core/a.go"]
	if !slices.Equal(a.oldLines, []int{10, 11, 30}) || !slices.Equal(a.newLines, []int{10, 11, 12, 31, 32}) {
		t.Errorf("a.go: old=%v new=%v", a.oldLines, a.newLines)
	}
	if o := h["internal/core/old.go"]; o == nil || !slices.Equal(o.oldLines, []int{1, 2, 3}) {
		t.Errorf("deleted file: %+v", o)
	}
	if n := h["internal/core/new.go"]; n == nil || !slices.Equal(n.newLines, []int{1}) {
		t.Errorf("new file: %+v", n)
	}
}

// fixture is a miniature of the shapes the gate must see: a core decision
// root, a helper reaching it, a row method, a handler calling the row, an
// unrelated package with a same-named unexported function, a permission
// constant, an RBAC seed, and the authzdiff op table.
func fixture() tree {
	return tree{
		"internal/core/storage/iface_rbac.go": []byte(`package storage
type RBACStore interface { ResolveUserPermissionAt() error }
type SecretStore interface { GetSecret() error; ListSharesBySecret() error }
`),
		"internal/core/authz.go": []byte(`package core
func (c *KeyorixCore) AuthorizePrincipal() (bool, error) { return c.storage.ResolveUserPermissionAt() == nil, nil }
func (c *KeyorixCore) requireCeiling() error {
	ok, _ := c.AuthorizePrincipal()
	if !ok { return nil }
	return nil
}
func roleName() string { return "x" }
`),
		"internal/core/token.go": []byte(`package core
func (c *KeyorixCore) IssueMachineToken() error {
	return c.requireCeiling()
}
func (c *KeyorixCore) Version() string { return "1" }
`),
		"internal/core/constants.go": []byte(`package core
const permSecretsRead = "secrets.read"
`),
		"internal/dynamic/engine.go": []byte(`package dynamic
func roleName() string { return "db-role" }
func Issue() string { return roleName() }
`),
		"server/http/handlers/tokens.go": []byte(`package handlers
func (h *CatalogHandler) IssueToken() error { return h.core.IssueMachineToken() }
func (h *CatalogHandler) Version() string { return h.core.Version() }
`),
		"server/middleware/auth.go": []byte(`package middleware
func RequireAuth() error { return core.AuthorizePrincipal() }
`),
		"migrations/003_rbac_seed_data.up.sql": []byte(`INSERT INTO permissions (name) VALUES ('secrets.read');`),
		"server/authzdiff/matrix.json":         []byte(`{"rows":[{"core":"IssueMachineToken"},{"core":"GetSecret"}]}`),
		"server/authzdiff/ops_test.go": []byte(`package authzdiff
var x = []opSpec{
	{name: "machine.token.issue", row: "IssueMachineToken", core: func() error { return lg.c.IssueMachineToken() }},
	{name: "secret.read", row: "GetSecret", core: func() error { return lg.c.GetSecret() }},
	{name: "secret.update", row: "UpdateSecret"},
	{name: "filler.a", row: "FillerA"},
	{name: "filler.b", row: "FillerB"},
	userOp("user.suspend", "SuspendUser", "users.write", func() error { return lg.c.SuspendUser() }),
	valueRead("secret.value.byid", nil),
}
func userOp(name, row, perm string, coreFn func() error) opSpec {
	return opSpec{name: name, row: row, core: coreFn}
}
func valueRead(name string, path func() string) opSpec {
	return opSpec{name: name, row: "GetSecretForValueRead", core: func() error { return lg.c.GetSecretForValueRead() }}
}
`),
	}
}

func lines(from, to int) []int {
	var out []int
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func TestPlan_Fixture(t *testing.T) {
	ft := fixture()
	cases := []struct {
		name  string
		file  string
		lines []int
		mode  mode
		ops   []string
	}{
		// The #4332 shape: a ceiling helper inside core changes.
		{"helper reaching a root -> the op of the row above it", "internal/core/authz.go", []int{4}, modeOps, []string{"machine.token.issue"}},
		{"row method itself", "internal/core/token.go", []int{3}, modeOps, []string{"machine.token.issue"}},
		{"handler calling an authz-checked row", "server/http/handlers/tokens.go", []int{2}, modeOps, []string{"machine.token.issue"}},
		{"decision root -> full", "internal/core/authz.go", []int{2}, modeFull, nil},
		{"permission constant -> full", "internal/core/constants.go", []int{2}, modeFull, nil},
		{"middleware -> full", "server/middleware/auth.go", []int{2}, modeFull, nil},
		{"RBAC seed migration -> full", "migrations/003_rbac_seed_data.up.sql", []int{1}, modeFull, nil},
		{"the oracle itself -> full", "server/authzdiff/ops_test.go", []int{3}, modeFull, nil},
		{"the gate itself -> full", "scripts/ci/authzgate/main.go", []int{1}, modeFull, nil},
		{"ci.yml -> canary ops", ".github/workflows/ci.yml", []int{1}, modeOps, canaryOps},
		{"non-authz core method -> none", "internal/core/token.go", []int{5}, modeNone, nil},
		{"non-authz handler -> none", "server/http/handlers/tokens.go", []int{3}, modeNone, nil},
		// unexported roleName in core is not the one in internal/dynamic
		{"same unexported name in another package -> none", "internal/dynamic/engine.go", []int{2, 3}, modeNone, nil},
		{"docs -> none", "docs/x.md", []int{1}, modeNone, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := planFrom(map[string]*fileHunks{tc.file: {oldLines: tc.lines, newLines: tc.lines}}, ft, ft)
			if err != nil {
				t.Fatal(err)
			}
			if p.mode != tc.mode || !slices.Equal(p.ops, tc.ops) {
				t.Fatalf("mode=%s ops=%v, want %s %v\n%s", p.mode, p.ops, tc.mode, tc.ops, strings.Join(p.reasons, "\n"))
			}
		})
	}
}

// A relevant function deleted at head cannot be mapped: full.
func TestPlan_DeletedHelperIsFull(t *testing.T) {
	ht := fixture()
	bt := fixture()
	bt["internal/core/extra.go"] = []byte("package core\nfunc (c *KeyorixCore) requireExtra() error { _, err := c.AuthorizePrincipal(); return err }\n")
	p, err := planFrom(map[string]*fileHunks{"internal/core/extra.go": {oldLines: lines(1, 2)}}, ht, bt)
	if err != nil {
		t.Fatal(err)
	}
	if p.mode != modeFull {
		t.Fatalf("mode=%s, want full\n%s", p.mode, strings.Join(p.reasons, "\n"))
	}
}

// A caller with an ambiguous (or library-like) name stops the mapping: full,
// never a narrower op set.
func TestPlan_AmbiguousCallerIsFull(t *testing.T) {
	ft := fixture()
	ft["internal/core/get.go"] = []byte("package core\nfunc (c *KeyorixCore) Get() error { return c.requireCeiling() }\n")
	p, err := planFrom(map[string]*fileHunks{"internal/core/authz.go": {newLines: []int{4}}}, ft, ft)
	if err != nil {
		t.Fatal(err)
	}
	if p.mode != modeFull {
		t.Fatalf("mode=%s, want full\n%s", p.mode, strings.Join(p.reasons, "\n"))
	}
}

func TestCheckLog(t *testing.T) {
	ok := "=== RUN TestAuthzDiffSweep\n    sweep_test.go:299: sweep: 256 cases, 0 with an O1/O2 class\n--- PASS: TestAuthzDiffSweep/machine.token.issue (0.7s)\n"
	if err := checkLog([]byte(ok), []string{"machine.token.issue"}, nil); err != nil {
		t.Errorf("ok log: %v", err)
	}
	failed := strings.Replace(ok, "--- PASS", "--- FAIL", 1)
	if err := checkLog([]byte(failed), []string{"machine.token.issue"}, nil); err != nil {
		t.Errorf("a failed op still ran (go test's status fails the job): %v", err)
	}
	for name, tc := range map[string]struct {
		log string
		ops []string
	}{
		"no sweep line (renamed test or env var)": {"ok  \tgithub.com/keyorixhq/keyorix/server/authzdiff\t0.1s [no tests to run]\n", nil},
		"zero cases":                      {"sweep: 0 cases\n", nil},
		"planned op unknown to the sweep": {ok, []string{"machine.token.issue", "no.such.op"}},
	} {
		if err := checkLog([]byte(tc.log), tc.ops, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// full mode: the ran set must be the parsed op table exactly
	full := ok + "--- PASS: TestAuthzDiffSweep/secret.update (0.1s)\n"
	if err := checkLog([]byte(full), nil, []string{"machine.token.issue", "secret.update"}); err != nil {
		t.Errorf("full, matching: %v", err)
	}
	if err := checkLog([]byte(full), nil, []string{"machine.token.issue"}); err == nil {
		t.Error("full: an op the parser does not know was accepted")
	}
	if err := checkLog([]byte(full), nil, []string{"machine.token.issue", "secret.update", "user.suspend"}); err == nil {
		t.Error("full: a parsed op the sweep did not run was accepted")
	}
}

// Both op shapes are parsed: literals and constructor calls.
func TestAuthzdiffOps_Fixture(t *testing.T) {
	all, err := authzdiffOps(fixture())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, o := range all {
		got[o.name] = o.row
	}
	for name, row := range map[string]string{
		"machine.token.issue": "IssueMachineToken",
		"user.suspend":        "SuspendUser",
		"secret.value.byid":   "GetSecretForValueRead",
	} {
		if got[name] != row {
			t.Errorf("op %s: row %q, want %q (all: %v)", name, got[name], row, got)
		}
	}
	if len(all) != 7 {
		t.Errorf("%d ops, want 7: %v", len(all), got)
	}
}

// ---------- the real tree ----------

func TestCoreDecisionRootsExist(t *testing.T) {
	m, _ := realModel(t)
	for _, r := range coreDecisionRoots {
		if len(m.ix.byKey[keyOf(coreDir, r)]) == 0 {
			t.Errorf("decision root %s is not declared in %s: renamed? update coreDecisionRoots", r, coreDir)
		}
	}
}

func TestStorageRootsAreDerived(t *testing.T) {
	_, tr := realModel(t)
	sr, err := storageRoots(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ResolveUserPermissionAt", "ResolveMachinePermissionAt", "GetMachineRoleScopes", "ListSharesBySecret"} {
		if !slices.Contains(sr, want) {
			t.Errorf("storage roots miss %s (got %d roots)", want, len(sr))
		}
	}
}

// Every authzdiff op's row is a KeyorixCore method in the index, so a core
// change can reach it. An op whose row is not would be selectable only through
// its literal's selectors, silently narrower.
func TestEveryOpRowIsAnIndexedCoreMethod(t *testing.T) {
	m, tr := realModel(t)
	all, err := authzdiffOps(tr)
	if err != nil {
		t.Fatal(err)
	}
	// 95 on 2026-11-16, equal to the full sweep's op count. A drift of a few is
	// caught exactly by check-log -full in CI; this floor catches a parser that
	// lost a whole shape.
	if len(all) < 90 {
		t.Fatalf("only %d ops parsed from server/authzdiff: the op table changed shape", len(all))
	}
	for _, o := range all {
		if !slices.ContainsFunc(m.ix.byKey[o.row], func(d *decl) bool { return d.recv == "KeyorixCore" }) {
			t.Errorf("op %s: row %s is not a KeyorixCore method", o.name, o.row)
		}
	}
}

// The shapes AUTHZ-MODEL-GUARD-1 names: permission-check helper callers,
// permission constants, seed data, the IssueMachineToken and role-assign
// handlers, the authz interceptors and middleware.
func TestTriggerSetCoversTheNamedShapes(t *testing.T) {
	m, _ := realModel(t)
	find := func(file, name string) *decl {
		for _, d := range m.ix.byFile[file] {
			if d.name == name {
				return d
			}
		}
		return nil
	}
	for _, c := range []struct{ file, name string }{
		{"internal/core/authz.go", "requireActorHoldsTargetPermissions"}, // #4332
		{"internal/core/authz.go", "requireMachinePrivilegeCeiling"},
		{"internal/core/machine_token.go", "IssueMachineToken"},
		{"internal/core/legal_hold.go", "LiftLegalHold"}, // (string, error) helper
		{"internal/core/constants.go", "permSecretsRead"},
		{"server/grpc/services/constants.go", "permSecretsRead"},
		{"server/http/handlers/machine_identities.go", "IssueMachineToken"},
		{"server/http/handlers/rbac.go", "AssignRole"},
		{"server/grpc/services/role_service.go", "AssignRole"},
		{"server/grpc/interceptors/auth.go", "authenticateRequest"},
		{"internal/storage/store/local_principal_permission.go", "ResolveUserPermissionAt"},
	} {
		d := find(c.file, c.name)
		if d == nil {
			t.Errorf("%s: %s not found (moved? update this list)", c.file, c.name)
			continue
		}
		if m.reason(d) == "" {
			t.Errorf("%s: %s is not in the trigger set", c.file, c.name)
		}
	}
	mw := 0
	for _, d := range m.ix.decls {
		if strings.HasPrefix(d.file, "server/middleware/") && m.reason(d) != "" {
			mw++
		}
	}
	if mw == 0 {
		t.Error("no server/middleware declaration is in the trigger set")
	}
}

// The real failure: #4332's own diff plans exactly the op the stale model got
// wrong. Needs the merge commit in this clone (a shallow CI checkout has no
// history: skipped there; TestPlan_Fixture covers the same shape).
func TestPlan_PR4332(t *testing.T) {
	const merge = "981a32f801ae4ab5553bb61a1f982d9b08430de3"
	if err := exec.Command("git", "cat-file", "-e", merge+"^1").Run(); err != nil {
		t.Skipf("%s is not in this clone (shallow checkout)", merge)
	}
	p, err := makePlan(merge+"^1", merge)
	if err != nil {
		t.Fatal(err)
	}
	if p.mode != modeOps || !slices.Equal(p.ops, []string{"machine.token.issue"}) {
		t.Fatalf("mode=%s ops=%v, want ops [machine.token.issue]\n%s", p.mode, p.ops, strings.Join(p.reasons, "\n"))
	}
}
