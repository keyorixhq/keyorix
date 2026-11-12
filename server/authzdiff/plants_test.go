package authzdiff

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Phase 3 plants, kept as a permanent self-test: the harness must keep
// detecting each of them. A plant is applied with `go test -overlay`, so the
// working tree is never edited; the child run sweeps only the planted op.
//
// Each plant must:
//   - still find its anchor exactly once (else the production code moved and
//     the plant must be re-pointed — the test says so, it does not skip);
//   - produce at least minUnexplained "unexplained" cases, ALL on op;
//   - and the same restricted sweep WITHOUT the overlay must produce zero
//     unexplained cases (the detection is the plant's, not pre-existing noise).
//
// Opt-in (AUTHZDIFF_PLANTS=1): each plant compiles the server packages with an
// overlay and runs a restricted sweep, ~1-2 min per plant — far over the 10 s
// default budget. CI runs it as its own job (authzdiff-plants in ci.yml):
// nightly schedule, manual dispatch and ci:full-labelled PRs only, never the
// merge queue.
type plant struct {
	name           string
	file           string // repo-relative
	anchor, repl   string
	op             string
	minUnexplained int
}

var plants = []plant{
	{
		name: "name-based-role-check",
		file: "internal/core/machine_token.go",
		anchor: "\tif err := c.requireGranterHoldsRolePermissions(ctx, actorID, roleID, scope, actorIsMachine); err != nil {\n" +
			"\t\treturn err\n\t}\n",
		repl: "\tif isAdminRoleName(role.Name) { // PLANT: pre-FIX-1 name-based check\n" +
			"\t\tif err := c.requireAdminAuthorityAt(ctx, actorID, scope.ProjectID); err != nil {\n" +
			"\t\t\treturn err\n\t\t}\n\t}\n\t_ = actorIsMachine\n",
		op:             "machine.role.assign",
		minUnexplained: 50,
	},
	{
		name: "grpc-guard-removed",
		file: "server/grpc/services/machine_identity_service.go",
		anchor: "\tif err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {\n" +
			"\t\treturn nil, err\n\t}\n\t// core.RevokeMachineToken does not evict",
		repl:           "\t// PLANT: guard removed\n\t// core.RevokeMachineToken does not evict",
		op:             "machine.token.revoke",
		minUnexplained: 50,
	},
	{
		name:           "router-gate-removed",
		file:           "server/http/router.go",
		anchor:         `r.With(customMiddleware.RequirePermission(permUsersWrite)).Delete("/{id}", groupHandler.DeleteGroup)`,
		repl:           `r.Delete("/{id}", groupHandler.DeleteGroup) // PLANT: gate removed`,
		op:             "group.delete",
		minUnexplained: 10,
	},
	{
		// Removes the gRPC write gate on group delete, keeping the read gate:
		// only principals with users.read but not users.write are exposed
		// (26 unexplained cases at introduction), hence the lower floor.
		name: "grpc-delete-gate-removed",
		file: "server/grpc/services/group_service.go",
		anchor: "\tif err := authorizeGlobalMutation(ctx, s.core, actor, permUsersRead, permUsersWrite); err != nil {\n" +
			"\t\treturn nil, err\n\t}\n\tif err := s.core.DeleteGroup(",
		repl: "\tif err := authorizeGlobal(ctx, s.core, actor, permUsersRead); err != nil { // PLANT: write gate removed\n" +
			"\t\treturn nil, err\n\t}\n\tif err := s.core.DeleteGroup(",
		op:             "group.delete",
		minUnexplained: 20,
	},
	{
		// Removes the gRPC route-group read gate on group delete, keeping the
		// write gate: gRPC then allows a principal REST refuses at the /groups
		// route group. No waiver may absorb it.
		name: "grpc-group-read-gate-removed",
		file: "server/grpc/services/group_service.go",
		anchor: "\tif err := authorizeGlobalMutation(ctx, s.core, actor, permUsersRead, permUsersWrite); err != nil {\n" +
			"\t\treturn nil, err\n\t}\n\tif err := s.core.DeleteGroup(",
		repl: "\tif err := authorizeGlobal(ctx, s.core, actor, permUsersWrite); err != nil { // PLANT: read gate removed\n" +
			"\t\treturn nil, err\n\t}\n\tif err := s.core.DeleteGroup(",
		op:             "group.delete",
		minUnexplained: 20,
	},
	{
		// V5: removes ReassignOwnedSecrets' own roles.assign@project gate — the
		// exact #G10 regression (the function once had "no independent
		// authorization of its own", and the per-secret continue-on-error below
		// masks every denial as a silent (0, nil) success). With the gate gone the
		// core leg returns no error for any principal that passes input
		// validation, so it over-allows everyone the model denies (REST keeps its
		// router gate, so only the core leg diverges).
		name: "reassign-owner-core-gate-removed",
		file: "internal/core/secret_reassign_owner.go",
		anchor: "\tif allowed, err := c.AuthorizePrincipal(ctx, actorKind, actorID, permRolesAssign, Scope{ProjectID: projectID}); err != nil {\n" +
			"\t\treturn 0, fmt.Errorf(\"%s: %w\", i18n.T(\"ErrorRetrievalFailed\", nil), err)\n" +
			"\t} else if !allowed {\n" +
			"\t\treturn 0, permissionDeniedf(\"%s: %s\", i18n.T(\"ErrorPermissionDenied\", nil), \"not authorized to reassign secrets in this project\")\n" +
			"\t}\n",
		repl:           "\t_ = actorKind // PLANT: core roles.assign@project gate removed\n",
		op:             "secret.reassign.owner",
		minUnexplained: 10,
	},
}

func TestPlantsAreDetected(t *testing.T) {
	if os.Getenv("AUTHZDIFF_PLANTS") == "" {
		t.Skip("set AUTHZDIFF_PLANTS=1 to run the planted-defect self-test (slow; CI job authzdiff-plants)")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, pl := range plants {
		t.Run(pl.name, func(t *testing.T) {
			orig := filepath.Join(root, pl.file)
			src, err := os.ReadFile(orig)
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(string(src), pl.anchor); n != 1 {
				t.Fatalf("plant anchor drifted: found %d times in %s (want 1) — re-point this plant at the current code", n, pl.file)
			}
			dir := t.TempDir()
			patched := filepath.Join(dir, filepath.Base(pl.file))
			if err := os.WriteFile(patched, []byte(strings.Replace(string(src), pl.anchor, pl.repl, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			ov, _ := json.Marshal(map[string]any{"Replace": map[string]string{orig: patched}})
			overlay := filepath.Join(dir, "overlay.json")
			if err := os.WriteFile(overlay, ov, 0o600); err != nil {
				t.Fatal(err)
			}

			planted := childSweep(t, pl.op, overlay)
			clean := childSweep(t, pl.op, "")
			if clean.unexplained != 0 {
				t.Fatalf("control sweep of %s WITHOUT the plant already has %d unexplained cases: fix those first", pl.op, clean.unexplained)
			}
			if planted.unexplained < pl.minUnexplained {
				t.Errorf("plant %s: %d unexplained cases on %s, want >= %d — the harness stopped detecting it", pl.name, planted.unexplained, pl.op, pl.minUnexplained)
			}
			if len(planted.otherOps) > 0 {
				t.Errorf("plant %s: unexplained cases on ops other than %s: %v", pl.name, pl.op, planted.otherOps)
			}
			t.Logf("plant %s: %d unexplained cases, all on %s (control: 0)", pl.name, planted.unexplained, pl.op)
		})
	}
}

type childResult struct {
	unexplained int
	otherOps    []string
}

// childSweep runs TestAuthzDiffSweep for one op in a child `go test`, with an
// overlay when given, and reads its JSONL results.
func childSweep(t *testing.T, op, overlay string) childResult {
	t.Helper()
	out := filepath.Join(t.TempDir(), "res.jsonl")
	args := []string{"test", "-count=1", "-run", "^TestAuthzDiffSweep$", "-timeout", "20m"}
	if overlay != "" {
		args = append(args, "-overlay", overlay)
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=", "AUTHZDIFF_SWEEP=1", "AUTHZDIFF_OPS="+op, "AUTHZDIFF_OUT="+out,
		"AUTHZDIFF_STRICT=", "AUTHZDIFF_PLANTS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child sweep (overlay=%q) failed: %v\n%s", overlay, err, tail(string(b), 40))
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("child results: %v", err)
	}
	defer func() { _ = f.Close() }()
	var res childResult
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r struct {
			Op     string `json:"op"`
			Bucket string `json:"bucket"`
		}
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Bucket != "unexplained" {
			continue
		}
		res.unexplained++
		if r.Op != op && !seen[r.Op] {
			seen[r.Op] = true
			res.otherOps = append(res.otherOps, r.Op)
		}
	}
	return res
}

func tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
