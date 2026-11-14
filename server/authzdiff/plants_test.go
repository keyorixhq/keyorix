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
//   - produce at least minUnexplained cases in its bucket (default
//     "unexplained"), ALL on op;
//   - and the same restricted sweep WITHOUT the overlay must produce zero
//     cases in that bucket (the detection is the plant's, not pre-existing
//     noise).
//
// A plant whose bucket is a waiver (not "unexplained") does NOT prove that a
// strict sweep fails on the defect: it proves only that the harness still
// RECORDS it, in that waiver, where a clean tree records none.
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
	// bucket is the partition bucket the plant's cases must land in; "" means
	// "unexplained" (a strict sweep fails on them).
	bucket string
}

func (pl plant) wantBucket() string {
	if pl.bucket == "" {
		return "unexplained"
	}
	return pl.bucket
}

var plants = append([]plant{
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
		// validation, so it over-allows everyone the model denies. REST keeps its
		// router gate and the op has no gRPC leg, so only the core leg diverges:
		// "core allows, every present transport denies, the model denies" is
		// exactly the known-04 waiver (partition_test.go), never "unexplained".
		// This plant therefore proves the harness RECORDS the core-only
		// over-allow (240 known-04 cases planted, 0 clean, at introduction); it
		// does not fail a strict sweep, by the partition's design.
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
		bucket:         "known-04",
	},
	{
		// V5: removes ActivateBreakGlass's IsProjectMember refusal — the
		// self-elevation gate. Its earlier form (GetUserRoleIDsAt, which matches
		// project_id = 0 OR P) let the install-wide baseline count as membership
		// and any authenticated user self-grant the emergency role on ANY project
		// (#284-era). With the refusal gone, core grants the emergency role to any
		// user who passes input validation, and REST and gRPC — which have no gate
		// of their own on this op — over-allow the same non-members, so every leg
		// allows what the memberOnly model rule denies.
		name:           "breakglass-activate-membership-gate-removed",
		file:           "internal/core/break_glass.go",
		anchor:         "\tif !affiliated {\n\t\treturn nil, refuseBreakGlass(fmt.Sprintf(\"%s: %s\", i18n.T(\"ErrorPermissionDenied\", nil), \"break-glass is available only to members of the project\"), ErrBreakGlassNotProjectMember, ErrPermissionDenied)\n\t}\n",
		repl:           "\t_ = affiliated // PLANT: break-glass membership gate removed\n",
		op:             "breakglass.activate",
		minUnexplained: 10,
	},
}, fixRegressionPlants...)

// fixRegressionPlants revert, one each, the authorization fixes merged after
// the harness's first findings, so every fix keeps a differential case that is
// red without it. Each replacement restores the pre-fix behaviour of the
// current code (not a historical copy of the file), and its floor is set
// below the count measured at introduction (AUTHZDIFF-TAILS-1).
//
// Not planted: #3983 (the system_viewer baseline ceiling on user creation).
// Every fixture user is created holding that baseline, so no principal can
// tell the check's absence apart; a custom principal without the baseline
// would be needed first.
var fixRegressionPlants = []plant{
	{
		// #3986: REST AddProjectMember no longer tags a machine actor as its own
		// granter, so core refuses every machine (an over-denial; 6 cases at
		// introduction: machines holding every permission the grant needs).
		name:           "fix-3986-member-add-self-granter-tag-removed",
		file:           "server/http/handlers/project_members.go",
		anchor:         "\t\tctx = core.WithSelfMachineGranter(ctx, userCtx.PrincipalID())\n\t}\n\tif err := h.coreService.AddProjectMember(",
		repl:           "\t\t// PLANT: #3986 reverted\n\t}\n\tif err := h.coreService.AddProjectMember(",
		op:             "member.add",
		minUnexplained: 5,
	},
	{
		// #3987: gRPC DeleteUser without the /users route group's read gate
		// (26 cases at introduction: users.delete without users.read, globally).
		name: "fix-3987-user-read-gate-removed",
		file: "server/grpc/services/user_service.go",
		anchor: "\tif err := authorizeGlobalMutation(ctx, s.core, actor, \"users.read\", \"users.delete\"); err != nil {\n" +
			"\t\treturn nil, err\n\t}\n",
		repl: "\tif err := authorizeGlobal(ctx, s.core, actor, \"users.delete\"); err != nil { // PLANT: #3987 reverted\n" +
			"\t\treturn nil, err\n\t}\n",
		op:             "user.delete",
		minUnexplained: 20,
	},
	{
		// #3990 (and FU-OWNERSHIP-1, which made the check unconditional): a
		// role set on an existing member is not judged against the granter
		// ceiling, so a machine without roleName's permissions passes (250
		// cases at introduction).
		name: "fix-3990-setrole-ceiling-removed",
		file: "internal/core/project_members.go",
		anchor: "\t// role or, for a machine, an untagged relay's way past roles.assign (#3990).\n" +
			"\tif err := c.requireGranterHoldsRolePermissions(ctx, actorID, role.ID, scope, actorIsMachine); err != nil {\n" +
			"\t\treturn err\n\t}\n",
		repl:           "\t// PLANT: #3990 reverted\n",
		op:             "member.setrole",
		minUnexplained: 100,
	},
	{
		// #3993: a machine issuing a token for a peer is not held to the
		// peer's permissions. Only 2 cases at introduction (a machine holding
		// roles.assign@A but not every permission of the target machine's
		// role), hence the floor of 2.
		name: "fix-3993-machine-target-ceiling-removed",
		file: "internal/core/authz.go",
		anchor: "\tif actorType == ActorTypeMachine && machineID != 0 {\n" +
			"\t\treturn c.requireMachineActorHoldsTargetPermissions(ctx, principalID, machineID)\n\t}\n",
		repl:           "\t// PLANT: #3993 reverted\n",
		op:             "machine.token.issue",
		minUnexplained: 2,
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

			bucket := pl.wantBucket()
			planted := childSweep(t, pl.op, overlay, bucket)
			clean := childSweep(t, pl.op, "", bucket)
			if clean.matched != 0 {
				t.Fatalf("control sweep of %s WITHOUT the plant already has %d %s cases: fix those first", pl.op, clean.matched, bucket)
			}
			if planted.matched < pl.minUnexplained {
				t.Errorf("plant %s: %d %s cases on %s, want >= %d — the harness stopped detecting it", pl.name, planted.matched, bucket, pl.op, pl.minUnexplained)
			}
			if len(planted.otherOps) > 0 {
				t.Errorf("plant %s: %s cases on ops other than %s: %v", pl.name, bucket, pl.op, planted.otherOps)
			}
			t.Logf("plant %s: %d %s cases, all on %s (control: 0)", pl.name, planted.matched, bucket, pl.op)
		})
	}
}

type childResult struct {
	matched  int // results in the requested bucket
	otherOps []string
}

// childSweep runs TestAuthzDiffSweep for one op in a child `go test`, with an
// overlay when given, and counts its JSONL results in bucket.
func childSweep(t *testing.T, op, overlay, bucket string) childResult {
	t.Helper()
	out := filepath.Join(t.TempDir(), "res.jsonl")
	args := []string{"test", "-count=1", "-run", "^TestAuthzDiffSweep$", "-timeout", "20m"}
	if overlay != "" {
		args = append(args, "-overlay", overlay)
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	// GOFLAGS is passed through (the parent's harness flags such as -p, -trimpath
	// and -ldflags=-w keep the child on the same build-cache keys, without
	// debug-symbol links). It used to be cleared with no recorded reason.
	cmd.Env = append(os.Environ(), "GOFLAGS="+os.Getenv("GOFLAGS"), "AUTHZDIFF_SWEEP=1", "AUTHZDIFF_OPS="+op, "AUTHZDIFF_OUT="+out,
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
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Bucket != bucket {
			continue
		}
		res.matched++
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
