package grpc_test

// authz_walk_dead_credential_groups_test.go — the dead-credential walk runs as
// deadWalkGroups top-level tests (CI-GRPC-SHARD-1).
//
// # Why
//
// TestEveryGRPCMethodRejectsDeadCredential walked every case in one test, 748 s in
// CI, and the test-suite matrix shards server/grpc by top-level test name
// (scripts/ci-test-legs.sh, weighted_run_filter), so one test was one leg's floor.
// The walk is now TestEveryGRPCMethodRejectsDeadCredential_G0 .. _G<deadWalkGroups-1>,
// test k walking only the cases with deadCaseGroup == k, each on a world of its own
// (forEachWalkBackend builds one per test and backend), so the groups share no state
// and may land on different legs. Same mechanism as server/http's
// authz_walk_groups_test.go (CI-HTTP-SPLIT-1).
//
// # Exactly once
//
// A case is one (dead state, cold|warm) pair; each is walked against EVERY method
// by the group that owns it, with every assertion of the unsplit walk (contract
// code, public-method rule, canary leak, state digest, audit delta, "credential was
// live before it was killed"). deadCaseGroup is a pure function of the case's
// position, so every case is in exactly one group.
// TestDeadWalkGroups_PartitionTheCases proves that on the real deadStates (union of
// the groups = all len(deadStates) x 2 cases, none twice, no group empty) and proves
// from the source (go/ast) that there is exactly one _Gk test per group, whose whole
// body is deadWalkGroup(t, k), and that nothing else calls the helper. Each group
// also asserts, per backend, that it made cases x len(methods) calls, so the calls
// of all groups add up to the unsplit walk's len(deadStates) x 2 x len(methods).
//
// Not covered by the proof: the order cases run in (each case mints its own
// principal and credential and compares digests taken around its own calls, so it
// relies on no predecessor's state).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deadWalkGroups is how many top-level tests the walk is split into. Changing it
// needs that many _Gk tests (the partition test says which). 4 groups put each at
// a quarter of the former 748 s test.
const deadWalkGroups = 4

// deadCaseGroup is the group of the case (deadStates[stateIdx], warm): the case's
// index in the state-major order the walk visits them, mod deadWalkGroups. Round
// robin over the cases, not a hash, so the groups differ by at most one case
// (34 cases: 9/9/8/8); adding a state moves later cases, which the partition test
// absorbs.
func deadCaseGroup(stateIdx int, warm bool) int {
	idx := stateIdx * 2
	if warm {
		idx++
	}
	return idx % deadWalkGroups
}

func TestEveryGRPCMethodRejectsDeadCredential_G0(t *testing.T) { deadWalkGroup(t, 0) }
func TestEveryGRPCMethodRejectsDeadCredential_G1(t *testing.T) { deadWalkGroup(t, 1) }
func TestEveryGRPCMethodRejectsDeadCredential_G2(t *testing.T) { deadWalkGroup(t, 2) }
func TestEveryGRPCMethodRejectsDeadCredential_G3(t *testing.T) { deadWalkGroup(t, 3) }

func TestDeadWalkGroups_PartitionTheCases(t *testing.T) {
	require.NotEmpty(t, deadStates)
	count := map[string]int{}
	perGroup := make([]int, deadWalkGroups)
	for si, st := range deadStates {
		for _, warm := range []bool{false, true} {
			g := deadCaseGroup(si, warm)
			require.Truef(t, g >= 0 && g < deadWalkGroups, "%s warm=%v has group %d", st.name, warm, g)
			count[st.name+"/"+strconv.FormatBool(warm)]++
			perGroup[g]++
		}
	}
	require.Len(t, count, len(deadStates)*2, "every (state, cold|warm) case must be distinct: state names are unique")
	total := 0
	for g, n := range perGroup {
		assert.NotZero(t, n, "group %d is empty", g)
		t.Logf("group %d has %d of %d cases", g, n, len(deadStates)*2)
		total += n
	}
	assert.Equal(t, len(deadStates)*2, total, "the groups must cover every case exactly once")
	for c, n := range count {
		assert.Equal(t, 1, n, "case %s must be walked by exactly one group", c)
	}

	// Exactly one top-level test per group, Prefix_Gk, whose whole body is
	// deadWalkGroup(t, k), and nothing else in the package calls the helper.
	const prefix, file, helper = "TestEveryGRPCMethodRejectsDeadCredential", "authz_walk_dead_credential_groups_test.go", "deadWalkGroup"
	files, err := filepath.Glob("*_test.go")
	require.NoError(t, err)
	calls := 0
	for _, f := range files {
		af, perr := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		require.NoError(t, perr)
		ast.Inspect(af, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == helper {
					calls++
				}
			}
			return true
		})
	}
	assert.Equal(t, deadWalkGroups, calls, "%s must be called exactly once per group, from the %s_Gk tests only", helper, prefix)

	af, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	require.NoError(t, err)
	re := regexp.MustCompile(`^(.*)_G([0-9]+)$`)
	var got []int
	for _, d := range af.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil {
			continue
		}
		m := re.FindStringSubmatch(fd.Name.Name)
		if m == nil || m[1] != prefix {
			continue
		}
		k, _ := strconv.Atoi(m[2])
		got = append(got, k)
		assert.Equal(t, strconv.Itoa(k), soleCallGroupArg(fd, helper),
			"%s must consist of exactly `%s(t, %d)`", fd.Name.Name, helper, k)
	}
	slices.Sort(got)
	want := make([]int, deadWalkGroups)
	for k := range want {
		want[k] = k
	}
	assert.Equal(t, want, got, "%s: want exactly one %s_Gk test for each k in [0, %d)", file, prefix, deadWalkGroups)
}

// soleCallGroupArg returns the literal second argument of fd's body when that body
// is exactly one call `helper(t, <int literal>)`, else "".
func soleCallGroupArg(fd *ast.FuncDecl, helper string) string {
	if fd.Body == nil || len(fd.Body.List) != 1 {
		return ""
	}
	es, ok := fd.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return ""
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return ""
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != helper {
		return ""
	}
	if id, ok := call.Args[0].(*ast.Ident); !ok || id.Name != "t" {
		return ""
	}
	lit, ok := call.Args[1].(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return ""
	}
	return lit.Value
}
