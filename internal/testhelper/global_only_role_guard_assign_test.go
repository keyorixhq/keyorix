package testhelper

// global_only_role_guard_assign_test.go — drives the fixture guard's own t.Fatalf path
// (global_only_role_guard_test.go checks only its predicate).

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// globalOnlyGuardChildEnv makes the test binary, re-run as a child, grant a global-only
// role at a project through the named helper method ("user" or "group").
const globalOnlyGuardChildEnv = "KEYORIX_TESTHELPER_GLOBAL_ONLY_CHILD"

// TestAssignRole_RefusesGlobalOnlyAtProject: a child run of this test binary grants the
// legacy admin role (id 2) at a project through AssignUserRole and AssignGroupRole and
// must fail with the guard's message. It goes red if either method stops calling
// requireAssignableAt. The in-process half is the green side: a project role at a project
// and the global-only role at the global scope pass.
func TestAssignRole_RefusesGlobalOnlyAtProject(t *testing.T) {
	if which := os.Getenv(globalOnlyGuardChildEnv); which != "" {
		h := NewRBACTestHelper(t)
		t.Cleanup(h.Cleanup)
		h.CreateTestUser(t, "child-user", 70)
		h.CreateTestGroup(t, "child-group", "child", 71)
		project := uint(1)
		switch which {
		case "user":
			h.AssignUserRole(t, 70, 2, &project)
		case "group":
			h.AssignGroupRole(t, 71, 2, &project)
		}
		t.Logf("NOT REFUSED: %s grant of a global-only role at a project", which)
		return
	}

	for _, which := range []string{"user", "group"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAssignRole_RefusesGlobalOnlyAtProject$", "-test.count=1", "-test.v") // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- re-runs this test binary itself with fixed arguments
		cmd.Env = append(os.Environ(), globalOnlyGuardChildEnv+"="+which)
		out, err := cmd.CombinedOutput()
		require.Error(t, err, "%s: the child granted a global-only role at a project and passed:\n%s", which, out)
		assert.Contains(t, string(out), "fixture grants the global-only role", "%s: the child failed, but not on the guard:\n%s", which, out)
		assert.NotContains(t, string(out), "NOT REFUSED", which)
	}

	h := NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "parent-user", 72)
	h.CreateTestGroup(t, "parent-group", "parent", 73)
	project := uint(1)
	h.AssignUserRole(t, 72, RoleProjectAdmin, &project)
	h.AssignGroupRole(t, 73, RoleProjectViewer, &project)
	h.AssignUserRole(t, 72, 2, nil)
	h.AssignGroupRole(t, 73, 2, nil)
}
