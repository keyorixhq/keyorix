package rbac

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitPermissionName_Valid(t *testing.T) {
	r, a, err := splitPermissionName("secrets.read")
	require.NoError(t, err)
	assert.Equal(t, "secrets", r)
	assert.Equal(t, "read", a)
}

func TestSplitPermissionName_NoResourceOrAction(t *testing.T) {
	cases := []string{"noDot", ".action", "resource.", ""}
	for _, c := range cases {
		_, _, err := splitPermissionName(c)
		require.Error(t, err, "input %q should fail", c)
		assert.Contains(t, err.Error(), "resource.action")
	}
}

func TestSplitPermissionName_MultiDot(t *testing.T) {
	r, a, err := splitPermissionName("a.b.c")
	require.NoError(t, err)
	assert.Equal(t, "a", r)
	assert.Equal(t, "b.c", a)
}

func TestAssignRoleCmd_NegativeTTL(t *testing.T) {
	orig := roleTTL
	defer func() { roleTTL = orig }()
	roleTTL = -1 * time.Hour
	err := runAssignRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ttl must be positive")
}

func TestAssignRoleCmd_RequiredFlags(t *testing.T) {
	const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"
	for _, name := range []string{"user", "role"} {
		f := assignRoleCmd.Flags().Lookup(name)
		require.NotNil(t, f)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestRemoveRoleCmd_RequiredFlags(t *testing.T) {
	const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"
	for _, name := range []string{"user", "role"} {
		f := removeRoleCmd.Flags().Lookup(name)
		require.NotNil(t, f)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestCheckPermissionCmd_RequiredFlags(t *testing.T) {
	const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"
	for _, name := range []string{"user", "permission"} {
		f := checkPermissionCmd.Flags().Lookup(name)
		require.NotNil(t, f)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}
