package accessreview

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hello", truncate("hello", 5))
	assert.Equal(t, "hel…", truncate("hello!", 4))
	assert.Equal(t, "h", truncate("hi", 1))
	assert.Equal(t, "", truncate("", 5))
}

func TestLastUsedLabel_Group(t *testing.T) {
	now := time.Now()
	assert.Equal(t, "—", lastUsedLabel("group", &now))
	assert.Equal(t, "—", lastUsedLabel("group", nil))
}

func TestLastUsedLabel_UserNil(t *testing.T) {
	assert.Equal(t, "never", lastUsedLabel("user", nil))
}

func TestLastUsedLabel_UserZero(t *testing.T) {
	z := time.Time{}
	assert.Equal(t, "never", lastUsedLabel("user", &z))
}

func TestLastUsedLabel_UserFresh(t *testing.T) {
	t5 := time.Now().Add(-5 * 24 * time.Hour)
	label := lastUsedLabel("user", &t5)
	assert.Equal(t, "5d", label)
}

func TestLastUsedLabel_UserStale(t *testing.T) {
	t100 := time.Now().Add(-100 * 24 * time.Hour)
	label := lastUsedLabel("user", &t100)
	assert.Contains(t, label, "stale")
	assert.Contains(t, label, "100d")
}

func TestRunDecision_ProjectIDRequired(t *testing.T) {
	dProject = 0
	err := runDecision("revoke")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project-id is required")
}

func TestRunDecision_SourceRequired(t *testing.T) {
	dProject = 5
	dSource = ""
	err := runDecision("attest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--source is required")
}

func TestRunDecision_PrincipalIDRequired(t *testing.T) {
	dProject = 5
	dSource = "role"
	dPrincipalID = 0
	err := runDecision("revoke")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--principal-id is required")
}

func TestRunDecision_RoleIDRequiredForRoleSource(t *testing.T) {
	dProject = 5
	dSource = "role"
	dPrincipalID = 3
	dRoleID = 0
	err := runDecision("revoke")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--role-id is required")
}

func TestRunDecision_SecretIDRequiredForShareSources(t *testing.T) {
	for _, src := range []string{"direct_share", "group_share"} {
		dProject = 5
		dSource = src
		dPrincipalID = 3
		dRoleID = 0
		dSecretID = 0
		err := runDecision("revoke")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--secret-id is required", "source=%s", src)
	}
}

func TestAccessReviewCmd_Subcommands(t *testing.T) {
	names := make(map[string]bool)
	for _, c := range AccessReviewCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{"revoke", "attest"} {
		assert.True(t, names[expected], "expected subcommand %q", expected)
	}
}

func TestDecisionCmdFlags(t *testing.T) {
	for _, name := range []string{"project-id", "source", "principal-type", "principal-id", "role-id", "environment-id", "secret-id"} {
		assert.NotNil(t, revokeCmd.Flags().Lookup(name), "revoke should have --%s", name)
		assert.NotNil(t, attestCmd.Flags().Lookup(name), "attest should have --%s", name)
	}
}
