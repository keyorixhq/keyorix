package invite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInviteCommandStructure(t *testing.T) {
	assert.Equal(t, "invite", InviteCmd.Use)

	names := make([]string, 0)
	for _, c := range InviteCmd.Commands() {
		names = append(names, c.Use)
	}
	for _, expected := range []string{"send", "list", "revoke"} {
		assert.Contains(t, names, expected, "expected subcommand %q", expected)
	}
}

func TestInviteSendRequiredFlags(t *testing.T) {
	for _, name := range []string{"project", "email", "role", "by"} {
		assert.NotNil(t, sendCmd.Flags().Lookup(name), "send should have --%s", name)
	}
	for _, name := range []string{"email", "role", "by"} {
		ann := sendCmd.Flags().Lookup(name).Annotations[cobraRequired]
		assert.NotEmpty(t, ann, "--%s should be marked required", name)
	}
}

func TestInviteRevokeRequiredFlags(t *testing.T) {
	for _, name := range []string{"id", "by"} {
		f := revokeCmd.Flags().Lookup(name)
		assert.NotNil(t, f, "revoke should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestInviteListFlags(t *testing.T) {
	assert.NotNil(t, listCmd.Flags().Lookup("project"))
	assert.NotNil(t, listCmd.Flags().Lookup("stale-days"))
}

// cobraRequired is the annotation key cobra uses to mark required flags.
const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"
