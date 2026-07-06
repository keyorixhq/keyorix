package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// cobraRequired is the annotation key cobra uses to mark required flags.
const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"

func TestRequestCommandStructure(t *testing.T) {
	assert.Equal(t, "request", RequestCmd.Use)

	names := make([]string, 0)
	for _, c := range RequestCmd.Commands() {
		names = append(names, c.Use)
	}
	for _, expected := range []string{"access", "secret-access", "list", "withdraw", "review"} {
		assert.Contains(t, names, expected, "expected subcommand %q", expected)
	}
}

func TestRequestSecretAccessFlags(t *testing.T) {
	for _, name := range []string{"secret-id", "ref", "user", "reason"} {
		assert.NotNil(t, secretAccessCmd.Flags().Lookup(name), "secret-access should have --%s", name)
	}
	assert.NotEmpty(t, secretAccessCmd.Flags().Lookup("user").Annotations[cobraRequired], "--user should be required")
}

func TestRequestAccessFlags(t *testing.T) {
	for _, name := range []string{"project", "user", "role", "reason"} {
		assert.NotNil(t, accessCmd.Flags().Lookup(name), "access should have --%s", name)
	}
	assert.NotEmpty(t, accessCmd.Flags().Lookup("user").Annotations[cobraRequired], "--user should be required")
}

func TestRequestWithdrawRequiredFlags(t *testing.T) {
	for _, name := range []string{"id", "user"} {
		f := withdrawCmd.Flags().Lookup(name)
		assert.NotNil(t, f, "withdraw should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestRequestReviewRequiredFlags(t *testing.T) {
	for _, name := range []string{"id", "action", "role", "reason", "by"} {
		assert.NotNil(t, reviewCmd.Flags().Lookup(name), "review should have --%s", name)
	}
	for _, name := range []string{"id", "action", "by"} {
		assert.NotEmpty(t, reviewCmd.Flags().Lookup(name).Annotations[cobraRequired], "--%s should be required", name)
	}
}
