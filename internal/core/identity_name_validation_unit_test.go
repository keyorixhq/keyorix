package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Unit half of identity_name_validation_test.go: the rule itself. Kept apart so
// the behavioral tests there reference no symbol this change adds and can be
// run against the pre-fix tree for a red/green proof.
func TestValidateUsernameCharset(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"admin", "john.developer", "user@example.com", "a_b-c+d", "Ada Lovelace", "bob99"} {
		assert.NoError(t, validateUsernameCharset(ok), ok)
	}
	for label, bad := range spoofedNames {
		assert.Error(t, validateUsernameCharset(bad), label)
	}
}

func TestValidateUsernameCharset_LegacyNameFailsRule(t *testing.T) {
	t.Parallel()
	assert.Error(t, validateUsernameCharset(legacyStoredUsername), "premise of TestLegacyStoredUsernameFailingRule_KeepsWorking")
	assert.Error(t, validateIdentifier(legacyStoredRoleName), "premise of TestLegacyStoredRoleNameFailingRule_KeepsWorking")
}

func TestDerivedUsernameShape_IsSubsetOfRule(t *testing.T) {
	t.Parallel()
	// derivedUsernameShape admits only [a-z0-9]; every such name passes the rule.
	for _, n := range []string{"abc", "jrgenmller", "usr", "a1b2c3"} {
		assert.Regexp(t, derivedUsernameShape, n)
		assert.NoError(t, validateUsernameCharset(n), n)
	}
}
