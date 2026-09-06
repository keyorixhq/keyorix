package envflag

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEnabled_UnparsableValue confirms that a set-but-invalid value (e.g.
// "yes" or "maybe") returns false (fail closed).
func TestEnabled_UnparsableValue(t *testing.T) {
	t.Setenv("TEST_FLAG_ENABLED_ENVFLAG", "yes") // not accepted by strconv.ParseBool
	assert.False(t, Enabled("TEST_FLAG_ENABLED_ENVFLAG"))
}

func TestEnabled_FalseValue(t *testing.T) {
	t.Setenv("TEST_FLAG_ENABLED_ENVFLAG", "false")
	assert.False(t, Enabled("TEST_FLAG_ENABLED_ENVFLAG"))
}

func TestEnabled_TrueValue(t *testing.T) {
	t.Setenv("TEST_FLAG_ENABLED_ENVFLAG", "1")
	assert.True(t, Enabled("TEST_FLAG_ENABLED_ENVFLAG"))
}

// TestEnabled_NotSetAtAll covers the !ok branch (the environment variable is
// entirely absent from the environment, not merely set-and-empty).
func TestEnabled_NotSetAtAll(t *testing.T) {
	assert.False(t, Enabled("KEYORIX_FLAG_DEFINITELY_NOT_SET_ENVFLAG_UNIQUE_XYZ"))
}

// TestEnabled_SetButEmpty covers the "set but empty" branch: LookupEnv
// returns ok=true for an empty string, and ParseBool("") fails.
func TestEnabled_SetButEmpty(t *testing.T) {
	t.Setenv("TEST_FLAG_EMPTY_ENVFLAG", "")
	assert.False(t, Enabled("TEST_FLAG_EMPTY_ENVFLAG"))
}
