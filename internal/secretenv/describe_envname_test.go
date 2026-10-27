package secretenv

// isEnvName decides between NAME="path" and label "path" in DescribeFile. The class is
// A-Z, 0-9 and '_'; gremlins left the comparison boundaries and negations of its range
// checks alive (MUTANT-RESIDUAL-1), so each edge of each range is tested on both sides.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsEnvName_CharacterClassEdges(t *testing.T) {
	for _, label := range []string{
		"A", "Z", "M", // both ends and the middle of A-Z
		"0", "9", "5", // both ends and the middle of 0-9
		"_",
		"KEYORIX_DB_PASSWORD_FILE", "X9", "_0A",
	} {
		assert.True(t, isEnvName(label), "%q is an environment variable name", label)
	}
	for _, label := range []string{
		"",       // nothing to name
		"@", "[", // the characters just outside A-Z
		"/", ":", // the characters just outside 0-9
		"a", "z", // lower case is not a variable name here
		"-", " ", ".",
		"KEY ORIX", "KEYORIX-DB", "KEYORIXz", "9@", "[0",
		"--passphrase-file",
	} {
		assert.False(t, isEnvName(label), "%q is not an environment variable name", label)
	}
}
