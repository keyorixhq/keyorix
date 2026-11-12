package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSCIMBool(t *testing.T) {
	for in, want := range map[string]bool{`true`: true, `false`: false, ` true `: true, `"True"`: true, `"FALSE"`: false, `" false "`: false} {
		got, err := parseSCIMBool([]byte(in))
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{``, `null`, `1`, `0`, `"yes"`, `"t"`, `"1"`, `[]`, `{}`, `"true`, `tru`} {
		_, err := parseSCIMBool([]byte(in))
		assert.ErrorIs(t, err, errSCIMInvalidBool, in)
	}
}
