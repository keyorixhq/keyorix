package sqlite

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAllColumns(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"single unquoted", "(id)", []string{"id"}},
		{"multiple unquoted", "(id, name, email)", []string{"id", "name", "email"}},
		{"quoted names", "(`id`, `name`)", []string{"id", "name"}},
		{"mixed quote styles", `("id", 'name')`, []string{"id", "name"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAllColumns(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseAllColumns_UnexpectedToken(t *testing.T) {
	_, err := parseAllColumns("()")
	require.Error(t, err)
}

func TestIsSpaceIsQuoteIsSeparator(t *testing.T) {
	assert.True(t, isSpace(' '))
	assert.True(t, isSpace('\t'))
	assert.False(t, isSpace('a'))

	assert.True(t, isQuote('`'))
	assert.True(t, isQuote('"'))
	assert.True(t, isQuote('\''))
	assert.False(t, isQuote('a'))

	assert.True(t, isSeparator(','))
	assert.False(t, isSeparator(';'))
}
