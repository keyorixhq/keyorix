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

func TestParseAllColumns_BracketQuoted(t *testing.T) {
	got, err := parseAllColumns("([id])")
	require.NoError(t, err)
	assert.Equal(t, []string{"id"}, got)
}

func TestParseAllColumns_EscapedQuoteInsideQuotedName(t *testing.T) {
	got, err := parseAllColumns("(`na``me`)")
	require.NoError(t, err)
	assert.Equal(t, []string{"na`me"}, got, "a doubled quote char inside a quoted name must be treated as an escaped literal, not the closing quote")
}

func TestParseAllColumns_SpacesAroundSeparator(t *testing.T) {
	got, err := parseAllColumns("(id  , name)")
	require.NoError(t, err)
	assert.Equal(t, []string{"id", "name"}, got)
}

func TestParseAllColumns_TrailingWhitespaceAfterClose(t *testing.T) {
	got, err := parseAllColumns("(id) ")
	require.NoError(t, err)
	assert.Equal(t, []string{"id"}, got)
}

func TestParseAllColumns_UnquotedNameFollowedByQuoteErrors(t *testing.T) {
	_, err := parseAllColumns(`(id"x)`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected token")
}

func TestParseAllColumns_UnexpectedTokenAfterName(t *testing.T) {
	_, err := parseAllColumns("(id x)")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected token")
}

func TestParseAllColumns_UnterminatedInput(t *testing.T) {
	_, err := parseAllColumns("(id")
	require.Error(t, err)
	assert.Equal(t, "unexpected end", err.Error())
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
