package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveToken's value: exactly one terminator stripped from a file (no TrimSpace,
// the X_FILE rule), the environment value trimmed as before.
func TestResolveToken_Values(t *testing.T) {
	cases := []struct {
		name, env, file, want string
	}{
		{"file LF", "", "tok\n", "tok"},
		{"file CRLF", "", "tok\r\n", "tok"},
		{"file only one terminator", "", "tok\n\n", "tok\n"},
		{"file no terminator", "", "tok", "tok"},
		{"env trimmed", "  tok \n", "", "tok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN", tc.env)
			t.Setenv("KEYORIX_TOKEN_FILE", "")
			if tc.file != "" {
				t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, tc.file, 0o600))
			}
			got, err := resolveToken()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResolveToken_NeitherSetIsRequired(t *testing.T) {
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_TOKEN_FILE", "")
	_, err := resolveToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_TOKEN is required")
	assert.Contains(t, err.Error(), "KEYORIX_TOKEN_FILE")

	t.Setenv("KEYORIX_TOKEN", "   ")
	_, err = resolveToken()
	require.Error(t, err, "a whitespace-only KEYORIX_TOKEN is still missing")
}
