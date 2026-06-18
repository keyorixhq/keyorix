package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretValuePolicy_Disabled(t *testing.T) {
	p := DefaultSecretValuePolicy() // disabled
	require.NoError(t, p.Validate([]byte("changeme")))
	require.NoError(t, p.Validate([]byte("")))
	require.NoError(t, p.Validate([]byte("x")))
}

func TestSecretValuePolicy_MinLength(t *testing.T) {
	p := SecretValuePolicy{Enabled: true, MinLength: 12}
	err := p.Validate([]byte("short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "12-character minimum")
	require.NoError(t, p.Validate([]byte("a-sufficiently-long-value")))
}

func TestSecretValuePolicy_RejectCommon(t *testing.T) {
	p := SecretValuePolicy{Enabled: true, RejectCommon: true}
	for _, weak := range []string{"changeme", "CHANGEME", "  password  ", "123456", "secret", "admin", ""} {
		require.Error(t, p.Validate([]byte(weak)), "%q should be rejected", weak)
	}
	require.NoError(t, p.Validate([]byte("Tr0ub4dor&3-x9fQ")))
}

func TestSecretValuePolicy_ExtraDenylist(t *testing.T) {
	p := SecretValuePolicy{Enabled: true, ExtraDenylist: []string{"acme-default", "Internal-Test"}}
	require.Error(t, p.Validate([]byte("acme-default")))
	require.Error(t, p.Validate([]byte("internal-test")), "case-insensitive")
	require.NoError(t, p.Validate([]byte("a-real-secret")))
}

func TestSecretValuePolicy_ErrorNeverEchoesValue(t *testing.T) {
	p := SecretValuePolicy{Enabled: true, RejectCommon: true, MinLength: 20}
	err := p.Validate([]byte("changeme"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "changeme", "the reason must not leak the value")
}
