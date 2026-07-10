package share

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveShareExpiry_BothSet(t *testing.T) {
	_, err := resolveShareExpiry("2026-12-01T00:00:00Z", "24h")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one of --expires or --ttl")
}

func TestResolveShareExpiry_NeitherSet(t *testing.T) {
	exp, err := resolveShareExpiry("", "")
	require.NoError(t, err)
	assert.Nil(t, exp)
}

func TestResolveShareExpiry_ValidExpires(t *testing.T) {
	exp, err := resolveShareExpiry("2030-06-01T12:00:00Z", "")
	require.NoError(t, err)
	require.NotNil(t, exp)
	assert.Equal(t, 2030, exp.Year())
}

func TestResolveShareExpiry_BadExpiresFormat(t *testing.T) {
	_, err := resolveShareExpiry("June 1st 2030", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--expires")
}

func TestResolveShareExpiry_ValidTTL(t *testing.T) {
	before := time.Now()
	exp, err := resolveShareExpiry("", "24h")
	require.NoError(t, err)
	require.NotNil(t, exp)
	assert.True(t, exp.After(before), "expiry should be in the future")
}

func TestResolveShareExpiry_BadTTLFormat(t *testing.T) {
	_, err := resolveShareExpiry("", "not-a-duration")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ttl")
}

func TestResolveShareExpiry_NegativeTTL(t *testing.T) {
	_, err := resolveShareExpiry("", "-1h")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "positive")
}

func TestFormatShareExpiry_Nil(t *testing.T) {
	assert.Equal(t, "never", formatShareExpiry(nil))
}

func TestFormatShareExpiry_NonNil(t *testing.T) {
	exp, _ := resolveShareExpiry("2026-06-15T10:00:00Z", "")
	label := formatShareExpiry(exp)
	assert.Contains(t, label, "2026-06-15")
}

func TestCreateCmd_PermissionValidation(t *testing.T) {
	origPerm := createPermission
	defer func() { createPermission = origPerm }()
	createPermission = "execute"
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid permission")
}
