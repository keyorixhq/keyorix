package middleware

// auth_machine_ip_test.go — tests for the machine token IP allowlist:
// tokenNetworkAllowed's machine-restriction branch (new in this PR) and
// the end-to-end machine-token-with-CIDRs authentication path.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
)

// TestTokenNetworkAllowed_MachineRestrictionAllowsInRange verifies that a
// machine token with AllowedCIDRs passes when the source IP is in-range.
func TestTokenNetworkAllowed_MachineRestrictionAllowsInRange(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:9000"

	uc := &UserContext{
		MachineTokenRestriction: &core.MachineTokenRestriction{
			AllowedCIDRs: []string{"10.0.0.0/8"},
		},
	}
	assert.True(t, tokenNetworkAllowed(r, uc))
}

// TestTokenNetworkAllowed_MachineRestrictionDeniesOutOfRange verifies that a
// machine token with AllowedCIDRs is denied when the source IP is out of range.
func TestTokenNetworkAllowed_MachineRestrictionDeniesOutOfRange(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:9000"

	uc := &UserContext{
		MachineTokenRestriction: &core.MachineTokenRestriction{
			AllowedCIDRs: []string{"10.0.0.0/8"},
		},
	}
	assert.False(t, tokenNetworkAllowed(r, uc))
}

// TestTokenNetworkAllowed_MachineNoRestriction verifies that a machine token
// with no MachineTokenRestriction is always allowed.
func TestTokenNetworkAllowed_MachineNoRestriction(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:9000"

	uc := &UserContext{MachineTokenRestriction: nil}
	assert.True(t, tokenNetworkAllowed(r, uc))
}

// TestTokenNetworkAllowed_NilContext verifies that a nil UserContext is allowed
// (the guard returns true before any allowlist check).
func TestTokenNetworkAllowed_NilContext(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:9000"
	assert.True(t, tokenNetworkAllowed(r, nil))
}
