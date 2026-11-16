package config

import (
	"strings"
	"testing"
)

// The rejected bind host may be an expanded ${VAR} secret; the error must name
// the field, not the value.
func TestValidateBindHost_DoesNotEchoValue(t *testing.T) {
	err := validateBindHost("server.http.host", "canary-secret-host-value")
	if err == nil {
		t.Fatal("non-IP host must be rejected")
	}
	if strings.Contains(err.Error(), "canary-secret-host-value") {
		t.Fatalf("error echoes the rejected value: %v", err)
	}
	if !strings.Contains(err.Error(), "server.http.host") || !strings.Contains(err.Error(), "is not an IP address") {
		t.Fatalf("error lost field name or stable text: %v", err)
	}
}
