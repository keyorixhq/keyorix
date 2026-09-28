package healthscan

import (
	"context"
	"strings"
	"testing"
)

func TestCheckAuthMethods_UserpassOnlyIsMedium(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/auth": `{"data":{"token/":{"type":"token"},"userpass/":{"type":"userpass"}}}`,
	})
	res := checkAuthMethods(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityMedium {
		t.Fatalf("expected medium for userpass-only, got %+v", res)
	}
}

func TestCheckAuthMethods_WithAppRoleAndOIDC(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/auth": `{"data":{"token/":{"type":"token"},"approle/":{"type":"approle"},"oidc/":{"type":"oidc"}}}`,
	})
	res := checkAuthMethods(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info when AppRole+OIDC are present, got %+v", res)
	}
	if !strings.Contains(res.Finding.Remediation, "OIDC is enabled") {
		t.Errorf("expected a positive OIDC note, got %q", res.Finding.Remediation)
	}
}

func TestCheckAppRoleSecretIDHygiene_FlagsUnboundedRoles(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/auth":                    `{"data":{"approle/":{"type":"approle"}}}`,
		"/v1/auth/approle/role":           `{"data":{"keys":["ci-runner","bounded"]}}`,
		"/v1/auth/approle/role/ci-runner": `{"data":{"secret_id_ttl":0,"secret_id_num_uses":0}}`,
		"/v1/auth/approle/role/bounded":   `{"data":{"secret_id_ttl":3600,"secret_id_num_uses":1}}`,
	})
	res := checkAppRoleSecretIDHygiene(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityMedium {
		t.Fatalf("expected medium when a role has secret_id_ttl=0, got %+v", res)
	}
	if !strings.Contains(res.Finding.Evidence, "2 roles inspected") {
		t.Errorf("evidence = %q, want both roles counted", res.Finding.Evidence)
	}
}

func TestCheckAppRoleSecretIDHygiene_NoAppRole(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/auth": `{"data":{"token/":{"type":"token"}}}`})
	res := checkAppRoleSecretIDHygiene(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info when no AppRole mount exists, got %+v", res)
	}
}
