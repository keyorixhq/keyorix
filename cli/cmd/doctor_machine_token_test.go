package cmd

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// #4279: a machine token has no user row, so GET /api/v1/auth/profile answers it 404
// (server/http/handlers/auth.go Profile). doctor reported that as an auth FAIL for a
// perfectly valid token. The 404 is only "not applicable" for a machine token: for a
// user session or a PAT it still means the account is gone.
func TestDoctor_AuthCheckByTokenKind(t *testing.T) {
	const notFound = `{"error":"NotFound","message":"User not found"}`
	const unauthorized = `{"error":"Unauthorized","message":"invalid token"}`
	cases := []struct {
		name       string
		token      string
		status     int
		body       string
		wantStatus string
		wantDetail string
	}{
		{"machine token, profile 404", "kx_machine_abc123def456", 404, notFound, doctorPass, "machine token: profile not applicable"},
		{"machine token rejected", "kx_machine_abc123def456", 401, unauthorized, doctorFail, "rejected the token"},
		{"machine token, server error", "kx_machine_abc123def456", 500, `{}`, doctorFail, "HTTP 500"},
		{"user login, profile 404", "session-token-value", 404, notFound, doctorFail, "HTTP 404"},
		{"PAT, profile 404", "kx_pat_abc123def456", 404, notFound, doctorFail, "HTTP 404"},
		{"user login, profile 200", "session-token-value", 200, `{"data":{"username":"alice","roles":["admin"]}}`, doctorPass, "logged in as alice"},
		{"PAT, profile 200", "kx_pat_abc123def456", 200, `{"data":{"username":"alice","roles":["admin"]}}`, doctorPass, "logged in as alice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := healthyDoctorServer()
			d.profileStatus, d.profileBody = c.status, c.body
			srv := httptest.NewServer(d.handler())
			defer srv.Close()
			useServer(t, srv.URL, c.token)

			rep := runDoctorReport(t)
			got := rep.check(t, "auth")
			if got.Status != c.wantStatus || !strings.Contains(got.Detail, c.wantDetail) {
				t.Fatalf("auth = %s %q (next: %q), want %s containing %q", got.Status, got.Detail, got.NextStep, c.wantStatus, c.wantDetail)
			}
			if strings.Contains(got.Detail, c.token) {
				t.Fatalf("the token leaked into the auth line: %q", got.Detail)
			}
			// The audit check hangs off a working login: a valid machine token must reach it.
			if c.wantStatus == doctorPass {
				if a := rep.check(t, "audit"); a.Status == doctorSkip {
					t.Fatalf("audit was skipped although auth passed: %+v", a)
				}
			}
		})
	}
}
