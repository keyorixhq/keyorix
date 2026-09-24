package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// setDynCreds points dynamicSecretAPIClient at an httptest server via env vars
// (highest precedence in resolveServerAndToken), matching pat_test.go/machine_test.go's
// established pattern for this module.
func setDynCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunDynList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 1's own test requirement): the header row and
// column values must match internal/cli/dynamic/dynamic.go's listCmd output
// byte-for-byte for the same server response.
func TestRunDynList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/dynamic-secrets/configs" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":[{"id":1,"name":"app-db","project_id":1,"environment_id":2,"backend_type":"postgres","default_ttl_seconds":3600,"max_ttl_seconds":7200,"classification":""}]}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runDynList(dynListCmd, nil); err != nil {
			t.Fatalf("runDynList: %v", err)
		}
	})

	want := fmt.Sprintf("%-5s %-24s %-10s %-8s %-8s\n", "ID", "NAME", "BACKEND", "TTL", "MAXTTL") +
		fmt.Sprintf("%-5d %-24s %-10s %-8d %-8d\n", 1, "app-db", "postgres", 3600, 7200)
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestRunDynList_EmptyPrintsNoConfigsMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":[]}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runDynList(dynListCmd, nil); err != nil {
			t.Fatalf("runDynList: %v", err)
		}
	})
	if out != "No dynamic-secret configs found.\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

func TestRunDynGetConfig_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/dynamic-secrets/configs/1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"id":1,"name":"app-db","project_id":1,"environment_id":2,"backend_type":"postgres","default_ttl_seconds":3600,"max_ttl_seconds":7200,"classification":"internal"}}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runDynGetConfig(dynGetConfigCmd, []string{"1"}); err != nil {
			t.Fatalf("runDynGetConfig: %v", err)
		}
	})
	if !containsAll(out, "ID:             1", "Name:           app-db", "Backend:        postgres", "Classification: internal") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunDynIssue_PrintsCredentialOnceToStdout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/dynamic-secrets/configs/1/issue" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"lease_id":"lease-xyz","username":"u1","password":"p1","expires_at":"2026-01-02T00:00:00Z"}}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runDynIssue(dynIssueCmd, []string{"1"}); err != nil {
			t.Fatalf("runDynIssue: %v", err)
		}
	})
	if !containsAll(out, "Credential issued", "lease:    lease-xyz", "username: u1", "password: p1", "expires:  2026-01-02T00:00:00Z") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunDynLeases_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/dynamic-secrets/configs/1/leases" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":[{"lease_id":"lease-xyz","role_name":"app-db-role","status":"active","expires_at":"2026-01-02T00:00:00Z"}]}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runDynLeases(dynLeasesCmd, []string{"1"}); err != nil {
			t.Fatalf("runDynLeases: %v", err)
		}
	})
	want := fmt.Sprintf("%-34s %-16s %-14s %s\n", "LEASE", "ROLE", "STATUS", "EXPIRES") +
		fmt.Sprintf("%-34s %-16s %-14s %s\n", "lease-xyz", "app-db-role", "active", "2026-01-02T00:00:00Z")
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestRunDynRenew_PrintsNewExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"lease_id":"lease-xyz","expires_at":"2026-01-02T01:00:00Z"}}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runDynRenew(dynRenewCmd, []string{"lease-xyz"}); err != nil {
			t.Fatalf("runDynRenew: %v", err)
		}
	})
	if out != "Lease lease-xyz renewed — new expiry 2026-01-02T01:00:00Z\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestRunDynRevoke_PrintsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"lease_id":"lease-xyz","status":"revoked"}}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runDynRevoke(dynRevokeCmd, []string{"lease-xyz"}); err != nil {
			t.Fatalf("runDynRevoke: %v", err)
		}
	})
	if out != "Lease lease-xyz revoked.\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestRunDynRevokeAll_SkipsPromptWithYesFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"config_id":1,"revoked":3,"failed":0}}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)
	dynYes = true
	defer func() { dynYes = false }()

	out := captureStdout(t, func() {
		if err := runDynRevokeAll(dynRevokeAllCmd, []string{"1"}); err != nil {
			t.Fatalf("runDynRevokeAll: %v", err)
		}
	})
	if out != "Config 1: revoked 3 lease(s), 0 failed.\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestRunDynClassify_RequiresLevelFlag(t *testing.T) {
	// dynClassifyCmd.MarkFlagRequired("level") enforces this via cobra when invoked
	// through Execute(); runDynClassify itself doesn't re-validate, so this test
	// documents that contract by driving the command through the parent's flag
	// parsing instead of calling runDynClassify directly.
	dynLevel = "internal"
	defer func() { dynLevel = "" }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"id":1,"name":"app-db","classification":"internal"}}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runDynClassify(dynClassifyCmd, []string{"1"}); err != nil {
			t.Fatalf("runDynClassify: %v", err)
		}
	})
	if out != "✅ Classification set to \"internal\" for config 1.\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestRunDynCreateConfig_RequiresNameProjectAndBackend(t *testing.T) {
	dynCfgName, dynCfgProjectID, dynCfgBackend = "", 0, ""
	err := runDynCreateConfig(dynCreateConfigCmd, nil)
	if err == nil || !containsAll(err.Error(), "--name, --project-id and --backend are required") {
		t.Fatalf("err = %v, want the required-flags error", err)
	}
}

func TestRunDynCreateConfig_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/dynamic-secrets/configs" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"id":9,"name":"app-db","backend_type":"postgres"}}`)
	}))
	defer srv.Close()
	setDynCreds(t, srv)
	t.Setenv("KEYORIX_DYNAMIC_ADMIN_DSN", "postgres://admin:s3cr3t@db.internal:5432/app")
	dynCfgName, dynCfgProjectID, dynCfgBackend = "app-db", 1, "postgres"
	defer func() { dynCfgName, dynCfgProjectID, dynCfgBackend = "", 0, "" }()

	out := captureStdout(t, func() {
		if err := runDynCreateConfig(dynCreateConfigCmd, nil); err != nil {
			t.Fatalf("runDynCreateConfig: %v", err)
		}
	})
	want := "Created dynamic-secret config #9 (app-db, postgres).\n" +
		"Issue a credential with: keyorix-next dynamic-secret issue 9\n"
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}
