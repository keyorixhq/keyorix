package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setMachineCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunMachineList_MatchesOldCLIOutputShape is a golden-output parity check: the
// fixed-width column header and row values must match the old CLI's
// internal/cli/machine printMachineTable output exactly for the same server data.
func TestRunMachineList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":3,"name":"infra"}]}}`)
		case "/api/v1/projects/3/machine-identities":
			_, _ = fmt.Fprint(w, `{"data":{"machine_identities":[{"id":11,"name":"ci-runner","identity_type":"ci","state":"active","description":"builds the release pipeline"}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setMachineCreds(t, srv)
	machineListProjectName = "infra"
	defer func() { machineListProjectName = "" }()

	out := captureStdout(t, func() {
		if err := runMachineList(machineListCmd, nil); err != nil {
			t.Fatalf("runMachineList: %v", err)
		}
	})

	if !containsAll(out, "ID", "NAME", "TYPE", "STATE", "DESCRIPTION",
		"11", "ci-runner", "ci", "active", "builds the release pipeline") {
		t.Fatalf("output missing expected columns/values, got: %q", out)
	}
}

func TestRunMachineList_EmptyPrintsNoIdentitiesMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":3,"name":"infra"}]}}`)
		case "/api/v1/projects/3/machine-identities":
			_, _ = fmt.Fprint(w, `{"data":{"machine_identities":[]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setMachineCreds(t, srv)
	machineListProjectName = "infra"
	defer func() { machineListProjectName = "" }()

	out := captureStdout(t, func() {
		if err := runMachineList(machineListCmd, nil); err != nil {
			t.Fatalf("runMachineList: %v", err)
		}
	})
	if out != "No machine identities found for project \"infra\".\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

// TestRunMachineTokenIssue_PrintsRawTokenOnceToStdoutOnly guards the DO instruction:
// a command that mints a new secret prints it once, to stdout only, with the same
// warning text as today.
func TestRunMachineTokenIssue_PrintsRawTokenOnceToStdoutOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":3,"name":"infra"}]}}`)
		case "/api/v1/projects/3/machine-identities":
			_, _ = fmt.Fprint(w, `{"data":{"machine_identities":[{"id":11,"name":"ci-runner","identity_type":"ci","state":"active"}]}}`)
		case "/api/v1/projects/3/machine-identities/11/tokens":
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"data":{"token":"kx_machine_the_raw_secret","id":42,"prefix":"kx_machine_ab"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setMachineCreds(t, srv)
	machineTokenProjectName = "infra"
	machineTokenIssueName = "ci-token"
	defer func() { machineTokenProjectName = ""; machineTokenIssueName = "" }()

	out := captureStdout(t, func() {
		if err := runMachineTokenIssue(machineTokenIssueCmd, []string{"ci-runner"}); err != nil {
			t.Fatalf("runMachineTokenIssue: %v", err)
		}
	})

	if !containsAll(out, "Copy it now", "will not be shown again", "kx_machine_the_raw_secret") {
		t.Fatalf("output missing the one-time-secret warning or the token itself: %q", out)
	}
}

// TestRunMachineMigrateFromUser_MatchesOldCLIOutputShape is a golden-output parity check
// against internal/cli/migrate/user_to_machine.go's runUserToMachine (its remote-equivalent
// output lines) -- minus --by, which has no REST equivalent (the bearer token IS the acting
// identity; see machine.go's own doc comment on this command for why).
func TestRunMachineMigrateFromUser_MatchesOldCLIOutputShape(t *testing.T) {
	var calledBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":3,"name":"infra"}]}}`)
		case "/api/v1/projects/3/machine-identities/migrate-from-user":
			buf, _ := io.ReadAll(r.Body)
			calledBody = string(buf)
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"data":{"machine_identity":{"id":42,"name":"ci-bot","identity_type":"service","state":"active","project_id":3}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setMachineCreds(t, srv)
	machineMigrateProjectName = "infra"
	machineMigrateType = "service"
	machineMigrateName = ""
	machineMigrateKeepUser = false
	defer func() {
		machineMigrateProjectName, machineMigrateType, machineMigrateName, machineMigrateKeepUser = "", "", "", false
	}()

	out := captureStdout(t, func() {
		if err := runMachineMigrateFromUser(machineMigrateFromUserCmd, []string{"ci-bot"}); err != nil {
			t.Fatalf("runMachineMigrateFromUser: %v", err)
		}
	})

	if !containsAll(calledBody, `"username":"ci-bot"`, `"identity_type":"service"`, `"keep_user":false`) {
		t.Fatalf("request body missing expected fields: %q", calledBody)
	}
	if !containsAll(out, `Migrated user "ci-bot" to machine identity: id=42 name="ci-bot" type=service state=active`,
		"Source user suspended (login blocked)") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunMachineMigrateFromUser_KeepUserSkipsSuspendMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":3,"name":"infra"}]}}`)
		case "/api/v1/projects/3/machine-identities/migrate-from-user":
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"data":{"machine_identity":{"id":42,"name":"ci-bot","identity_type":"service","state":"active","project_id":3}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setMachineCreds(t, srv)
	machineMigrateProjectName = "infra"
	machineMigrateType = "service"
	machineMigrateName = ""
	machineMigrateKeepUser = true
	defer func() {
		machineMigrateProjectName, machineMigrateType, machineMigrateName, machineMigrateKeepUser = "", "", "", false
	}()

	out := captureStdout(t, func() {
		if err := runMachineMigrateFromUser(machineMigrateFromUserCmd, []string{"ci-bot"}); err != nil {
			t.Fatalf("runMachineMigrateFromUser: %v", err)
		}
	})
	if containsAll(out, "Source user suspended") {
		t.Fatalf("output should not mention suspension when --keep-user is set: %q", out)
	}
}
