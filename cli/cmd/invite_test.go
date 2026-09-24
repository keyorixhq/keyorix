package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// inviteTestServer wires a project-list handler (so resolveInviteProjectID
// resolves "test-project" -> id 1) plus a caller-supplied handler for the
// invitation-specific route under test.
func inviteTestServer(t *testing.T, path string, method string, respond func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":1,"name":"test-project"}]}}`)
			return
		}
		if r.URL.Path == path && r.Method == method {
			respond(w)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunInviteSend_RequiresEmailAndRole(t *testing.T) {
	inviteSendEmail = ""
	inviteSendRole = ""
	if err := runInviteSend(inviteSendCmd, nil); err == nil {
		t.Fatal("expected an error when --email/--role are omitted")
	}
}

func TestRunInviteSend_MatchesOldCLIOutputShape(t *testing.T) {
	srv := inviteTestServer(t, "/api/v1/projects/1/invitations", http.MethodPost, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"data":{"invitation":{"ID":8,"Email":"new@example.test","Role":"viewer","ExpiresAt":null},"setup_link":{"email":"new@example.test","channel":"out_of_band","delivered":false,"link_for_admin":"https://x/accept/tok"}}}`)
	})
	setPATCreds(t, srv)
	inviteSendProject, inviteSendEmail, inviteSendRole = "test-project", "new@example.test", "viewer"
	defer func() { inviteSendProject, inviteSendEmail, inviteSendRole = "", "", "" }()

	out := captureStdout(t, func() {
		if err := runInviteSend(inviteSendCmd, nil); err != nil {
			t.Fatalf("runInviteSend: %v", err)
		}
	})
	if !containsAll(out, "Invitation sent: id=8 email=new@example.test role=viewer project=test-project",
		"Setup link (relay this to new@example.test securely", "https://x/accept/tok") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunInviteList_EmptyPrintsNoInvitationsMessage(t *testing.T) {
	srv := inviteTestServer(t, "/api/v1/projects/1/invitations", http.MethodGet, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"invitations":[]}}`)
	})
	setPATCreds(t, srv)
	inviteListProject = "test-project"
	defer func() { inviteListProject = "" }()

	out := captureStdout(t, func() {
		if err := runInviteList(inviteListCmd, nil); err != nil {
			t.Fatalf("runInviteList: %v", err)
		}
	})
	if !containsAll(out, "No invitations found.") {
		t.Fatalf("output missing the empty-state message, got: %q", out)
	}
}

func TestRunInviteList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := inviteTestServer(t, "/api/v1/projects/1/invitations", http.MethodGet, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"invitations":[{"ID":3,"Email":"pending@example.test","Role":"editor","State":"pending","ExpiresAt":null}]}}`)
	})
	setPATCreds(t, srv)
	inviteListProject = "test-project"
	defer func() { inviteListProject = "" }()

	out := captureStdout(t, func() {
		if err := runInviteList(inviteListCmd, nil); err != nil {
			t.Fatalf("runInviteList: %v", err)
		}
	})
	if !containsAll(out, "ID", "EMAIL", "ROLE", "STATE", "EXPIRES", "3", "pending@example.test", "editor", "pending") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunInviteRevoke_RequiresID(t *testing.T) {
	inviteRevokeID = 0
	if err := runInviteRevoke(inviteRevokeCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunInviteRevoke_MatchesOldCLIOutputShape(t *testing.T) {
	srv := inviteTestServer(t, "/api/v1/projects/1/invitations/3", http.MethodDelete, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":null,"message":"Invitation revoked"}`)
	})
	setPATCreds(t, srv)
	inviteRevokeID, inviteRevokeProject = 3, "test-project"
	defer func() { inviteRevokeID, inviteRevokeProject = 0, "" }()

	out := captureStdout(t, func() {
		if err := runInviteRevoke(inviteRevokeCmd, nil); err != nil {
			t.Fatalf("runInviteRevoke: %v", err)
		}
	})
	if !containsAll(out, "Invitation 3 revoked.") {
		t.Fatalf("output missing expected confirmation, got: %q", out)
	}
}

func TestRunInviteResend_RequiresID(t *testing.T) {
	inviteResendID = 0
	if err := runInviteResend(inviteResendCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunInviteResend_MatchesOldCLIOutputShape(t *testing.T) {
	srv := inviteTestServer(t, "/api/v1/projects/1/invitations/3/resend", http.MethodPost, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"setup_link":{"email":"pending@example.test","channel":"smtp","delivered":true}}}`)
	})
	setPATCreds(t, srv)
	inviteResendID, inviteResendProject = 3, "test-project"
	defer func() { inviteResendID, inviteResendProject = 0, "" }()

	out := captureStdout(t, func() {
		if err := runInviteResend(inviteResendCmd, nil); err != nil {
			t.Fatalf("runInviteResend: %v", err)
		}
	})
	if !containsAll(out, "Invitation link reissued for invitation 3.", "Setup link delivered to pending@example.test via smtp.") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}
