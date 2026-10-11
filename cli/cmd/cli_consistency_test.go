package cmd

// cli_consistency_test.go: #2981. group/machine/break-glass commands read like their
// rbac siblings (names accepted, active project honoured) and a refusal is never
// reported as "nothing found".

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// groupServer serves the group + user lookups the name-based forms need and records
// every request as "METHOD path".
func groupServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+" "+string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/groups" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"groups":[{"id":3,"name":"platform-team"}],"total":1}}`)
		case r.URL.Path == "/api/v1/users":
			_, _ = fmt.Fprint(w, `{"data":{"users":[{"id":7,"username":"alice","email":"alice@example.com"}],"total":1}}`)
		case r.URL.Path == "/api/v1/groups/3" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"id":3,"name":"platform-team","description":"d"}}`)
		case r.URL.Path == "/api/v1/groups/3/members" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"members":[],"total":0}}`)
		case r.URL.Path == "/api/v1/groups/3/members" && r.Method == http.MethodPost:
			_, _ = fmt.Fprint(w, `{"data":{}}`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/groups/3/members/7") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func resetGroupFlags() {
	groupGetID, groupMembersID = 0, 0
	groupAddMemberGroupID, groupAddMemberGroup, groupAddMemberUserID, groupAddMemberUser, groupAddMemberProjectID = 0, "", 0, "", 0
	groupRemoveMemberGroupID, groupRemoveMemberGroup, groupRemoveMemberUserID, groupRemoveMemberUser, groupRemoveMemberProjectID = 0, "", 0, "", 0
}

func TestGroupGet_AcceptsGroupNamePositionally(t *testing.T) {
	srv, seen := groupServer(t)
	setPATCreds(t, srv)
	resetGroupFlags()
	out := captureStdout(t, func() {
		if err := runGroupGet(groupGetCmd, []string{"platform-team"}); err != nil {
			t.Fatalf("group get platform-team: %v", err)
		}
	})
	if !strings.Contains(out, "Name: platform-team") {
		t.Fatalf("output = %q", out)
	}
	if got := strings.Join(seen(), "\n"); !strings.Contains(got, "GET /api/v1/groups/3 ") {
		t.Fatalf("name was not resolved to id 3; requests:\n%s", got)
	}
}

func TestGroupMembers_AcceptsGroupNamePositionally(t *testing.T) {
	srv, _ := groupServer(t)
	setPATCreds(t, srv)
	resetGroupFlags()
	out := captureStdout(t, func() {
		if err := runGroupMembers(groupMembersCmd, []string{"platform-team"}); err != nil {
			t.Fatalf("group members platform-team: %v", err)
		}
	})
	if !strings.Contains(out, "Group 3 — 0 member(s)") {
		t.Fatalf("output = %q", out)
	}
}

func TestGroupAddMember_GroupNameAndUsername(t *testing.T) {
	srv, seen := groupServer(t)
	setPATCreds(t, srv)
	resetGroupFlags()
	groupAddMemberUser = "alice"
	defer resetGroupFlags()
	out := captureStdout(t, func() {
		if err := runGroupAddMember(groupAddMemberCmd, []string{"platform-team"}); err != nil {
			t.Fatalf("group add-member platform-team --user alice: %v", err)
		}
	})
	if !strings.Contains(out, "User 7 added to group 3") {
		t.Fatalf("output = %q", out)
	}
	if got := strings.Join(seen(), "\n"); !strings.Contains(got, `POST /api/v1/groups/3/members {"user_id":7}`) {
		t.Fatalf("add-member request wrong; requests:\n%s", got)
	}
}

func TestGroupAddMember_UserByEmailAndGroupFlag(t *testing.T) {
	srv, _ := groupServer(t)
	setPATCreds(t, srv)
	resetGroupFlags()
	groupAddMemberGroup, groupAddMemberUser = "platform-team", "alice@example.com"
	defer resetGroupFlags()
	out := captureStdout(t, func() {
		if err := runGroupAddMember(groupAddMemberCmd, nil); err != nil {
			t.Fatalf("add-member --group --user email: %v", err)
		}
	})
	if !strings.Contains(out, "User 7 added to group 3") {
		t.Fatalf("output = %q", out)
	}
}

func TestGroupRemoveMember_GroupNameAndUsername(t *testing.T) {
	srv, _ := groupServer(t)
	setPATCreds(t, srv)
	resetGroupFlags()
	groupRemoveMemberUser = "alice"
	defer resetGroupFlags()
	out := captureStdout(t, func() {
		if err := runGroupRemoveMember(groupRemoveMemberCmd, []string{"platform-team"}); err != nil {
			t.Fatalf("group remove-member: %v", err)
		}
	})
	if !strings.Contains(out, "User 7 removed from group 3") {
		t.Fatalf("output = %q", out)
	}
}

// The numeric forms that worked before keep working and need no name lookup.
func TestGroupAddMember_NumericFlagsStillWork(t *testing.T) {
	srv, seen := groupServer(t)
	setPATCreds(t, srv)
	resetGroupFlags()
	groupAddMemberGroupID, groupAddMemberUserID = 3, 7
	defer resetGroupFlags()
	_ = captureStdout(t, func() {
		if err := runGroupAddMember(groupAddMemberCmd, nil); err != nil {
			t.Fatalf("add-member --group-id --user-id: %v", err)
		}
	})
	for _, r := range seen() {
		if strings.Contains(r, "/api/v1/users") || r == "GET /api/v1/groups " {
			t.Fatalf("numeric ids triggered a name lookup: %s", r)
		}
	}
}

func TestGroupCommands_MissingGroupSaysHowToGiveOne(t *testing.T) {
	resetGroupFlags()
	err := runGroupMembers(groupMembersCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "group is required") {
		t.Fatalf("err = %v, want a 'group is required' message", err)
	}
	groupAddMemberGroup = "platform-team"
	defer resetGroupFlags()
	err = runGroupAddMember(groupAddMemberCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "user is required") {
		t.Fatalf("err = %v, want a 'user is required' message", err)
	}
}

func TestMachineTokenRevoke_OneArgSaysWhatIsMissing(t *testing.T) {
	err := machineTokenRevokeArgs(machineTokenRevokeCmd, []string{"1"})
	if err == nil || !strings.Contains(err.Error(), "token id") || strings.Contains(err.Error(), "accepts 2 arg(s)") {
		t.Fatalf("err = %v, want a message naming the missing token id", err)
	}
	if err := machineTokenRevokeArgs(machineTokenRevokeCmd, []string{"ci-app", "4"}); err != nil {
		t.Fatalf("two args must be accepted: %v", err)
	}
}

func TestMachineProject_FallsBackToActiveProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/projects" {
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":4,"name":"backend-api"}],"total":1}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	t.Setenv("KEYORIX_PROJECT", "backend-api") // stands in for `project use` / the env var

	client, err := machineAPIClient()
	if err != nil {
		t.Fatal(err)
	}
	name, id, err := resolveMachineProjectID(client, "")
	if err != nil || name != "backend-api" || id != 4 {
		t.Fatalf("resolveMachineProjectID = (%q, %d, %v), want (backend-api, 4, nil)", name, id, err)
	}
	t.Setenv("KEYORIX_PROJECT", "")
	t.Setenv("HOME", t.TempDir())
	if _, _, err := resolveMachineProjectID(client, ""); err == nil || !strings.Contains(err.Error(), "project use") {
		t.Fatalf("err = %v, want the no-project message to mention `keyorix project use`", err)
	}
}

// A refused list must not read as an empty one: alice's own list said "No break-glass
// activations" while the admin's showed hers (#2981).
func TestRunBGList_RefusalIsNotReportedAsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":"PermissionDenied","message":"permission denied: roles.read required"}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)
	bgProject = 2
	defer func() { bgProject = 0 }()

	var err error
	out := captureStdout(t, func() { err = runBGList(bgListCmd, nil) })
	if err == nil || !strings.Contains(err.Error(), "roles.read required") {
		t.Fatalf("err = %v, want the server's refusal", err)
	}
	if strings.Contains(out, "No break-glass activations") {
		t.Fatalf("a 403 was reported as an empty list: %q", out)
	}
}

// The non-member refusal reaches the operator with its reason (#2937's generic
// mechanism applied to break-glass) and tells them what to do.
func TestRunBGActivate_NonMemberRefusalShowsReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":"Error","message":"permission denied: break-glass is available only to members of the project"}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)
	bgProject, bgJustify = 1, "incident INC-1 database down"
	defer func() { bgProject, bgJustify = 0, "" }()

	err := runBGActivate(bgActivateCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "only to members of the project") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want the member-only reason and the status", err)
	}
}
