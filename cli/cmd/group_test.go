package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRunGroupList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 3's own test requirement): the header row
// and column values must match the old CLI's remote-mode table exactly for the
// same server response.
func TestRunGroupList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/groups" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"groups":[{"id":3,"name":"platform-team","description":"Platform engineers"}],"total":1}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runGroupList(groupListCmd, nil); err != nil {
			t.Fatalf("runGroupList: %v", err)
		}
	})

	if !containsAll(out, "ID", "NAME", "DESCRIPTION", "3", "platform-team", "Platform engineers") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunGroupCreate_RequiresName(t *testing.T) {
	groupCreateName = ""
	if err := runGroupCreate(groupCreateCmd, nil); err == nil {
		t.Fatal("expected an error when --name is omitted")
	}
}

func TestRunGroupCreate_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"data":{"id":9,"name":"new-group","description":""}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	groupCreateName = "new-group"
	defer func() { groupCreateName = "" }()

	out := captureStdout(t, func() {
		if err := runGroupCreate(groupCreateCmd, nil); err != nil {
			t.Fatalf("runGroupCreate: %v", err)
		}
	})
	if !containsAll(out, "Group created: id=9 name=new-group") {
		t.Fatalf("output missing expected confirmation, got: %q", out)
	}
}

func TestRunGroupGet_RequiresID(t *testing.T) {
	groupGetID = 0
	if err := runGroupGet(groupGetCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunGroupGet_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/groups/5" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":5,"name":"sre","description":"SRE team"}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	groupGetID = 5
	defer func() { groupGetID = 0 }()

	out := captureStdout(t, func() {
		if err := runGroupGet(groupGetCmd, nil); err != nil {
			t.Fatalf("runGroupGet: %v", err)
		}
	})
	if out != "ID: 5\nName: sre\nDescription: SRE team\n" {
		t.Fatalf("output = %q, want the old CLI's exact get format", out)
	}
}

func TestRunGroupUpdate_RequiresNameOrDescription(t *testing.T) {
	groupUpdateID = 1
	groupUpdateName = ""
	groupUpdateDescription = ""
	defer func() { groupUpdateID = 0 }()
	if err := runGroupUpdate(groupUpdateCmd, nil); err == nil {
		t.Fatal("expected an error when neither --name nor --description is set")
	}
}

func TestRunGroupMembers_EmptyPrintsZeroCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"members":[],"total":0}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	groupMembersID = 2
	defer func() { groupMembersID = 0 }()

	out := captureStdout(t, func() {
		if err := runGroupMembers(groupMembersCmd, nil); err != nil {
			t.Fatalf("runGroupMembers: %v", err)
		}
	})
	if !containsAll(out, "Group 2 — 0 member(s)", "ID", "USERNAME", "EMAIL") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunGroupAddMember_RequiresGroupAndUserID(t *testing.T) {
	groupAddMemberGroupID = 0
	groupAddMemberUserID = 0
	if err := runGroupAddMember(groupAddMemberCmd, nil); err == nil {
		t.Fatal("expected an error when --group-id/--user-id are omitted")
	}
}

func TestRunGroupAddMember_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"group_id":1,"user_id":2,"project_id":0}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	groupAddMemberGroupID, groupAddMemberUserID = 1, 2
	defer func() { groupAddMemberGroupID, groupAddMemberUserID = 0, 0 }()

	out := captureStdout(t, func() {
		if err := runGroupAddMember(groupAddMemberCmd, nil); err != nil {
			t.Fatalf("runGroupAddMember: %v", err)
		}
	})
	if out != "User 2 added to group 1 (project 0).\n" {
		t.Fatalf("output = %q, want the old CLI's exact confirmation", out)
	}
}

func TestRunGroupRemoveMember_RequiresGroupAndUserID(t *testing.T) {
	groupRemoveMemberGroupID = 0
	groupRemoveMemberUserID = 0
	if err := runGroupRemoveMember(groupRemoveMemberCmd, nil); err == nil {
		t.Fatal("expected an error when --group-id/--user-id are omitted")
	}
}

func TestRunGroupRemoveMember_SendsProjectIDQueryParam(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	groupRemoveMemberGroupID, groupRemoveMemberUserID, groupRemoveMemberProjectID = 1, 2, 7
	defer func() { groupRemoveMemberGroupID, groupRemoveMemberUserID, groupRemoveMemberProjectID = 0, 0, 0 }()

	if err := runGroupRemoveMember(groupRemoveMemberCmd, nil); err != nil {
		t.Fatalf("runGroupRemoveMember: %v", err)
	}
	if gotQuery != "project_id=7" {
		t.Fatalf("query = %q, want project_id=7 (the fixed removeGroupMember spec gap)", gotQuery)
	}
}

func TestRunGroupDelete_ForceSkipsPrompt(t *testing.T) {
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"id":4,"name":"temp-group","description":""}}`)
		case http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	groupDeleteID = 4
	groupDeleteForce = true
	defer func() { groupDeleteID, groupDeleteForce = 0, false }()

	out := captureStdout(t, func() {
		if err := runGroupDelete(groupDeleteCmd, nil); err != nil {
			t.Fatalf("runGroupDelete: %v", err)
		}
	})
	if !deleted {
		t.Fatal("expected DELETE to reach the server when --force is set")
	}
	if !containsAll(out, "Deleted group 4 (temp-group).") {
		t.Fatalf("output missing expected confirmation, got: %q", out)
	}
}
