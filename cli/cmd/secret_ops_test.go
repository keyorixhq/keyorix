package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// secretOpsRoute is one (method, path) -> responder pair for secretOpsServer.
type secretOpsRoute struct {
	method, path string
	respond      func(w http.ResponseWriter, r *http.Request)
}

func jsonRoute(method, path, body string) secretOpsRoute {
	return secretOpsRoute{method, path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}}
}

// secretOpsServer dispatches to the first matching (method, path) route --
// many of these commands each need their own small fixture.
func secretOpsServer(t *testing.T, routes ...secretOpsRoute) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, route := range routes {
			if r.Method == route.method && r.URL.Path == route.path {
				route.respond(w, r)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ── versions / diff / rollback / comments ───────────────────────────────────────

func TestRunSecretVersions_RequiresID(t *testing.T) {
	secretVersionsID = 0
	if err := runSecretVersions(secretVersionsCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretVersions_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t,
		jsonRoute(http.MethodGet, "/api/v1/secrets/1", `{"data":{"ID":1,"Name":"db-pass","Type":"generic"}}`),
		jsonRoute(http.MethodGet, "/api/v1/secrets/1/versions", `{"data":{"versions":[{"ID":9,"VersionNumber":2,"ReadCount":3,"CreatedAt":"2026-01-02T00:00:00Z"}]}}`),
	)
	setPATCreds(t, srv)
	secretVersionsID, secretVersionsFormat = 1, "table"
	defer func() { secretVersionsID = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretVersions(secretVersionsCmd, nil); err != nil {
			t.Fatalf("runSecretVersions: %v", err)
		}
	})
	if !containsAll(out, "db-pass", "VERSION", "READS", "2", "3") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretDiff_RequiresProjectAndEnvironmentWithoutID(t *testing.T) {
	secretDiffID, secretDiffProject, secretDiffEnv = 0, 0, 0
	if err := runSecretDiff(secretDiffCmd, []string{"my-secret", "1", "2"}); err == nil {
		t.Fatal("expected an error when --project/--environment are omitted and --id is unset")
	}
}

func TestRunSecretDiff_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t,
		jsonRoute(http.MethodGet, "/api/v1/secrets/1/versions/1/diff/2",
			`{"data":{"secret_name":"db-pass","from_version":1,"to_version":2,"changes":[{"field":"classification","old_value":"","new_value":"confidential"}],"acl_user_ids":[7],"degraded":false}}`),
	)
	setPATCreds(t, srv)
	secretDiffID = 1
	defer func() { secretDiffID = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretDiff(secretDiffCmd, []string{"db-pass", "1", "2"}); err != nil {
			t.Fatalf("runSecretDiff: %v", err)
		}
	})
	if !containsAll(out, "db-pass", "v1 -> v2", "classification", "confidential", "users [7]") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretRollback_RequiresIDAndVersion(t *testing.T) {
	secretRollbackID, secretRollbackVersion = 0, 0
	if err := secretRollbackCmd.RunE(secretRollbackCmd, nil); err == nil {
		t.Fatal("expected an error when --id/--version are omitted")
	}
}

func TestVersionCommentAdd_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t,
		jsonRoute(http.MethodPost, "/api/v1/secrets/1/versions/2/comments", `{"data":{"id":5,"comment":"rotated","username":"alice","created_at":"2026-01-02T00:00:00Z"}}`),
	)
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := versionCommentAddCmd.RunE(versionCommentAddCmd, []string{"1", "2", "rotated"}); err != nil {
			t.Fatalf("versionCommentAddCmd: %v", err)
		}
	})
	if !containsAll(out, "Comment added (id=5)", "alice") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── acl ─────────────────────────────────────────────────────────────────────────

func TestSecretACLList_EmptyPrintsNoGrantsMessage(t *testing.T) {
	srv := secretOpsServer(t, jsonRoute(http.MethodGet, "/api/v1/secrets/1/acl", `{"data":[]}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := secretACLListCmd.RunE(secretACLListCmd, []string{"1"}); err != nil {
			t.Fatalf("secretACLListCmd: %v", err)
		}
	})
	if !containsAll(out, "No ACL grants for this secret.") {
		t.Fatalf("output missing the empty-state message, got: %q", out)
	}
}

func TestSecretACLGrant_RequiresUserAndPerm(t *testing.T) {
	secretACLGrantSecret, secretACLGrantUser, secretACLGrantPerms = 1, 0, nil
	if err := secretACLGrantCmd.RunE(secretACLGrantCmd, nil); err == nil {
		t.Fatal("expected an error when --user/--perm are omitted")
	}
}

// ── folder ──────────────────────────────────────────────────────────────────────

func TestSecretFolderCreate_RequiresName(t *testing.T) {
	secretFolderCreateName = ""
	if err := runSecretFolderCreate(secretFolderCreateCmd, nil); err == nil {
		t.Fatal("expected an error when --name is omitted")
	}
}

func TestSecretFolderList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, jsonRoute(http.MethodGet, "/api/v1/folders", `{"data":[{"ID":3,"Name":"db-creds","ProjectID":1,"EnvironmentID":1}]}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runSecretFolderList(secretFolderListCmd, nil); err != nil {
			t.Fatalf("runSecretFolderList: %v", err)
		}
	})
	if !containsAll(out, "db-creds", "3") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── move / copy / copy-environment ──────────────────────────────────────────────

func TestSecretMove_RequiresID(t *testing.T) {
	secretMoveID = 0
	if err := secretMoveCmd.RunE(secretMoveCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestSecretCopy_RequiresIDAndTargetEnv(t *testing.T) {
	secretCopyID, secretCopyToEnv = 0, 0
	if err := secretCopyCmd.RunE(secretCopyCmd, nil); err == nil {
		t.Fatal("expected an error when --id/--to-environment are omitted")
	}
}

func TestSecretCopyEnvironment_FromAndToMustDiffer(t *testing.T) {
	secretCopyEnvProject, secretCopyEnvFrom, secretCopyEnvTo = 1, 2, 2
	defer func() { secretCopyEnvProject, secretCopyEnvFrom, secretCopyEnvTo = 0, 0, 0 }()
	if err := secretCopyEnvironmentCmd.RunE(secretCopyEnvironmentCmd, nil); err == nil {
		t.Fatal("expected an error when --from-environment equals --to-environment")
	}
}

// ── deps ────────────────────────────────────────────────────────────────────────

func TestSecretDepsList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, jsonRoute(http.MethodGet, "/api/v1/secrets/1/dependencies",
		`{"data":{"secret_id":1,"depends_on":[{"id":2,"secret_id":5,"secret_name":"db-root","note":"rotation source"}],"dependents":[]}}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := secretDepsListCmd.RunE(secretDepsListCmd, []string{"1"}); err != nil {
			t.Fatalf("secretDepsListCmd: %v", err)
		}
	})
	if !containsAll(out, "Depends on (1)", "db-root", "rotation source", "Used by (0)") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestSecretDepsImpact_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, jsonRoute(http.MethodGet, "/api/v1/secrets/1/impact",
		`{"data":{"secret_id":1,"secret_name":"db-root","affected":[{"secret_id":9,"secret_name":"app-conn","depth":1}]}}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := secretDepsImpactCmd.RunE(secretDepsImpactCmd, []string{"1"}); err != nil {
			t.Fatalf("secretDepsImpactCmd: %v", err)
		}
	})
	if !containsAll(out, "db-root", "affects 1 secret(s)", "app-conn", "1 hop") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── access / access-log ──────────────────────────────────────────────────────────

func TestSecretAccess_RequiresID(t *testing.T) {
	secretAccessID = 0
	if err := secretAccessCmd.RunE(secretAccessCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestSecretAccess_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, jsonRoute(http.MethodGet, "/api/v1/secrets/1/access",
		`{"data":{"accessors":[{"username":"alice","permission":"read","source":"owner"}]}}`))
	setPATCreds(t, srv)
	secretAccessID = 1
	defer func() { secretAccessID = 0 }()

	out := captureStdout(t, func() {
		if err := secretAccessCmd.RunE(secretAccessCmd, nil); err != nil {
			t.Fatalf("secretAccessCmd: %v", err)
		}
	})
	if !containsAll(out, "alice", "read", "owner") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── schedule ────────────────────────────────────────────────────────────────────

func TestSecretSetSchedule_RejectsInvalidDay(t *testing.T) {
	if _, err := convertSecretDayNames("notaday"); err == nil {
		t.Fatal("expected an error for an invalid day name")
	}
}

func TestSecretSetSchedule_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, jsonRoute(http.MethodPut, "/api/v1/secrets/1/schedule",
		`{"data":{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17,"timezone":"UTC"}}`))
	setPATCreds(t, srv)
	secretSchedDays, secretSchedStartHour, secretSchedEndHour, secretSchedTimezone = "mon,tue,wed,thu,fri", 9, 17, "UTC"
	defer func() { secretSchedDays = "" }()

	out := captureStdout(t, func() {
		if err := secretSetScheduleCmd.RunE(secretSetScheduleCmd, []string{"1"}); err != nil {
			t.Fatalf("secretSetScheduleCmd: %v", err)
		}
	})
	if !containsAll(out, "Schedule set", "1,2,3,4,5", "09:00-17:00", "UTC") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── suspend / resume / trash / restore ──────────────────────────────────────────

func TestSecretSuspend_RequiresID(t *testing.T) {
	secretSuspendID = 0
	if err := secretSuspendCmd.RunE(secretSuspendCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestSecretTrash_RequiresProject(t *testing.T) {
	secretTrashProject = 0
	if err := secretTrashCmd.RunE(secretTrashCmd, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestSecretTrash_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, jsonRoute(http.MethodGet, "/api/v1/projects/1/secrets/deleted",
		`{"data":{"deleted":[{"id":4,"name":"old-key","type":"generic","classification":"","deleted_at":"2026-01-02T00:00:00Z"}]}}`))
	setPATCreds(t, srv)
	secretTrashProject = 1
	defer func() { secretTrashProject = 0 }()

	out := captureStdout(t, func() {
		if err := secretTrashCmd.RunE(secretTrashCmd, nil); err != nil {
			t.Fatalf("secretTrashCmd: %v", err)
		}
	})
	if !containsAll(out, "4", "old-key", "generic") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── templates ───────────────────────────────────────────────────────────────────

func TestSecretTemplateCreate_RequiresName(t *testing.T) {
	secretTmplName = ""
	if err := secretTemplateCreateCmd.RunE(secretTemplateCreateCmd, nil); err == nil {
		t.Fatal("expected an error when --name is omitted")
	}
}

func TestSecretTemplateList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t, jsonRoute(http.MethodGet, "/api/v1/secret-templates",
		`{"data":{"templates":[{"id":2,"name":"db-cred","description":"Standard DB credential"}]}}`))
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := secretTemplateListCmd.RunE(secretTemplateListCmd, nil); err != nil {
			t.Fatalf("secretTemplateListCmd: %v", err)
		}
	})
	if !containsAll(out, "db-cred", "Standard DB credential") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

// ── metadata: tags / description / classify / info ──────────────────────────────

func TestSecretTags_RequiresID(t *testing.T) {
	secretTagsID = 0
	if err := secretTagsCmd.RunE(secretTagsCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestSecretTags_ListEmptyPrintsNoTags(t *testing.T) {
	srv := secretOpsServer(t, jsonRoute(http.MethodGet, "/api/v1/secrets/1/tags", `{"data":{"tags":[]}}`))
	setPATCreds(t, srv)
	secretTagsID = 1
	defer func() { secretTagsID = 0 }()

	out := captureStdout(t, func() {
		if err := secretTagsCmd.RunE(secretTagsCmd, nil); err != nil {
			t.Fatalf("secretTagsCmd: %v", err)
		}
	})
	if !containsAll(out, "(no tags)") {
		t.Fatalf("output missing the empty-state message, got: %q", out)
	}
}

func TestSecretClassify_RejectsInvalidLevel(t *testing.T) {
	secretClassifyID, secretClassifyLevel = 1, "not-a-level"
	defer func() { secretClassifyID, secretClassifyLevel = 0, "" }()
	if err := secretClassifyCmd.RunE(secretClassifyCmd, nil); err == nil {
		t.Fatal("expected an error for an invalid --level")
	}
}

func TestSecretInfo_RequiresID(t *testing.T) {
	secretInfoID = 0
	if err := secretInfoCmd.RunE(secretInfoCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestSecretInfo_MatchesOldCLIOutputShape(t *testing.T) {
	srv := secretOpsServer(t,
		jsonRoute(http.MethodGet, "/api/v1/secrets/1", `{"data":{"ID":1,"Name":"db-pass","Type":"generic","Status":"active","Classification":"confidential","OwnerID":9,"CreatedBy":"alice"}}`),
		jsonRoute(http.MethodGet, "/api/v1/secrets/1/tags", `{"data":{"tags":["prod","db"]}}`),
	)
	setPATCreds(t, srv)
	secretInfoID = 1
	defer func() { secretInfoID = 0 }()

	out := captureStdout(t, func() {
		if err := secretInfoCmd.RunE(secretInfoCmd, nil); err != nil {
			t.Fatalf("secretInfoCmd: %v", err)
		}
	})
	if !containsAll(out, "Secret 1: db-pass", "confidential", "user #9", "alice", "prod, db") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}
