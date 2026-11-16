package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The password inside every DSN these tests use. It must never reach stdout, stderr or an error.
const dsnTestPassword = "Pw-9f2c-CANARY"

const dsnTestDSN = "postgres://admin:" + dsnTestPassword + "@db.internal:5432/app?sslmode=verify-full"

// dsnRecorder is a server that records the PATCH admin-dsn requests it receives.
type dsnRecorder struct {
	srv    *httptest.Server
	calls  int
	paths  []string
	bodies []map[string]any
}

func newDSNRecorder(t *testing.T, status int, response string) *dsnRecorder {
	t.Helper()
	rec := &dsnRecorder{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || !strings.HasSuffix(r.URL.Path, "/admin-dsn") {
			http.NotFound(w, r)
			return
		}
		rec.calls++
		rec.paths = append(rec.paths, r.URL.Path)
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		rec.bodies = append(rec.bodies, b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, response)
	}))
	t.Cleanup(rec.srv.Close)
	setDynCreds(t, rec.srv)
	return rec
}

func feedDSNStdin(t *testing.T, s string) {
	t.Helper()
	t.Setenv(dynAdminDSNEnv, "")
	dynAdminDSNStdin = strings.NewReader(s)
	t.Cleanup(func() { dynAdminDSNStdin = sharedStdin{} })
}

func assertNoDSNLeak(t *testing.T, where, text string) {
	t.Helper()
	if strings.Contains(text, dsnTestPassword) {
		t.Errorf("%s contains the DSN password: %q", where, text)
	}
}

const dsnOKResponse = `{"success":true,"message":"admin DSN replaced","data":{"id":5,"name":"app-db","project_id":3,"environment_id":2,"backend_type":"postgres"}}`

func TestRunDynSetAdminDSN_FromEnvironment(t *testing.T) {
	rec := newDSNRecorder(t, http.StatusOK, dsnOKResponse)
	t.Setenv(dynAdminDSNEnv, dsnTestDSN)

	var err error
	stdout, stderr := captureStdoutAndStderr(t, func() { err = runDynSetAdminDSN(dynSetAdminDSNCmd, []string{"5"}) })
	if err != nil {
		t.Fatalf("runDynSetAdminDSN: %v", err)
	}
	if rec.calls != 1 || rec.paths[0] != "/api/v1/dynamic-secrets/configs/5/admin-dsn" {
		t.Fatalf("want one PATCH to /configs/5/admin-dsn, got %d calls %v", rec.calls, rec.paths)
	}
	if got := rec.bodies[0]["admin_dsn"]; got != dsnTestDSN {
		t.Errorf("the server received admin_dsn %v, want the environment value", got)
	}
	const want = "Replaced the admin DSN of dynamic-secret config #5 (app-db, postgres).\n" +
		"Check it with: keyorix dynamic-secret issue 5\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	assertNoDSNLeak(t, "stdout", stdout)
	assertNoDSNLeak(t, "stderr", stderr)
	if strings.Contains(stdout+stderr, "db.internal") {
		t.Errorf("the output names the DSN host, it should not echo any part of the DSN: %q %q", stdout, stderr)
	}
}

func TestRunDynSetAdminDSN_FromStdin(t *testing.T) {
	rec := newDSNRecorder(t, http.StatusOK, dsnOKResponse)
	feedDSNStdin(t, dsnTestDSN+"\n") // echo adds a newline

	var err error
	stdout, stderr := captureStdoutAndStderr(t, func() { err = runDynSetAdminDSN(dynSetAdminDSNCmd, []string{"5"}) })
	if err != nil {
		t.Fatalf("runDynSetAdminDSN: %v", err)
	}
	if rec.calls != 1 || rec.bodies[0]["admin_dsn"] != dsnTestDSN {
		t.Fatalf("the server did not receive the piped DSN without its newline: %+v", rec.bodies)
	}
	assertNoDSNLeak(t, "stdout", stdout)
	assertNoDSNLeak(t, "stderr", stderr)
}

func TestRunDynSetAdminDSN_EnvironmentWinsOverStdin(t *testing.T) {
	rec := newDSNRecorder(t, http.StatusOK, dsnOKResponse)
	feedDSNStdin(t, "postgres://other@elsewhere/db\n")
	t.Setenv(dynAdminDSNEnv, dsnTestDSN)

	captureStdoutAndStderr(t, func() {
		if err := runDynSetAdminDSN(dynSetAdminDSNCmd, []string{"5"}); err != nil {
			t.Fatalf("runDynSetAdminDSN: %v", err)
		}
	})
	if rec.bodies[0]["admin_dsn"] != dsnTestDSN {
		t.Errorf("got %v, the environment variable must win like `dynamic-secret create`", rec.bodies[0]["admin_dsn"])
	}
}

// Nothing to send means nothing is sent: an empty stdin must not become an empty admin_dsn
// on the server, and the message says what to do.
func TestRunDynSetAdminDSN_NoDSNSendsNothing(t *testing.T) {
	for name, in := range map[string]string{"empty": "", "newline": "\n", "spaces": "   \n"} {
		t.Run(name, func(t *testing.T) {
			rec := newDSNRecorder(t, http.StatusOK, dsnOKResponse)
			feedDSNStdin(t, in)
			err := runDynSetAdminDSN(dynSetAdminDSNCmd, []string{"5"})
			if err == nil || !containsAll(err.Error(), dynAdminDSNEnv, "stdin", "Nothing was changed") {
				t.Fatalf("want an error naming the environment variable and stdin, got %v", err)
			}
			if code, _ := classifyError(err, true); code != exitUsage {
				t.Errorf("exit code = %d, want usage (%d)", code, exitUsage)
			}
			if rec.calls != 0 {
				t.Errorf("the server was called %d time(s)", rec.calls)
			}
		})
	}
}

func TestRunDynSetAdminDSN_OversizedStdinIsRefused(t *testing.T) {
	rec := newDSNRecorder(t, http.StatusOK, dsnOKResponse)
	feedDSNStdin(t, strings.Repeat("x", maxSecretFileSize+1))
	err := runDynSetAdminDSN(dynSetAdminDSNCmd, []string{"5"})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("want a too-large error, got %v", err)
	}
	if rec.calls != 0 {
		t.Errorf("the server was called %d time(s)", rec.calls)
	}
}

func TestRunDynSetAdminDSN_BadConfigID(t *testing.T) {
	rec := newDSNRecorder(t, http.StatusOK, dsnOKResponse)
	t.Setenv(dynAdminDSNEnv, dsnTestDSN)
	for _, id := range []string{"abc", "0", "-3", ""} {
		err := runDynSetAdminDSN(dynSetAdminDSNCmd, []string{id})
		if err == nil || !strings.Contains(err.Error(), "invalid config id") {
			t.Errorf("id %q: want an invalid-id error, got %v", id, err)
		}
	}
	if rec.calls != 0 {
		t.Errorf("the server was called %d time(s)", rec.calls)
	}
}

// The DSN is never accepted as a flag, with or without the migration escape hatch that the
// older secret flags have. TestRefusedSecretFlagsAreRefused covers the generic wording for
// every entry of refusedSecretFlags; this one adds that nothing reaches the server and the
// canary appears nowhere.
func TestDynSetAdminDSN_AdminDSNFlagIsNeverAccepted(t *testing.T) {
	const canary = "postgres://admin:" + dsnTestPassword + "@db.internal/app"
	for _, allowInsecure := range []string{"", "1"} {
		t.Run("allow-insecure="+allowInsecure, func(t *testing.T) {
			isolateSecretFlagEnv(t)
			// cobra keeps a parsed flag (and Changed) on the command after a run; the tests that
			// call runDynSetAdminDSN directly must not inherit it.
			t.Cleanup(func() { resetAllFlags(rootCmd) })
			rec := newDSNRecorder(t, http.StatusOK, dsnOKResponse)
			t.Setenv(allowInsecureSecretFlagsEnv, allowInsecure)
			t.Setenv(dynAdminDSNEnv, "")

			// executeForTest discards the command's own output; the error is what the user sees.
			err := executeForTest(t, "dynamic-secret", "set-admin-dsn", "5", "--"+dynAdminDSNFlag, canary)
			if err == nil {
				t.Fatal("want a refusal, got success")
			}
			if code, _ := classifyError(err, true); code != exitUsage {
				t.Errorf("exit code = %d, want usage (%d)", code, exitUsage)
			}
			if !strings.Contains(err.Error(), dynAdminDSNEnv) {
				t.Errorf("the refusal does not name the safe way in: %v", err)
			}
			assertNoDSNLeak(t, "error", err.Error())
			if rec.calls != 0 {
				t.Errorf("a refused flag still reached the server (%d call(s))", rec.calls)
			}
		})
	}
}

func TestDynSetAdminDSN_FlagIsHiddenFromHelp(t *testing.T) {
	f := dynSetAdminDSNCmd.Flags().Lookup(dynAdminDSNFlag)
	if f == nil || !f.Hidden {
		t.Fatalf("--%s must exist (so it can be refused with a message) and be hidden", dynAdminDSNFlag)
	}
	if strings.Contains(dynSetAdminDSNCmd.UsageString(), "--"+dynAdminDSNFlag) {
		t.Errorf("--%s is advertised in --help:\n%s", dynAdminDSNFlag, dynSetAdminDSNCmd.UsageString())
	}
}

// Whatever the server (or a proxy in front of it) puts in an error, the password does not
// reach the user, and the exit code of the failure is kept.
func TestRunDynSetAdminDSN_ErrorsNeverEchoTheDSN(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		response string
		wantCode int
		wantText string
	}{
		{"conflict echoing the DSN", http.StatusConflict,
			`{"message":"new admin DSN must name host db.internal; got ` + dsnTestDSN + `"}`, exitFailure, "HTTP 409"},
		{"bad request echoing only the password", http.StatusBadRequest,
			`{"message":"invalid DSN: password ` + dsnTestPassword + ` rejected"}`, exitFailure, "HTTP 400"},
		{"forbidden", http.StatusForbidden, `{"message":"admin authority required for ` + dsnTestDSN + `"}`, exitPermission, "HTTP 403"},
		{"audit unavailable", http.StatusServiceUnavailable, `{"message":"audit_unavailable"}`, exitFailure, "HTTP 503"},
		{"not found", http.StatusNotFound, `{"message":"config 5 not found, dsn ` + dsnTestDSN + `"}`, exitNotFound, "HTTP 404"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			newDSNRecorder(t, c.status, c.response)
			t.Setenv(dynAdminDSNEnv, dsnTestDSN)
			var err error
			stdout, stderr := captureStdoutAndStderr(t, func() { err = runDynSetAdminDSN(dynSetAdminDSNCmd, []string{"5"}) })
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), c.wantText) {
				t.Errorf("error = %q, want it to say %q", err, c.wantText)
			}
			if code, msg := classifyError(err, true); code != c.wantCode {
				t.Errorf("exit code = %d, want %d", code, c.wantCode)
			} else {
				assertNoDSNLeak(t, "classified message", msg)
			}
			assertNoDSNLeak(t, "error", err.Error())
			assertNoDSNLeak(t, "stdout", stdout)
			assertNoDSNLeak(t, "stderr", stderr)
		})
	}
}

func TestRunDynSetAdminDSN_UnreachableServerErrorHasNoDSN(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	setDynCreds(t, srv)
	srv.Close() // connection refused
	t.Setenv(dynAdminDSNEnv, dsnTestDSN)
	err := runDynSetAdminDSN(dynSetAdminDSNCmd, []string{"5"})
	if err == nil {
		t.Fatal("want a connection error")
	}
	assertNoDSNLeak(t, "error", err.Error())
	if code, _ := classifyError(err, true); code != exitUnreach {
		t.Errorf("exit code = %d, want unreachable (%d): the scrubbing must not hide the transport error", code, exitUnreach)
	}
}

func TestRedactDSN(t *testing.T) {
	pw := "p@ss/w:rd?"
	escaped := "postgres://admin:p%40ss%2Fw%3Ard%3F@db.internal/app"
	cases := []struct {
		name, dsn, msg string
		wantAbsent     []string
	}{
		{"whole DSN", dsnTestDSN, "bad " + dsnTestDSN + " end", []string{dsnTestDSN, dsnTestPassword}},
		{"password alone", dsnTestDSN, "password " + dsnTestPassword + " rejected", []string{dsnTestPassword}},
		{"escaped password", escaped, "bad " + escaped, []string{"p%40ss%2Fw%3Ard%3F", escaped}},
		{"raw password of an escaped DSN", escaped, "got " + pw, []string{pw}},
		{"JSON cloud config", `{"role_arn":"arn:aws:iam::1:role/x"}`, `config {"role_arn":"arn:aws:iam::1:role/x"} refused`, []string{`{"role_arn"`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := redactDSN(withExitCode(exitPermission, errors.New(c.msg)), c.dsn)
			for _, absent := range c.wantAbsent {
				if strings.Contains(err.Error(), absent) {
					t.Errorf("%q still contains %q", err, absent)
				}
			}
			if !strings.Contains(err.Error(), "[redacted]") {
				t.Errorf("%q has no [redacted] marker", err)
			}
			if code, _ := classifyError(err, true); code != exitPermission {
				t.Errorf("exit code = %d, want it kept (%d)", code, exitPermission)
			}
		})
	}
	// An error that does not contain the DSN is returned as it was, and nil stays nil.
	orig := errors.New("HTTP 409: conflict")
	if got := redactDSN(orig, dsnTestDSN); got != orig {
		t.Errorf("an error without the DSN was rewritten: %v", got)
	}
	if redactDSN(nil, dsnTestDSN) != nil {
		t.Error("nil must stay nil")
	}
}

const refusedResponse = `{"success":true,"data":{"configs":[` +
	`{"id":5,"name":"app-db","project_id":3,"environment_id":2,"backend_type":"postgres","refused_options":["sslrootcert"],"live_leases":2},` +
	`{"id":8,"name":"events-mongo","project_id":3,"environment_id":2,"backend_type":"mongodb","refused_options":["tlscafile","authmechanism=mongodb-aws"],"live_leases":0}` +
	`],"unreadable":1}}`

func newRefusedServer(t *testing.T, response string, gotProject *string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/dynamic-secrets/configs/refused-admin-dsn" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if gotProject != nil {
			*gotProject = r.URL.Query().Get("project_id")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, response)
	}))
	t.Cleanup(srv.Close)
	setDynCreds(t, srv)
}

func setRefusedFlags(t *testing.T, project int, format string) {
	t.Helper()
	dynRefusedProjectID, dynRefusedFormat = project, format
	t.Cleanup(func() { dynRefusedProjectID, dynRefusedFormat = 0, outputTable })
}

func TestRunDynRefusedDSN_TableGolden(t *testing.T) {
	var project string
	newRefusedServer(t, refusedResponse, &project)
	setRefusedFlags(t, 3, outputTable)

	var err error
	stdout, stderr := captureStdoutAndStderr(t, func() { err = runDynRefusedDSN(dynRefusedDSNCmd, nil) })
	if err != nil {
		t.Fatalf("runDynRefusedDSN: %v", err)
	}
	if project != "3" {
		t.Errorf("project_id query = %q, want 3", project)
	}
	want := fmt.Sprintf("%-5s %-24s %-10s %-7s %s\n", "ID", "NAME", "BACKEND", "LEASES", "REFUSED OPTIONS") +
		fmt.Sprintf("%-5d %-24s %-10s %-7d %s\n", 5, "app-db", "postgres", 2, "sslrootcert") +
		fmt.Sprintf("%-5d %-24s %-10s %-7d %s\n", 8, "events-mongo", "mongodb", 0, "tlscafile, authmechanism=mongodb-aws") +
		"\nFix each with: keyorix dynamic-secret set-admin-dsn <config-id>\n"
	if stdout != want {
		t.Errorf("stdout =\n%q\nwant\n%q", stdout, want)
	}
	// A config that could not be checked is said, on stderr so stdout stays parseable.
	if want := "1 config(s) in project 3 have an admin DSN that could not be decrypted and were not checked.\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}

func TestRunDynRefusedDSN_JSONGolden(t *testing.T) {
	newRefusedServer(t, refusedResponse, nil)
	setRefusedFlags(t, 3, "json")

	var err error
	stdout, stderr := captureStdoutAndStderr(t, func() { err = runDynRefusedDSN(dynRefusedDSNCmd, nil) })
	if err != nil {
		t.Fatalf("runDynRefusedDSN: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not a JSON array (the unreadable note must stay on stderr): %v\n%s", err, stdout)
	}
	if len(got) != 2 || got[0]["name"] != "app-db" || got[1]["backend_type"] != "mongodb" {
		t.Fatalf("unexpected records: %v", got)
	}
	opts, _ := got[1]["refused_options"].([]any)
	if len(opts) != 2 || opts[1] != "authmechanism=mongodb-aws" {
		t.Errorf("refused_options = %v", got[1]["refused_options"])
	}
	if !strings.Contains(stderr, "could not be decrypted") {
		t.Errorf("stderr = %q, want the unreadable note", stderr)
	}
}

func TestRunDynRefusedDSN_EmptyAndUnchecked(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		newRefusedServer(t, `{"success":true,"data":{"configs":[],"unreadable":0}}`, nil)
		setRefusedFlags(t, 3, outputTable)
		var err error
		stdout, stderr := captureStdoutAndStderr(t, func() { err = runDynRefusedDSN(dynRefusedDSNCmd, nil) })
		if err != nil {
			t.Fatal(err)
		}
		if stdout != "No config in project 3 has a refused admin DSN option.\n" || stderr != "" {
			t.Errorf("stdout = %q stderr = %q", stdout, stderr)
		}
	})
	t.Run("none as json is an empty array", func(t *testing.T) {
		newRefusedServer(t, `{"success":true,"data":{}}`, nil)
		setRefusedFlags(t, 3, "json")
		var err error
		stdout, _ := captureStdoutAndStderr(t, func() { err = runDynRefusedDSN(dynRefusedDSNCmd, nil) })
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(stdout) != "[]" {
			t.Errorf("stdout = %q, want []", stdout)
		}
	})
	t.Run("nothing checked is not reported as clean silently", func(t *testing.T) {
		newRefusedServer(t, `{"success":true,"data":{"configs":[],"unreadable":4}}`, nil)
		setRefusedFlags(t, 9, outputTable)
		var err error
		_, stderr := captureStdoutAndStderr(t, func() { err = runDynRefusedDSN(dynRefusedDSNCmd, nil) })
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stderr, "4 config(s) in project 9") {
			t.Errorf("stderr = %q, want the 4 unreadable configs named", stderr)
		}
	})
}

func TestRunDynRefusedDSN_Errors(t *testing.T) {
	t.Run("project id required", func(t *testing.T) {
		setRefusedFlags(t, 0, outputTable)
		err := runDynRefusedDSN(dynRefusedDSNCmd, nil)
		if err == nil || !strings.Contains(err.Error(), "--project-id is required") {
			t.Fatalf("got %v", err)
		}
		if code, _ := classifyError(err, true); code != exitUsage {
			t.Errorf("exit code = %d, want usage", code)
		}
	})
	t.Run("bad output format", func(t *testing.T) {
		setRefusedFlags(t, 3, "xml")
		if err := runDynRefusedDSN(dynRefusedDSNCmd, nil); err == nil {
			t.Fatal("want an error for -o xml")
		}
	})
	t.Run("forbidden is a permission error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"message":"dynamic-secret admin authority required"}`)
		}))
		t.Cleanup(srv.Close)
		setDynCreds(t, srv)
		setRefusedFlags(t, 3, outputTable)
		err := runDynRefusedDSN(dynRefusedDSNCmd, nil)
		if err == nil {
			t.Fatal("want an error")
		}
		if code, _ := classifyError(err, true); code != exitPermission {
			t.Errorf("exit code = %d, want permission (%d): %v", code, exitPermission, err)
		}
	})
}

// The command is wired into the real tree and its required flag is enforced by cobra.
func TestDynRefusedDSN_RequiresProjectIDThroughTheCommandTree(t *testing.T) {
	isolateSecretFlagEnv(t)
	err := executeForTest(t, "dynamic-secret", "refused-dsn")
	if err == nil || !strings.Contains(err.Error(), "project-id") {
		t.Fatalf("want a missing --project-id error, got %v", err)
	}
	if code, _ := classifyError(err, false); code != exitUsage {
		t.Errorf("exit code = %d, want usage", code)
	}
}
