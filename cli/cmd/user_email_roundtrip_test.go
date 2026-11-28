package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

const quotedLocalPartEmail = `"a b"@example.com`

// TestGeneratedEmailRuntimeGap pins the premise cliEmailAddress rests on: the
// oapi-codegen runtime's Email decodes a quoted local part into a value its own
// encoder rejects. If a runtime upgrade fixes that, this fails: remove the guard
// (or narrow it) instead of keeping a check for a defect that no longer exists.
func TestGeneratedEmailRuntimeGap(t *testing.T) {
	var body apiclient.UpdateUserJSONRequestBody
	raw := fmt.Sprintf(`{"email":%q}`, quotedLocalPartEmail)
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("runtime no longer decodes %s (%v): re-check cliEmailAddress", raw, err)
	}
	if _, err := json.Marshal(body); err == nil {
		t.Fatal("runtime now re-encodes a decoded quoted local part: cliEmailAddress may be unnecessary")
	}
}

// TestUserEmailRoundTrip_QuotedLocalPart drives the report in #4797: list a user
// whose email has a quoted local part, then send that same value back. The CLI
// must refuse it with one error that names --email, before any request is made
// (on main the request went out with the address silently rewritten to a b@example.com).
func TestUserEmailRoundTrip_QuotedLocalPart(t *testing.T) {
	var puts, posts int
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/users/42" && r.Method == http.MethodGet:
			_, _ = fmt.Fprintf(w, `{"data":{"id":42,"username":"bob","email":%q,"active":true}}`, quotedLocalPartEmail)
		case r.URL.Path == "/api/v1/users/42" && r.Method == http.MethodPut:
			puts++
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			gotBody = string(buf[:n])
			_, _ = fmt.Fprint(w, `{"data":{"id":42,"username":"bob","email":"a b@example.com"}}`)
		case r.URL.Path == "/api/v1/users" && r.Method == http.MethodPost:
			posts++
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"data":{"id":43,"username":"carol","email":"a b@example.com"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setUserCreds(t, srv)

	// 1. list: the server returns the address and the CLI prints it as is.
	userGetID, userGetEmail = 42, ""
	out := captureStdout(t, func() {
		if err := runUserGet(userGetCmd, nil); err != nil {
			t.Fatalf("runUserGet: %v", err)
		}
	})
	if !strings.Contains(out, "Email: "+quotedLocalPartEmail) {
		t.Fatalf("get output = %q, want the quoted address shown", out)
	}

	// 2. re-send it: update.
	userUpdateID = 42
	userUpdateEmail = quotedLocalPartEmail
	userUpdateUsername, userUpdateDisplayName, userUpdateActiveStr = "", "", ""
	defer func() { userUpdateEmail = "" }()
	err := runUserUpdate(userUpdateCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--email must be a plain name@domain.tld address") {
		t.Fatalf("update err = %v, want one error naming --email", err)
	}
	if puts != 0 {
		t.Fatalf("update sent %d request(s) (body %q), want none", puts, gotBody)
	}

	// 3. re-send it: create.
	userCreateUsername, userCreateEmail, userCreateDisplayName = "carol", quotedLocalPartEmail, ""
	userCreateSetupLink, userCreateOneTimePassword = true, false
	defer func() {
		userCreateUsername, userCreateEmail, userCreateSetupLink = "", "", false
	}()
	err = runUserCreate(userCreateCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--email must be a plain name@domain.tld address") {
		t.Fatalf("create err = %v, want one error naming --email", err)
	}
	if posts != 0 {
		t.Fatalf("create sent %d request(s), want none", posts)
	}
}
