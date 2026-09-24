package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setNotificationCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunChannelList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 7's own test requirement) against
// internal/cli/notification/channels.go's runChannelListRemote.
func TestRunChannelList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/notification-channels" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"channels":[{"id":1,"name":"oncall","type":"slack","enabled":true,"url":"https://hooks.example/x","events":"secret.rotated","created_by":"admin"}]}}`)
	}))
	defer srv.Close()
	setNotificationCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runChannelList(channelListCmd, nil); err != nil {
			t.Fatalf("runChannelList: %v", err)
		}
	})
	if !containsAll(out, "ID", "NAME", "TYPE", "ENABLED", "EVENTS", "1", "oncall", "slack", "yes", "secret.rotated") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunChannelAdd_MatchesOldCLIOutputShape(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/notification-channels" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":2,"name":"new-channel","type":"webhook"}}`)
	}))
	defer srv.Close()
	setNotificationCreds(t, srv)
	channelType = "webhook"
	channelURL = "https://hooks.example/y"
	channelEmail = ""
	channelEvents = ""
	defer func() { channelType = "" }()

	out := captureStdout(t, func() {
		if err := runChannelAdd(channelAddCmd, []string{"new-channel"}); err != nil {
			t.Fatalf("runChannelAdd: %v", err)
		}
	})
	if !containsAll(out, `Notification channel "new-channel" (id=2, type=webhook) created.`) {
		t.Fatalf("output = %q", out)
	}
	if !containsAll(gotBody, `"name":"new-channel"`, `"type":"webhook"`) {
		t.Fatalf("request body = %q", gotBody)
	}
}

func TestRunChannelDelete_RequiresConfirm(t *testing.T) {
	channelDeleteConfirm = false
	if err := runChannelDelete(channelDeleteCmd, []string{"oncall"}); err == nil || !containsAll(err.Error(), "--confirm") {
		t.Fatalf("err = %v, want the missing-confirm error", err)
	}
}
