package cmd

// CLI-PROMPT-READER-1 (#3448): every prompt must read from ONE shared buffered reader over
// stdin. A fresh bufio.NewReader(os.Stdin) per prompt swallows the rest of a pipe in its
// first fill, so `printf 'user\npass\n123456\n' | keyorix ...` lost every line after the first.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pipeStdin makes os.Stdin a pipe that already holds input (a non-terminal stdin, as in
// `printf ... | keyorix`), and restores the previous stdin and shared reader afterwards.
func pipeStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatalf("write pipe: %v", err)
	}
	_ = w.Close()
	orig := os.Stdin
	os.Stdin = r
	resetStdinReader()
	t.Cleanup(func() {
		os.Stdin = orig
		resetStdinReader()
		_ = r.Close()
	})
}

func TestPrompts_ThreePipedLinesAreAllRead(t *testing.T) {
	pipeStdin(t, "alice\nhunter2\n123456\n")

	user, err := promptLine("Username: ")
	if err != nil || user != "alice" {
		t.Fatalf("line 1: got %q, %v; want alice", user, err)
	}
	pass, err := promptPassword("Password: ")
	if err != nil || pass != "hunter2" {
		t.Fatalf("line 2: got %q, %v; want hunter2", pass, err)
	}
	code, err := promptLine("Code: ")
	if err != nil || code != "123456" {
		t.Fatalf("line 3: got %q, %v; want 123456", code, err)
	}
}

func TestMFAActivate_TwoPipedPromptsReadCodeThenPassword(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"recovery_codes":["rc-1"]}}`))
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	mfaActivateCode, mfaActivatePassword = "", ""
	for _, k := range []string{"KEYORIX_MFA_CODE", "KEYORIX_MFA_CODE_FILE", "KEYORIX_PASSWORD", "KEYORIX_PASSWORD_FILE"} {
		t.Setenv(k, "")
	}
	pipeStdin(t, "654321\npiped-activate-pw\n")

	captureStdout(t, func() {
		if err := runMFAActivate(mfaActivateCmd, nil); err != nil {
			t.Fatalf("runMFAActivate: %v", err)
		}
	})
	if got["code"] != "654321" || got["password"] != "piped-activate-pw" {
		t.Errorf("request body: %v; want code 654321 and password piped-activate-pw", got)
	}
}

func TestLogin_PipedUsernameAndPassword(t *testing.T) {
	var gotLogin map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/login":
			_ = json.NewDecoder(r.Body).Decode(&gotLogin)
			_, _ = w.Write([]byte(`{"success":true,"data":{"token":"tok-login"}}`))
		case "/api/v1/auth/profile":
			_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
		default:
			_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
		}
	}))
	defer srv.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	for _, k := range []string{"KEYORIX_TOKEN", "KEYORIX_TOKEN_FILE", "KEYORIX_PASSWORD", "KEYORIX_PASSWORD_FILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("KEYORIX_SERVER", srv.URL)
	loginServerURL, loginUsername, loginPassword, loginMFACode = "", "", "", ""
	pipeStdin(t, "alice\npiped-login-pw\n")

	var out string
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() {
			if err := runLogin(loginCmd, nil); err != nil {
				t.Fatalf("runLogin: %v", err)
			}
		})
	})
	if gotLogin["username"] != "alice" || gotLogin["password"] != "piped-login-pw" {
		t.Errorf("login request body: %v; want alice / piped-login-pw (stderr: %s)", gotLogin, stderr)
	}
	if !strings.Contains(out, "Logged in") {
		t.Errorf("stdout missing the login confirmation: %q", out)
	}
}
