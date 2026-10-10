package cmd

// ADR-112 item 1: security.require_mfa defaults on, so a fresh install's first admin
// is confined to the MFA-enrolment endpoints until it enrols. These tests drive
// `keyorix mfa enroll` and `keyorix mfa activate` against a stand-in server; both
// commands did not exist before, so every test here fails to compile without them.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMFAEnroll_PrintsSecretAndURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/mfa/enroll" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok-abc" {
			t.Errorf("Authorization: got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"otpauth_uri":"otpauth://totp/Keyorix:admin?secret=JBSWY3DPEHPK3PXP","secret":"JBSWY3DPEHPK3PXP"}}`))
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runMFAEnroll(mfaEnrollCmd, nil); err != nil {
			t.Fatalf("runMFAEnroll: %v", err)
		}
	})
	for _, want := range []string{"JBSWY3DPEHPK3PXP", "otpauth://totp/", "keyorix mfa activate"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestMFAEnroll_ServerErrorIsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"error":"MFA already enabled"}`))
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	if err := runMFAEnroll(mfaEnrollCmd, nil); err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("expected an HTTP 400 failure, got %v", err)
	}
}

func TestMFAActivate_SendsCodeAndPasswordAndPrintsRecoveryCodes(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/mfa/activate" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"recovery_codes":["rc-1111","rc-2222"]}}`))
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	for flag, val := range map[string]string{"code": "123456", "password": "Correct-Horse-Battery9"} {
		if err := mfaActivateCmd.Flags().Set(flag, val); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		mfaActivateCode, mfaActivatePassword = "", ""
		mfaActivateCmd.Flags().Lookup("code").Changed = false
		mfaActivateCmd.Flags().Lookup("password").Changed = false
	})

	out := captureStdout(t, func() {
		if err := runMFAActivate(mfaActivateCmd, nil); err != nil {
			t.Fatalf("runMFAActivate: %v", err)
		}
	})
	if got["code"] != "123456" || got["password"] != "Correct-Horse-Battery9" {
		t.Errorf("request body: %v", got)
	}
	for _, want := range []string{"MFA enabled", "rc-1111", "rc-2222"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestMFAActivate_WrongCodeIsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"error":"invalid code"}`))
	}))
	defer srv.Close()
	setProjectCreds(t, srv)
	mfaActivateCode, mfaActivatePassword = "000000", "pw"
	t.Cleanup(func() { mfaActivateCode, mfaActivatePassword = "", "" })

	if err := runMFAActivate(mfaActivateCmd, nil); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("expected an HTTP 401 failure, got %v", err)
	}
}
