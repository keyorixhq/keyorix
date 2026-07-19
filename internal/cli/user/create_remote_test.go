package user

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCreateRemote should POST the password-mode payload to /api/v1/users and
// print the created user, rather than touching a local SQLite file.
func TestRunCreateRemote(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/api/v1/users", r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":7,"username":"bob","email":"bob@test.com"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	createUsername, createEmail, createDisplayName = "bob", "bob@test.com", ""
	require.NoError(t, runCreateRemote(rc, "s3cret-pass"))

	assert.Equal(t, "bob", gotBody["username"])
	assert.Equal(t, "bob@test.com", gotBody["email"])
	assert.Equal(t, "s3cret-pass", gotBody["password"])
	assert.Equal(t, "bob", gotBody["display_name"], "display_name defaults to username when empty")
}

// TestRunCreateRemote_SetupLink verifies that --setup-link sends deliver_setup_link:true
// and prints the out-of-band setup link returned by the server.
func TestRunCreateRemote_SetupLink(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/api/v1/users", r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{
			"user":{"id":12,"username":"alice","email":"alice@example.com"},
			"setup_link":{"email":"alice@example.com","channel":"out_of_band","delivered":false,"link_for_admin":"https://app.example.com/auth/setup/abc123"}
		}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origSetupLink := createSetupLink
	origOTP := createOneTimePassword
	defer func() { createSetupLink = origSetupLink; createOneTimePassword = origOTP }()

	createUsername, createEmail, createDisplayName = "alice", "alice@example.com", ""
	createSetupLink = true
	createOneTimePassword = false

	out := captureOutput(t, func() {
		require.NoError(t, runCreateRemote(rc, ""))
	})

	assert.Equal(t, true, gotBody["deliver_setup_link"])
	assert.Nil(t, gotBody["password"])
	assert.Contains(t, out, "User created: id=12 username=alice email=alice@example.com")
	assert.Contains(t, out, "abc123")
	assert.Contains(t, out, "alice@example.com")
}

// TestRunCreateRemote_SetupLink_Delivered verifies that when the server reports the
// setup link was delivered (e.g. via SMTP), the CLI prints the delivery confirmation
// instead of the raw link.
func TestRunCreateRemote_SetupLink_Delivered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{
			"user":{"id":13,"username":"carol","email":"carol@example.com"},
			"setup_link":{"email":"carol@example.com","channel":"smtp","delivered":true}
		}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origSetupLink := createSetupLink
	origOTP := createOneTimePassword
	defer func() { createSetupLink = origSetupLink; createOneTimePassword = origOTP }()

	createUsername, createEmail, createDisplayName = "carol", "carol@example.com", ""
	createSetupLink = true
	createOneTimePassword = false

	out := captureOutput(t, func() {
		require.NoError(t, runCreateRemote(rc, ""))
	})

	assert.Contains(t, out, "User created: id=13 username=carol email=carol@example.com")
	assert.Contains(t, out, "delivered to carol@example.com via smtp")
}

// TestRunCreateRemote_OTP verifies that --one-time-password sends
// generate_one_time_password:true and prints the OTP returned by the server.
func TestRunCreateRemote_OTP(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{
			"user":{"id":9,"username":"dave","email":"dave@example.com"},
			"one_time_password":{"email":"dave@example.com","one_time_password":"S3cr3tP@ss!"}
		}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origSetupLink := createSetupLink
	origOTP := createOneTimePassword
	defer func() { createSetupLink = origSetupLink; createOneTimePassword = origOTP }()

	createUsername, createEmail, createDisplayName = "dave", "dave@example.com", ""
	createSetupLink = false
	createOneTimePassword = true

	out := captureOutput(t, func() {
		require.NoError(t, runCreateRemote(rc, ""))
	})

	assert.Equal(t, true, gotBody["generate_one_time_password"])
	assert.Nil(t, gotBody["password"])
	assert.Contains(t, out, "User created: id=9 username=dave email=dave@example.com")
	assert.Contains(t, out, "S3cr3tP@ss!")
	assert.Contains(t, out, "dave@example.com")
}

// TestRunCreateRemote_ServerError verifies that a server error is propagated to
// the caller.
func TestRunCreateRemote_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"ValidationError","message":"Invalid request"}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origSetupLink := createSetupLink
	origOTP := createOneTimePassword
	defer func() { createSetupLink = origSetupLink; createOneTimePassword = origOTP }()

	createUsername, createEmail, createDisplayName = "eve", "eve@example.com", ""
	createSetupLink = true
	createOneTimePassword = false

	err := runCreateRemote(rc, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create user")
}
