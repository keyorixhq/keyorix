package connect

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"localhost", "127.0.0.1", "127.0.0.5", "::1"}
	for _, h := range loopback {
		assert.True(t, isLoopbackHost(h), "%s should be loopback", h)
	}
	notLoopback := []string{"example.com", "10.0.0.1", "8.8.8.8", "0.0.0.0", ""}
	for _, h := range notLoopback {
		assert.False(t, isLoopbackHost(h), "%s should NOT be loopback", h)
	}
}

// TestIsLoopbackHost_RejectsDNSNamePrefixedWith127 is #G46: an attacker-controlled DNS
// name like "127.evil.com" must never be classified as loopback — a raw
// strings.HasPrefix(host, "127.") used to match it, silently skipping the
// cleartext-credential warning `keyorix connect` prints for every non-loopback host.
func TestIsLoopbackHost_RejectsDNSNamePrefixedWith127(t *testing.T) {
	adversarial := []string{"127.evil.com", "127.0.0.1.attacker.com", "127.attacker.net"}
	for _, h := range adversarial {
		assert.False(t, isLoopbackHost(h), "%s must NOT be classified as loopback", h)
	}
}

func cmdWithFlags() *cobra.Command {
	c := &cobra.Command{}
	c.Flags().String("api-key", "", "")
	c.Flags().String("password", "", "")
	return c
}

func TestResolveAPIKey(t *testing.T) {
	t.Run("flag wins", func(t *testing.T) {
		c := cmdWithFlags()
		require.NoError(t, c.Flags().Set("api-key", "from-flag"))
		assert.Equal(t, "from-flag", resolveAPIKey(c))
	})
	t.Run("env fallback", func(t *testing.T) {
		t.Setenv("KEYORIX_API_KEY", "from-env")
		assert.Equal(t, "from-env", resolveAPIKey(cmdWithFlags()))
	})
	t.Run("empty when neither set", func(t *testing.T) {
		t.Setenv("KEYORIX_API_KEY", "")
		assert.Equal(t, "", resolveAPIKey(cmdWithFlags()))
	})
}

func TestResolveConnectPassword(t *testing.T) {
	t.Run("flag wins", func(t *testing.T) {
		c := cmdWithFlags()
		require.NoError(t, c.Flags().Set("password", "flagpw"))
		pw, err := resolveConnectPassword(c, "alice")
		require.NoError(t, err)
		assert.Equal(t, "flagpw", pw)
	})
	t.Run("env fallback", func(t *testing.T) {
		t.Setenv("KEYORIX_PASSWORD", "envpw")
		pw, err := resolveConnectPassword(cmdWithFlags(), "alice")
		require.NoError(t, err)
		assert.Equal(t, "envpw", pw)
	})
}

func TestLoginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/auth/login", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"token":"session-token-xyz"}}`))
	}))
	defer srv.Close()

	tok, err := loginWithCredentials(srv.URL, "alice", "pw", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "session-token-xyz", tok)
}

func TestLoginWithCredentials_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := loginWithCredentials(srv.URL, "alice", "wrong", 5*time.Second)
	require.Error(t, err)
}

// TestLoginWithCredentials_SanitizesResponseBodyOnFailure is the regression test
// for the threat model in #G69/common.SanitizeForTerminal: a malicious or
// compromised KEYORIX_SERVER endpoint could embed ANSI/control-sequence
// terminal-injection payloads in its login-failure response body. That body
// reaches the operator's terminal verbatim via loginWithCredentials's returned
// error (wrapped by runConnect's "login failed: %w" and printed by cobra), so
// it must be stripped of control/escape bytes before it ever gets there.
func TestLoginWithCredentials_SanitizesResponseBodyOnFailure(t *testing.T) {
	// A representative hostile payload: ANSI color escape, BEL, CR, LF mixed in
	// with a plausible human-readable error message.
	payload := "invalid credentials\x1b[31;1m\x07\r\nnested \x1b[2Jscreen-clear attempt"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	_, err := loginWithCredentials(srv.URL, "alice", "wrong", 5*time.Second)
	require.Error(t, err)

	msg := err.Error()
	// No raw control/escape bytes must reach the returned error (and therefore
	// the terminal): ESC, BEL, CR, LF are all stripped.
	assert.NotContains(t, msg, "\x1b")
	assert.NotContains(t, msg, "\x07")
	assert.NotContains(t, msg, "\r")
	assert.NotContains(t, msg, "\n")
	// The human-readable portions of the server's message are still surfaced —
	// this isn't a blanket "hide everything" fix, just a sanitize-before-echo one.
	assert.Contains(t, msg, "invalid credentials")
	assert.Contains(t, msg, "screen-clear attempt")
}

// TestLoginWithCredentials_TruncatesLongResponseBodyOnFailure guards against a
// hostile or misbehaving server flooding the operator's terminal with an
// oversized error response.
func TestLoginWithCredentials_TruncatesLongResponseBodyOnFailure(t *testing.T) {
	long := strings.Repeat("x", 5000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(long))
	}))
	defer srv.Close()

	_, err := loginWithCredentials(srv.URL, "alice", "wrong", 5*time.Second)
	require.Error(t, err)
	assert.Less(t, len(err.Error()), 400, "error message should be bounded, not carry the full 5000-byte body")
	assert.Contains(t, err.Error(), "…", "truncated excerpt should be marked with an ellipsis")
}

func TestTestServerConnection(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/health", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		require.NoError(t, testServerConnection(srv.URL, "key", 5*time.Second))
	})
	t.Run("unhealthy status is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		require.Error(t, testServerConnection(srv.URL, "key", 5*time.Second))
	})
}
