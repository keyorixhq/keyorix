package connect

import (
	"net/http"
	"net/http/httptest"
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
