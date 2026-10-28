package notary

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A configured TSA URL can carry a token (userinfo, path, query). None of it
// may reach an error string, and the wrapped *url.Error must be gone.
func assertTSAErrorRedacted(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	for _, frag := range []string{"user", "tok3n", "/path", "key=secret", "secret"} {
		assert.NotContains(t, err.Error(), frag, "error leaks %q: %s", frag, err)
	}
	var ue *url.Error
	assert.False(t, errors.As(err, &ue), "error must not wrap a *url.Error")
}

func TestNewRFC3161_ValidationErrorsRedactURL(t *testing.T) {
	for name, raw := range map[string]string{
		"unparsable":     "https://user:tok3n@tsa.example.test:bad/path?key=secret",
		"plaintext http": "http://user:tok3n@tsa.example.test/path?key=secret",
		"no host":        "https:///path?key=secret&user=tok3n",
		// url.Parse cuts the authority at the unescaped '/' and quotes the
		// password prefix as an invalid port in its inner error.
		"unescaped slash in password": "https://user:tok3n/x@tsa.example.test/path?key=secret",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewRFC3161(raw, time.Second)
			assertTSAErrorRedacted(t, err)
		})
	}
}

func TestRFC3161_AnchorTransportErrorRedactsURL(t *testing.T) {
	// Port 1 on loopback refuses the connection: client.Do returns a *url.Error
	// that embeds the full request URL.
	r, err := NewRFC3161("http://user:tok3n@127.0.0.1:1/path?key=secret", time.Second)
	require.NoError(t, err)
	_, err = r.Anchor(context.Background(), []byte("checkpoint"))
	assertTSAErrorRedacted(t, err)
	assert.Contains(t, err.Error(), "127.0.0.1")
}

func TestRefuseRedirect_NamesHostOnly(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://user:tok3n@tsa.example.test/path?key=secret", nil)
	require.NoError(t, err)
	err = refuseRedirect(req, nil)
	assertTSAErrorRedacted(t, err)
	assert.Contains(t, err.Error(), "https://tsa.example.test")
}

// Receipt.Provider is persisted verbatim as audit_checkpoints.anchor_provider
// (internal/core anchorCheckpoint) and served by the audit verify/checkpoint
// API, gRPC and the admin export, so it may carry only scheme://host.
func TestRFC3161_ProviderRedactsConfiguredURL(t *testing.T) {
	srv, _, _ := newTestTSA(t, time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
	raw := "http://user:tok3n@" + strings.TrimPrefix(srv.URL, "http://") + "/path?key=secret"
	r, err := NewRFC3161(raw, 5*time.Second)
	require.NoError(t, err)

	assert.Equal(t, "rfc3161:"+srv.URL, r.Provider())
	rec, err := r.Anchor(context.Background(), []byte("checkpoint"))
	require.NoError(t, err)
	assert.Equal(t, "rfc3161:"+srv.URL, rec.Provider)
	for _, frag := range []string{"user", "tok3n", "/path", "key=secret", "secret"} {
		assert.NotContains(t, rec.Provider, frag, "anchor provider leaks %q", frag)
	}
}
