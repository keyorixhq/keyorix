package notary

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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
