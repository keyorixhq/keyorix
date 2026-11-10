package connect

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingBody yields data, then fails with err instead of io.EOF: a connection that
// dies mid-body.
type failingBody struct {
	data string
	err  error
}

func (b *failingBody) Read(p []byte) (int, error) {
	if b.data == "" {
		return 0, b.err
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

func (b *failingBody) Close() error { return nil }

// CheckTokenTTL used to discard the io.ReadAll error (#4063). When the connection
// died after a complete, valid root-token reply ("ttl": 0 means no expiry), the
// caller got (0, false, nil), which looks like a healthy never-expiring token. A
// failed read must be an error, and the error must not carry any body text.
func TestVault_CheckTokenTTL_BodyReadFailureIsAnError(t *testing.T) {
	const marker = "BODYMARKER-4063"
	boom := errors.New("connection reset")
	for name, data := range map[string]string{
		"valid reply then failure": `{"data":{"ttl":0,"renewable":false,"policies":["root"],"note":"` + marker + `"}}`,
		"partial reply":            `{"data":{"ttl":0`,
		"nothing read":             ``,
	} {
		t.Run(name, func(t *testing.T) {
			c := NewVaultConnector("v", "http://127.0.0.1:1", "tok", nil)
			c.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{},
					Body:       &failingBody{data: data, err: boom},
				}, nil
			})
			ttl, renewable, err := c.CheckTokenTTL(context.Background())
			require.Error(t, err)
			assert.ErrorIs(t, err, boom)
			assert.False(t, strings.Contains(err.Error(), marker), "body text reached the error: %v", err)
			assert.Zero(t, ttl)
			assert.False(t, renewable)
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var _ io.ReadCloser = (*failingBody)(nil)
