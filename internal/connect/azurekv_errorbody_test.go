//go:build !noazure

package connect

import (
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

type staticAzureCred struct{}

func (staticAzureCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "t"}, nil
}

// nestedBody is a ~40 KB JSON document nested well below encoding/json's depth limit.
func nestedBody() string {
	const depth = 4400
	return strings.Repeat(`{"error":`, depth) + `1` + strings.Repeat(`}`, depth)
}

// azureClientAgainst builds the real azsecrets client over the Azure hardened
// transport, pointed at a TLS stub that answers every request with status/body.
func azureClientAgainst(t *testing.T, status int, header http.Header, body string) *azsecrets.Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maps.Copy(w.Header(), header)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	cl, err := azsecrets.NewClient(srv.URL, staticAzureCred{}, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: &http.Client{
				Transport:     newAzureHardenedTransport(srv.Client().Transport.(*http.Transport)),
				CheckRedirect: refuseRedirect,
			},
			Retry: policy.RetryOptions{MaxRetries: -1},
		},
		DisableChallengeResourceVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func TestAzureKV_NestedErrorBodyDoesNotAmplifyMemory(t *testing.T) {
	body := nestedBody()
	if len(body) > 50<<10 {
		t.Fatalf("test body too large: %d", len(body))
	}
	for _, status := range []int{400, 404, 500, 502, 503} {
		cl := azureClientAgainst(t, status, nil, body)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := cl.GetSecret(context.Background(), "name", "", nil)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Fatalf("status %d: expected an error", status)
		}
		var re *azcore.ResponseError
		if !errors.As(err, &re) || re.StatusCode != status {
			t.Fatalf("status %d: status code not surfaced: %v", status, err)
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 8<<20 {
			t.Fatalf("status %d: GetSecret on a %d byte error body allocated %d MiB", status, len(body), alloc>>20)
		}
	}
}

func TestAzureKV_ErrorTextIsNotServerControlled(t *testing.T) {
	cl := azureClientAgainst(t, 500, nil, `{"error":{"code":"X","message":"INJECTED\r\nline"}}`)
	_, err := cl.GetSecret(context.Background(), "name", "", nil)
	if err == nil || strings.Contains(err.Error(), "INJECTED") {
		t.Fatalf("server text reached the error: %v", err)
	}
	if !strings.Contains(err.Error(), "ERROR CODE: X") {
		t.Fatalf("a plain error code should still be surfaced: %v", err)
	}
}

type stubRT func(*http.Request) (*http.Response, error)

func (f stubRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestErrorBodyScrub_KeepsStatusAndHeadersForRetries(t *testing.T) {
	rt := errorBodyScrubRoundTripper{Transport: stubRT(func(r *http.Request) (*http.Response, error) {
		h := http.Header{}
		h.Set("Retry-After", "7")
		h.Set("Www-Authenticate", `Bearer authorization="https://login/x", resource="https://vault.azure.net"`)
		h.Set("X-Ms-Request-Id", "abc")
		h.Set("Content-Encoding", "gzip")
		return &http.Response{StatusCode: 429, Header: h, Body: io.NopCloser(strings.NewReader(nestedBody())), ContentLength: -1}, nil
	})}
	resp, err := rt.RoundTrip(httptest.NewRequest("GET", "https://v.example/secrets/x", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "7" || resp.Header.Get("X-Ms-Request-Id") != "abc" ||
		!strings.HasPrefix(resp.Header.Get("Www-Authenticate"), "Bearer ") {
		t.Fatalf("status/headers changed: %d %v", resp.StatusCode, resp.Header)
	}
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("Content-Encoding must not describe the replacement body")
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != scrubbedErrorBody(nil) || resp.ContentLength != int64(len(b)) {
		t.Fatalf("body = %q (len %d, ContentLength %d)", b, len(b), resp.ContentLength)
	}
}

func TestErrorBodyScrub_KeepsOnlyAPlainErrorCode(t *testing.T) {
	for name, tc := range map[string]struct{ in, wantCode string }{
		"plain code":        {`{"error":{"code":"SecretNotFound","message":"x\r\ny"}}`, "SecretNotFound"},
		"code with control": {`{"error":{"code":"A\r\nB"}}`, "UpstreamError"},
		"code with space":   {`{"error":{"code":"A B"}}`, "UpstreamError"},
		"code too long":     {`{"error":{"code":"` + strings.Repeat("a", 65) + `"}}`, "UpstreamError"},
		"code wrong type":   {`{"error":{"code":5}}`, "UpstreamError"},
		"not json":          {`<html>`, "UpstreamError"},
		"truncated nested":  {nestedBody()[:4096], "UpstreamError"},
		"empty":             {``, "UpstreamError"},
	} {
		t.Run(name, func(t *testing.T) {
			got := scrubbedErrorBody([]byte(tc.in))
			if want := `{"error":{"code":"` + tc.wantCode + `","message":"upstream error response body suppressed"}}`; got != want {
				t.Fatalf("got %s", got)
			}
		})
	}
}

func TestErrorBodyScrub_SuccessAndTransportErrorsPassThrough(t *testing.T) {
	const ok = `{"value":"v"}`
	rt := errorBodyScrubRoundTripper{Transport: stubRT(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(ok))}, nil
	})}
	resp, err := rt.RoundTrip(httptest.NewRequest("GET", "https://v.example/x", nil))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != ok {
		t.Fatalf("2xx body modified: %q", b)
	}
	boom := errors.New("boom")
	rt = errorBodyScrubRoundTripper{Transport: stubRT(func(*http.Request) (*http.Response, error) { return nil, boom })}
	if _, err := rt.RoundTrip(httptest.NewRequest("GET", "https://v.example/x", nil)); !errors.Is(err, boom) {
		t.Fatalf("transport error not passed through: %v", err)
	}
}

func TestErrorBodyScrub_BoundsReadOfOriginalBody(t *testing.T) {
	var read int64
	big := io.LimitReader(countingReader{&read}, 1<<30)
	rt := errorBodyScrubRoundTripper{Transport: stubRT(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 502, Header: http.Header{}, Body: io.NopCloser(big)}, nil
	})}
	if _, err := rt.RoundTrip(httptest.NewRequest("GET", "https://v.example/x", nil)); err != nil {
		t.Fatal(err)
	}
	if read > errorBodyDrainBytes+64<<10 {
		t.Fatalf("read %d bytes of the original error body", read)
	}
}

type countingReader struct{ n *int64 }

func (c countingReader) Read(p []byte) (int, error) {
	*c.n += int64(len(p))
	return len(p), nil
}
