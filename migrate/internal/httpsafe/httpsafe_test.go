package httpsafe

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCappedTransport_CapsOversizedResponse is the "oversized value" case: a malicious or
// misbehaving endpoint returning far more than MaxResponseBytes must not be read in full by
// this process — CappedTransport must truncate the body a caller sees to MaxResponseBytes,
// regardless of how much the server actually sent.
func TestCappedTransport_CapsOversizedResponse(t *testing.T) {
	const oversized = MaxResponseBytes + (1 << 20) // 1MB over the cap
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, io.LimitReader(neverEndingReader{}, oversized))
	}))
	defer srv.Close()

	cl := &http.Client{Transport: CappedTransport{Base: http.DefaultTransport}}
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(body) != MaxResponseBytes {
		t.Errorf("read %d bytes, want exactly the %d-byte cap", len(body), MaxResponseBytes)
	}
}

func TestRefuseRedirect_ReturnsErrUseLastResponse(t *testing.T) {
	if err := RefuseRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Errorf("RefuseRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

func TestClient_RefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect target was followed: %s %s — a followed redirect could leak credentials to an unconfigured host", r.Method, r.URL.Path)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	cl := Client()
	resp, err := cl.Get(redirector.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (the redirect itself, not followed)", resp.StatusCode, http.StatusFound)
	}
}

// neverEndingReader streams zero bytes forever — paired with io.LimitReader above to produce
// an exact oversized body without allocating it up front.
type neverEndingReader struct{}

func (neverEndingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
