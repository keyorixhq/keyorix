package cmd

// hostile_server_redgreen_test.go -- the red/green proof that FuzzCLIHostileServer's
// oracles are load-bearing (CLAUDE.md: "a guard nobody has watched fail is not a
// guard"). Each sub-test runs the SAME hostile server against two clients:
//
//   GREEN -- the REAL hardened client newAPIClient builds (refuseRedirect, 10 MiB cap).
//   RED   -- a deliberately UN-hardened client (plain http.Client, follows redirects,
//            no size cap) -- the shape the hardening exists to prevent.
//
// The oracle's detector (NetMeter air-gap, the evil-target recorder, ErrResponseTooLarge)
// must be silent on GREEN and fire on RED. No production code is edited: the RED client
// is built in-test from the exported apiclient constructors.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// unhardenedClient builds a ClientWithResponses with NO redirect refusal and NO size
// cap -- a bare http.Client routed through nm so its dials are still metered. It carries
// the same bearer token the hardened client does.
func unhardenedClient(t *testing.T, serverURL string, nm *resguard.NetMeter) *apiclient.ClientWithResponses {
	t.Helper()
	httpClient := &http.Client{Transport: nm.Transport()} // no CheckRedirect, no cappingTransport
	c, err := apiclient.NewClientWithResponses(serverURL,
		apiclient.WithHTTPClient(httpClient),
		apiclient.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+hostileToken)
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("build unhardened client: %v", err)
	}
	return c
}

func TestCLIHostile_RedGreen_RedirectAirGap(t *testing.T) {
	// A server that 302-redirects the token-bearing request to the cloud metadata IP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://"+metadataSSRFHost+"/latest/meta-data/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	// GREEN: the real hardened client. Air-gapped NetMeter installed as default so its
	// cappingTransport dials through it. No non-loopback dial must occur.
	nmG := resguard.NewNetMeter()
	restore := nmG.InstallDefault()
	client, err := newAPIClient(srv.URL, hostileToken)
	if err != nil {
		restore()
		t.Fatalf("newAPIClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, gerr := client.GetVersionWithResponse(ctx)
	cancel()
	restore()
	if gerr == nil {
		t.Fatalf("GREEN: hardened client did not error on a redirect (fail-open)")
	}
	if nmG.NonLoopback() != 0 {
		t.Fatalf("GREEN: hardened client made %d non-loopback dial(s) -- refuseRedirect did not fire", nmG.NonLoopback())
	}

	// RED: the unhardened client follows the redirect; the air-gap must fire.
	nmR := resguard.NewNetMeter()
	restore2 := nmR.InstallDefault()
	rc := unhardenedClient(t, srv.URL, nmR)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = rc.GetVersionWithResponse(ctx2)
	cancel2()
	restore2()
	if nmR.NonLoopback() == 0 {
		t.Fatalf("RED: unhardened redirect-following client made ZERO non-loopback dials -- the air-gap oracle would not have detected the SSRF")
	}
	t.Logf("RED fired: unhardened client made %d non-loopback dial(s) to %s", nmR.NonLoopback(), metadataSSRFHost)
}

func TestCLIHostile_RedGreen_RedirectCredentialForward(t *testing.T) {
	var evilHits, evilAuth int64
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&evilHits, 1)
		if r.Header.Get("Authorization") != "" {
			atomic.AddInt64(&evilAuth, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"api_version":99}`))
	}))
	defer evil.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://"+evil.Listener.Addr().String()+"/stolen")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	// GREEN: the hardened client refuses the redirect; evil gets nothing.
	nmG := resguard.NewNetMeter()
	restore := nmG.InstallDefault()
	client, err := newAPIClient(srv.URL, hostileToken)
	if err != nil {
		restore()
		t.Fatalf("newAPIClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = client.GetVersionWithResponse(ctx)
	cancel()
	restore()
	if atomic.LoadInt64(&evilHits) != 0 {
		t.Fatalf("GREEN: hardened client forwarded %d request(s) to the evil target", evilHits)
	}

	// RED: the unhardened client follows the redirect and forwards the token.
	nmR := resguard.NewNetMeter()
	restore2 := nmR.InstallDefault()
	rc := unhardenedClient(t, srv.URL, nmR)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = rc.GetVersionWithResponse(ctx2)
	cancel2()
	restore2()
	if atomic.LoadInt64(&evilHits) == 0 {
		t.Fatalf("RED: unhardened client did not reach the evil target -- the forward oracle would not have detected it")
	}
	if atomic.LoadInt64(&evilAuth) == 0 {
		t.Fatalf("RED: unhardened client reached the evil target but WITHOUT the token -- the credential-forward oracle would not have detected it")
	}
	t.Logf("RED fired: unhardened client forwarded the bearer token to the evil target (%d hit(s), %d with Authorization)", evilHits, evilAuth)
}

func TestCLIHostile_RedGreen_SizeCap(t *testing.T) {
	// A server that writes ~12 MiB -- over the 10 MiB cap.
	const over = (10 << 20) + (256 << 10)
	// Non-json content-type so ParseGetVersionResponse skips json.Unmarshal and the
	// read-full-body signal is observable on rr.Body (an incidental parse error would
	// otherwise mask it). The 10 MiB cap is content-type-independent, so GREEN still fires.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = 'A'
		}
		written := 0
		for written < over {
			n, err := w.Write(chunk)
			written += n
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	nm := resguard.NewNetMeter()
	restore := nm.InstallDefault()
	defer restore()

	// GREEN: the hardened client caps the read and errors.
	client, err := newAPIClient(srv.URL, hostileToken)
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, gerr := client.GetVersionWithResponse(ctx)
	cancel()
	if gerr == nil {
		t.Fatalf("GREEN: hardened client accepted a %d-byte reply without error (size cap did not fire)", over)
	}
	if !errors.Is(gerr, apiclient.ErrResponseTooLarge) {
		t.Logf("GREEN note: hardened client errored but not with ErrResponseTooLarge (%v) -- still fail-closed", gerr)
	}

	// RED: the unhardened client reads the whole oversized body with no error.
	rc := unhardenedClient(t, srv.URL, nm)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	rr, rerr := rc.GetVersionWithResponse(ctx2)
	cancel2()
	if rerr != nil {
		t.Fatalf("RED: unhardened client errored (%v) -- expected it to swallow the whole oversized body", rerr)
	}
	if len(rr.Body) <= (10 << 20) {
		t.Fatalf("RED: unhardened client read only %d bytes -- expected it to read past the 10 MiB cap (the cap is what the oracle proves load-bearing)", len(rr.Body))
	}
	t.Logf("RED fired: unhardened client read %d bytes (past the 10 MiB cap) with no error", len(rr.Body))
}
