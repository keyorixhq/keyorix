// remote_client_timeout_test.go — #1521: the old defaultRemoteClientTimeout
// was a single flat http.Client.Timeout bounding the ENTIRE round trip, so it
// could not tell "the server is unreachable" from "a large transfer is
// slowly, genuinely progressing over a slow link" -- both looked identical
// to a clock that only measures elapsed time since the request started.
//
// Verified red against the pre-fix behaviour before writing the fix: with a
// single http.Client{Timeout: X}, a handler that writes a byte every
// interval < X but whose CUMULATIVE elapsed time exceeds X fails outright
// (TestOldTimeoutShape_KillsASlowButProgressingTransfer, kept as a permanent
// regression guard against reintroducing a flat timeout). The three tests
// below exercise the fixed shape: a genuinely unreachable dial target fails
// fast and says so, a genuine mid-transfer stall is cut off and says so, and
// a slow-but-always-progressing transfer completes even though its total
// duration would have tripped the old flat timeout.
package common

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTimeoutTestTransport builds the real newRemoteTransport with short
// timeouts so these tests run in milliseconds instead of waiting out
// defaultConnectTimeout (5s) / defaultIdleTransferTimeout (30s).
func newTimeoutTestClient(endpoint string, connectTimeout, idleTimeout time.Duration) *RemoteClient {
	return &RemoteClient{
		Endpoint: endpoint,
		Token:    "tok",
		hc:       &http.Client{Transport: newRemoteTransport(connectTimeout, idleTimeout)},
	}
}

// TestOldTimeoutShape_KillsASlowButProgressingTransfer is the RED-BEFORE
// control: it proves the bug this fix closes actually exists by reproducing
// it directly against a bare http.Client{Timeout: ...} (the old shape), not
// against RemoteClient. A handler writes 6 chunks, each after a 40ms sleep
// (240ms total, always making progress, no single gap exceeds 40ms), against
// a flat 150ms client timeout -- shorter than the total but longer than any
// single gap. The old shape has no way to tell "slow but moving" from "one
// long stall" and fails; kept permanently so the old shape can never be
// silently reintroduced without this test going red again.
func TestOldTimeoutShape_KillsASlowButProgressingTransfer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		for range 6 {
			time.Sleep(40 * time.Millisecond)
			_, _ = w.Write([]byte("x"))
			flusher.Flush()
		}
	}))
	defer srv.Close()

	oldShapeClient := &http.Client{Timeout: 150 * time.Millisecond}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	// Client.Timeout bounds header receipt AND body reading, but Do() only
	// returns once headers arrive (after the first 40ms chunk) -- well inside
	// the 150ms budget. The bug only shows up when the BODY is actually read,
	// since the remaining chunks (200ms more) are what blows the budget.
	resp, err := oldShapeClient.Do(req)
	if err != nil {
		t.Fatalf("expected headers to arrive within budget (only ~40ms elapsed by then), got: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	_, err = io.ReadAll(resp.Body)
	if err == nil {
		t.Fatal("expected reading the body of a transfer whose TOTAL duration exceeds Client.Timeout to fail, even though every individual gap is fine -- got no error")
	}
	if !strings.Contains(err.Error(), "Client.Timeout") && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("expected a client-timeout-shaped error, got: %v", err)
	}
}

// TestRemoteClient_Unreachable_FailsFastWithClearMessage: dialing a closed
// port fails immediately (connection refused) at the dial phase, well within
// the connect timeout, and the message says the server couldn't be reached
// -- not a generic "request failed".
func TestRemoteClient_Unreachable_FailsFastWithClearMessage(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // now nothing is listening on addr -- connection refused

	rc := newTimeoutTestClient("http://"+addr, 2*time.Second, 2*time.Second)

	start := time.Now()
	err = rc.Get(context.Background(), "/whatever", &struct{}{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error against an unreachable server")
	}
	if !strings.Contains(err.Error(), "could not reach server") {
		t.Errorf("error = %q, want it to say the server could not be reached", err.Error())
	}
	if elapsed > 1*time.Second {
		t.Errorf("took %s to fail against a closed port -- should fail immediately (connection refused), not wait out any timeout", elapsed)
	}
}

// TestRemoteClient_GenuineStall_CutOffWithClearMessage: the server accepts
// the connection (so it IS reachable) but then never writes a single byte of
// response. With a short idle timeout, the request is cut off once that
// idle window elapses, and the message says the transfer stalled -- not a
// generic "request failed".
func TestRemoteClient_GenuineStall_CutOffWithClearMessage(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Read the request so the write side of the roundtrip completes, then go
		// silent forever -- never write a response. Simulates a hung server.
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		select {} //nolint:staticcheck // deliberately block until the test's idle timeout fires and the deferred Close runs
	}()

	const idleTimeout = 150 * time.Millisecond
	rc := newTimeoutTestClient("http://"+ln.Addr().String(), 2*time.Second, idleTimeout)

	start := time.Now()
	err = rc.Get(context.Background(), "/whatever", &struct{}{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error against a server that never responds")
	}
	if !strings.Contains(err.Error(), "transfer stalled") {
		t.Errorf("error = %q, want it to say the transfer stalled", err.Error())
	}
	if elapsed < idleTimeout {
		t.Errorf("took only %s, shorter than the %s idle timeout -- cut off too early", elapsed, idleTimeout)
	}
	if elapsed > 2*idleTimeout {
		t.Errorf("took %s, more than 2x the %s idle timeout -- not cut off promptly", elapsed, idleTimeout)
	}
}

// TestRemoteClient_SlowButProgressing_Completes is the direct fix-in-action
// counterpart to TestOldTimeoutShape_KillsASlowButProgressingTransfer above:
// same shape (6 chunks, 40ms apart, 240ms total), but through RemoteClient's
// real idle-timeout transport with a 100ms idle window. Every individual gap
// (40ms) is well under the idle window (100ms), so the transfer completes
// successfully even though its total duration (240ms) exceeds the idle
// window more than twice over -- proving the timeout is genuinely no-progress-
// shaped, not a disguised total-elapsed clock.
func TestRemoteClient_SlowButProgressing_Completes(t *testing.T) {
	const chunkGap = 40 * time.Millisecond
	const chunks = 6

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(hdrContentType, mimeJSON)
		flusher := w.(http.Flusher)
		w.Write([]byte(`{"data":`)) //nolint:errcheck
		flusher.Flush()
		for range chunks {
			time.Sleep(chunkGap)
			w.Write([]byte("1")) //nolint:errcheck
			flusher.Flush()
		}
		w.Write([]byte("}")) //nolint:errcheck
	}))
	defer srv.Close()

	const idleTimeout = 100 * time.Millisecond // > chunkGap, < chunks*chunkGap
	rc := newTimeoutTestClient(srv.URL, 2*time.Second, idleTimeout)

	var out int
	start := time.Now()
	err := rc.Get(context.Background(), "/whatever", &out)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected the slow-but-always-progressing transfer to succeed, got: %v", err)
	}
	if elapsed < chunks*chunkGap {
		t.Errorf("completed in %s, faster than the %d chunks could have produced -- test fixture problem", elapsed, chunks)
	}
	if elapsed <= idleTimeout {
		t.Errorf("completed in %s, at or under the idle timeout (%s) -- this doesn't actually demonstrate surviving PAST the idle window", elapsed, idleTimeout)
	}
}

// sanity check that classifyTransportError's dial/read/write branches don't
// panic or misfire on a plain, non-network error (e.g. context cancellation
// surfaced through http.Client.Do) -- it must fall through to the fallback
// wording unchanged.
func TestClassifyTransportError_NonNetworkErrorPassesThroughFallback(t *testing.T) {
	rc := &RemoteClient{Endpoint: "http://example.invalid"}
	plain := errors.New("boom")
	got := rc.classifyTransportError(plain, "request failed")
	if !strings.Contains(got.Error(), "request failed") || !strings.Contains(got.Error(), "boom") {
		t.Errorf("got %q, want it to contain both the fallback wording and the original error", got.Error())
	}
	if strings.Contains(got.Error(), "could not reach") || strings.Contains(got.Error(), "stalled") {
		t.Errorf("got %q, a non-network error should never be classified as a network failure", got.Error())
	}
}
