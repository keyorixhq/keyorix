package wirefuzz

// health_check_test.go closes the "single-connection" gap the B1 report named as a
// caveat: the liveness/robustness oracles only ever observed the SAME connection that
// carried the abusive input, so an input that wedged the listener or leaked a
// per-connection resource — taking down the server for the NEXT, legitimate client —
// would have gone unseen.
//
// After every fuzz exec, the three targets now open a FRESH connection and drive one
// known-GOOD request through it. The server MUST still serve it. A failure here is a
// denial-of-service signal: one abusive connection broke the listener for later
// clients. The probe is deliberately lenient about the response CONTENT (any complete,
// parseable response of any status counts as "served") and strict only about the
// server actually completing a response on a new connection — so a legitimately
// degraded-but-alive server never false-fires, while a dead/wedged listener always
// does.
//
// RED/GREEN proof: TestRedProof_HTTPHealthProbe / TestRedProof_GRPCHealthProbe
// (oracle_redproof_test.go region below) watch each probe return nil against a live
// server and a non-nil error against a stopped one — "a guard nobody has watched fail
// is not a guard".
//
// What the probe does NOT verify: it is still a single later connection, not a
// sustained load; it does not measure latency regression (a server that recovers but
// is now 100x slower still passes as long as it answers within the probe deadline);
// and it cannot attribute WHICH abusive input caused a failure beyond the one that
// immediately preceded it (the harness serializes execs under http1Mu, so the
// preceding exec is the only suspect, but a slow cumulative leak would be blamed on
// whichever exec happens to cross the threshold).

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// probeTimeout bounds a single health probe. Generous: on a loopback listener a live
// server answers in microseconds, so this only ever elapses when the server is
// genuinely not serving. (Timeouts detect hangs; they do not enforce speed.)
const probeTimeout = 4 * time.Second

// httpHealthProbe opens a NEW TCP connection to addr and sends a minimal, always-valid
// GET /health HTTP/1.1 request (an unauthenticated liveness route, server/http/
// router.go). It returns nil iff the server returns a complete, parseable HTTP/1.1
// response — proof the listener still serves a later clean request. Any dial/write/read
// failure, or an unparseable/absent response, is returned as an error (the DoS signal).
// The response STATUS is not asserted: a degraded-but-alive server (e.g. a 503 health
// body) still proves the listener is up, which is exactly the property under test.
func httpHealthProbe(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return fmt.Errorf("dial fresh connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	const req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("write health request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return fmt.Errorf("read health response (listener not serving?): %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == 0 {
		return fmt.Errorf("health response had no status line")
	}
	return nil
}

// grpcHealthProbe opens a NEW connection to a gRPC/HTTP2 listener, performs the client
// preface + SETTINGS handshake, and requires the server to emit its own (non-ack)
// SETTINGS frame — which a healthy grpc-go server sends immediately on accepting any
// new HTTP/2 connection. Reading that frame proves the HTTP/2 serving goroutine is
// alive for a FRESH connection after the abusive one. A dial/handshake/read failure, or
// a connection that never yields a server SETTINGS frame within the deadline, is the
// DoS signal.
func grpcHealthProbe(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return fmt.Errorf("dial fresh connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return fmt.Errorf("write client preface: %w", err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		return fmt.Errorf("write client settings: %w", err)
	}
	// The healthy server sends its SETTINGS frame first. Read frames until we see a
	// non-ack SETTINGS (liveness confirmed) or the deadline/connection fails.
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return fmt.Errorf("read server frame (listener not serving?): %w", err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			return nil
		}
	}
}
