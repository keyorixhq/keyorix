package wirefuzz

// FuzzWireHTTP2TLS closes the "HTTP/2-on-the-HTTP-listener-via-ALPN is not reached"
// gap named in the B1 report. The other HTTP/2 target (FuzzWireHTTP2) drives grpc-go's
// HTTP/2 implementation on the gRPC listener; this one stands the REAL REST router up
// behind a TLS listener whose ALPN advertises "h2", so an "h2" client reaches
// net/http's OWN HTTP/2 server (golang.org/x/net/http2 as embedded in net/http) — a
// DISTINCT framing code path, and the one a production deployment that terminates TLS
// in-process (rather than at a sidecar) actually exposes.
//
// The driver negotiates ALPN "h2" over TLS, asserts the negotiation actually selected
// h2 (so a silent fallback to HTTP/1.1 can never make this target vacuously pass — see
// the reachability red-proof), then emits a fuzz-controlled frame sequence against the
// REST endpoints.
//
// ORACLES (and what each does NOT verify):
//
//	(1) LIVENESS/BOUNDED — no server panic, 10s watchdog, 512 MiB heap-delta cap
//	    (evalAlloc). DOES NOT verify: CPU, goroutine/fd leaks (beyond the post-abuse
//	    health probe).
//	(2) AUTHZ/LEAK INVARIANCE, PER STREAM — a seeded secret's plaintext appears on a
//	    stream only if the credential sent on THAT stream's HEADERS is authorized to
//	    read it (evalH2Leak). The driver keeps the connection open until the response
//	    is complete (no half-close: see oracles_test.go), so an authorized read and a
//	    cross-tenant read are both reachable (TestAntiVacuity_HTTP2TLS). DOES NOT
//	    verify: a non-literal (e.g. encrypted) leak.
//	(3) POST-ABUSE HEALTH — a fresh TLS+h2 connection is still served a real GET
//	    /health afterwards.
//
// NOT AN ORACLE HERE: the HTTP/1 handler-count smuggling check (HTTP/2 stream muxing is
// inside net/http's h2 server, not a wrappable middleware — same limitation as
// FuzzWireHTTP2).
//
// RED/GREEN proof: TestRedProof_TLSALPNReachability (h2 is actually negotiated),
// TestRedProof_TLSHealthProbe, the planted-leak twin and TestAntiVacuity_HTTP2TLS.

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/keyorixhq/keyorix/internal/config"
	httpServer "github.com/keyorixhq/keyorix/server/http"
)

type tlsWireWorld struct {
	addr      string
	s         *seededStack
	clientCfg *tls.Config
}

// inMemoryTLSConfig builds a throwaway self-signed server cert (RSA-2048, 1-hour
// validity) and the matching server/client tls.Configs, both advertising ALPN "h2".
// InsecureSkipVerify on the client side skips chain/SAN verification (loopback test
// only), so no SAN is needed on the cert.
func inMemoryTLSConfig(tb testing.TB) (server, client *tls.Config) {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wirefuzz-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create certificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	server = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	client = &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // loopback test, self-signed cert
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	}
	return server, client
}

// buildTLSWireWorld seeds the shared stack and serves the real HTTP router over a TLS
// listener with ALPN "h2". http.Server.ServeTLS auto-configures net/http's HTTP/2
// server when the negotiated protocol is "h2".
func buildTLSWireWorld(tb testing.TB) *tlsWireWorld {
	tb.Helper()
	s := seedCore(tb)
	router, err := httpServer.NewRouter(&config.Config{}, s.c)
	if err != nil {
		tb.Fatalf("router: %v", err)
	}
	return serveTLSHandler(tb, router, s)
}

// serveTLSHandler serves h over TLS+ALPN h2 on loopback. The red twin plants a leaky
// handler here and drives it through the same tlsH2Drive and oracles as the real router.
func serveTLSHandler(tb testing.TB, h http.Handler, s *seededStack) *tlsWireWorld {
	tb.Helper()
	serverCfg, clientCfg := inMemoryTLSConfig(tb)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: wireReadHeaderTimeout,
		ReadTimeout:       wireReadTimeout,
		IdleTimeout:       wireIdleTimeout,
		MaxHeaderBytes:    wireMaxHeaderBytes,
		TLSConfig:         serverCfg,
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	tb.Cleanup(func() { _ = srv.Close() })

	return &tlsWireWorld{addr: ln.Addr().String(), s: s, clientCfg: clientCfg}
}

// restRequestHeaders is the pseudo-header set for an HTTP/2 request to a REST path over
// the h2 (net/http) listener. :scheme is https because the transport is TLS.
func restRequestHeaders(path, authority, authHdr string) []hpack.HeaderField {
	h := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: path},
		{Name: ":authority", Value: authority},
	}
	if authHdr != "" {
		h = append(h, hpack.HeaderField{Name: "authorization", Value: authHdr})
	}
	return h
}

// tlsH2Dial dials addr, completes the TLS handshake with ALPN, and returns the conn
// plus the negotiated protocol. The caller checks the protocol is "h2" (a fallback to
// http/1.1 would make the HTTP/2 framer plumbing meaningless).
func tlsH2Dial(addr string, cfg *tls.Config) (*tls.Conn, string, error) {
	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, "", err
	}
	conn := tls.Client(raw, cfg)
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, "", err
	}
	return conn, conn.ConnectionState().NegotiatedProtocol, nil
}

func FuzzWireHTTP2TLS(f *testing.F) {
	w := buildTLSWireWorld(f)

	f.Add([]byte{0, 0, 0})       // minimal HEADERS, no cred
	f.Add([]byte{0, 2, 0})       // HEADERS with admin cred (authorized read path)
	f.Add([]byte{1, 0, 0})       // HEADERS + DATA
	f.Add([]byte{2, 0, 0, 2, 0}) // RST flood
	f.Add([]byte{3, 0, 0})       // CONTINUATION chain
	f.Add([]byte{4, 0, 0})       // SETTINGS abuse
	f.Add([]byte{0, 0, 2, 1})    // admin GET secret A (authorized read)
	f.Add([]byte{0, 0, 3, 2})    // reader GET secret B (must be denied)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		http1Mu.Lock()
		defer http1Mu.Unlock()

		var res *h2Result
		var proto string
		var timedOut bool
		delta := measureAlloc(func() { res, proto, timedOut = tlsH2Drive(w, data, 10*time.Second) })

		if timedOut {
			t.Fatalf("HANG: TLS HTTP/2 exchange exceeded watchdog for %d-byte input", len(data))
		}
		if proto != "" && proto != "h2" {
			// A non-h2 negotiation means the listener did not expose HTTP/2 via ALPN;
			// the whole target would be vacuous. Fail loudly rather than pass quietly.
			t.Fatalf("ALPN negotiated %q, not h2 — the HTTP/2-on-HTTP-listener surface is not being reached", proto)
		}
		if v := evalAlloc(delta); v != "" {
			t.Fatalf("%s for %d-byte TLS HTTP/2 input", v, len(data))
		}
		if v := evalH2Leak(res, w.s.valA, w.s.valB); v != "" {
			t.Fatalf("%s\nresp=%q", v, truncate(res.all(), 800))
		}
		if err := tlsH2HealthProbe(w.addr, w.clientCfg); err != nil {
			t.Fatalf("POST-ABUSE HEALTH: TLS HTTP/2 listener did not serve a fresh connection after %d-byte input: %v", len(data), err)
		}
	})
}

// tlsH2Drive negotiates ALPN h2, sends the client preface + a fuzz-controlled frame
// sequence against the REST router, and reads what the server returns. Returns the raw
// response bytes, which credentials were on the wire, the negotiated ALPN protocol, and
// whether the watchdog fired.
func tlsH2Drive(w *tlsWireWorld, data []byte, watchdog time.Duration) (res *h2Result, proto string, timedOut bool) {
	type result struct {
		res   *h2Result
		proto string
	}
	ch := make(chan result, 1)
	go func() {
		res := newH2Result()
		conn, negotiated, err := tlsH2Dial(w.addr, w.clientCfg)
		if err != nil {
			ch <- result{res, ""}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(watchdog))
		if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
			ch <- result{res, negotiated}
			return
		}
		fr := newH2Framer(conn)
		if err := fr.WriteSettings(); err != nil {
			ch <- result{res, negotiated}
			return
		}

		rd := &byteReader{data: data}
		streamID := uint32(1)
		var lastOpen uint32
		open := map[uint32]bool{}
		nFrames := int(rd.u8()%8) + 1
		for range nFrames {
			switch rd.u8() % 6 {
			case 0: // well-formed REST request to a secret/health path, maybe with a cred
				authHdr, s := tlsPickCred(w, rd)
				res.creds[streamID] = s
				path := tlsPickPath(w, rd)
				hb := encodeHeaders(restRequestHeaders(path, "127.0.0.1", authHdr))
				_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: hb, EndHeaders: true, EndStream: true})
				open[streamID], lastOpen = true, streamID
				streamID += 2
			case 1: // DATA on a GET stream (illegal: body on a no-body method), on the last OPENED stream
				target := lastOpen
				if target == 0 {
					target = streamID
				}
				_ = fr.WriteData(target, rd.u8()%2 == 0, bytes.Repeat([]byte{rd.u8()}, int(rd.u8())))
			case 2: // RST_STREAM flood
				for range int(rd.u8()%32) + 1 {
					_ = fr.WriteRSTStream(streamID, http2.ErrCode(rd.u8()))
				}
			case 3: // HEADERS without END_HEADERS + CONTINUATION
				hb := encodeHeaders(restRequestHeaders(tlsPickPath(w, rd), "127.0.0.1", ""))
				mid := len(hb) / 2
				_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: hb[:mid], EndHeaders: false})
				_ = fr.WriteContinuation(streamID, true, hb[mid:])
				open[streamID], lastOpen = true, streamID
				streamID += 2
			case 4: // SETTINGS abuse
				_ = fr.WriteSettings(
					http2.Setting{ID: http2.SettingInitialWindowSize, Val: rd.u32()},
					http2.Setting{ID: http2.SettingMaxFrameSize, Val: rd.u32()},
				)
			default: // WINDOW_UPDATE storm (incl. 0 increments — protocol errors)
				_ = fr.WriteWindowUpdate(rd.u32()%8, rd.u32())
			}
		}
		_ = fr.WriteSettingsAck()
		readH2(conn, fr, open, res)
		ch <- result{res, negotiated}
	}()
	select {
	case r := <-ch:
		return r.res, r.proto, false
	case <-time.After(watchdog + 2*time.Second):
		return newH2Result(), "", true
	}
}

func tlsPickCred(w *tlsWireWorld, rd *byteReader) (authHdr string, sent credsSent) {
	switch rd.u8() % 4 {
	case 0:
		return "", sent
	case 1:
		return "Bearer garbage-not-a-real-token", sent
	case 2:
		sent.admin = true
		return "Bearer " + w.s.adminTok, sent
	default:
		sent.reader = true
		return "Bearer " + w.s.readTok, sent
	}
}

func tlsPickPath(w *tlsWireWorld, rd *byteReader) string {
	return rd.pick([]string{
		"/health",
		"/api/v1/secrets/value?ref=" + w.s.refA,
		"/api/v1/secrets/value?ref=" + w.s.refB,
		"/api/v1/secrets/",
		"/api/v1/secrets/value?ref=../../etc",
	})
}

// tlsH2HealthProbe opens a FRESH TLS+h2 connection, confirms ALPN selected h2, and
// requires the server to answer a real GET /health with a :status — proof the listener
// still serves a later clean client after the abusive exchange, not merely that it
// accepts connections and sends SETTINGS.
func tlsH2HealthProbe(addr string, cfg *tls.Config) error {
	conn, proto, err := tlsH2Dial(addr, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if proto != "h2" {
		return &alpnError{got: proto}
	}
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return err
	}
	fr := newH2Framer(conn)
	if err := fr.WriteSettings(); err != nil {
		return err
	}
	return h2ProbeRequest(conn, fr, restRequestHeaders("/health", "127.0.0.1", ""), nil, ":status")
}

type alpnError struct{ got string }

func (e *alpnError) Error() string { return "ALPN negotiated " + e.got + ", not h2" }
