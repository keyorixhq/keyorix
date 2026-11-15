// Package azurefuzz drives the real Azure SDK (azcore pipeline + azsecrets Key
// Vault client) against a hostile loopback server whose HTTP status line,
// headers, body and wire framing are all derived from fuzz input.
//
// The point is to attack the THIRD-PARTY library directly through its public API
// only (azsecrets.Client.GetSecret, which runs azcore's retry + bearer-token
// challenge-authentication pipeline) with NO Keyorix wrapper in the loop, so any
// finding localises to the SDK (or the stdlib net/http response reader under
// it), not to Keyorix's own response-handling code.
//
// This file is the fake server + fuzz-input decoder (identical in shape to the
// AWS harness's). The azsecrets challenge-auth handshake means a fuzzer-chosen
// 401 + WWW-Authenticate response on the first request drives the challenge
// parser; see azure_fuzz_test.go.
package azurefuzz

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// azcore's bearer-token policy refuses to attach a token to a non-TLS endpoint
// ("authorized requests are not permitted for non-TLS protected (https)
// endpoints"), so the Key Vault client never reaches the server over http.
// The fake server therefore serves TLS with a cached self-signed loopback cert,
// and the client is configured (newVaultClient) to skip verification. This is a
// transport detail only: the fuzzer still controls all HTTP response bytes,
// written verbatim over the TLS connection.
var (
	certOnce sync.Once
	certVal  tls.Certificate
	certErr  error
)

func loopbackCert() (tls.Certificate, error) {
	certOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			certErr = err
			return
		}
		tmpl := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "127.0.0.1"},
			NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			DNSNames:     []string{"localhost"},
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
		if err != nil {
			certErr = err
			return
		}
		certVal = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return certVal, certErr
}

// respSpec is the fuzzer-controlled description of ONE HTTP response the fake
// server will write. The fuzzer can ask for well-framed responses (so the SDK
// deserializer is exercised with parseable-looking bodies) or raw verbatim
// bytes (so net/http's own response reader is exercised with arbitrary
// framing).
type respSpec struct {
	raw         bool   // write body verbatim with no synthesised status/headers
	status      int    // 100..599
	contentType string // Content-Type header value
	extraHdr    string // one extra "Name: Value" header line (fuzzer-controlled)
	body        []byte // response body bytes
	// lyingLen, when >0, is written as Content-Length instead of len(body);
	// combined with closeAfterBody it models "server declares N bytes, sends
	// fewer, then closes mid-body" — the ignored-read-error case.
	lyingLen        int
	closeAfterBody  bool // close the connection right after writing the body
	chunked         bool // use Transfer-Encoding: chunked framing
	truncateInChunk bool // in chunked mode, announce a big chunk then send little
}

// decodeSpecs turns fuzz bytes into a (possibly empty) cycle of response specs.
// A server with multiple specs serves them round-robin across the retries the
// SDK may issue, so the fuzzer can explore "first attempt 500, retry 200" etc.
func decodeSpecs(data []byte) []respSpec {
	r := &reader{b: data}
	n := int(r.u8()%4) + 1 // 1..4 specs
	specs := make([]respSpec, 0, n)
	cts := []string{
		"application/x-amz-json-1.1",
		"application/x-amz-json-1.0",
		"text/xml",
		"application/json",
		"text/plain",
		"",
	}
	for range n {
		var s respSpec
		flags := r.u8()
		s.raw = flags&0x01 != 0
		s.closeAfterBody = flags&0x02 != 0
		s.chunked = flags&0x04 != 0
		s.truncateInChunk = flags&0x08 != 0
		// status in 100..599
		s.status = 100 + int(r.u16()%500)
		s.contentType = cts[int(r.u8())%len(cts)]
		if flags&0x10 != 0 {
			// Azure-specific: feed the bearer-token challenge-authentication
			// parser a fuzzer-controlled WWW-Authenticate header. Paired with a
			// 401 status this drives azcore's keyvault challenge policy, which
			// parses authorization/resource/scope tokens out of this value.
			s.extraHdr = "WWW-Authenticate: " + sanitizeHeader(r.lenPrefixed(256))
		}
		s.body = r.lenPrefixed(1 << 16)
		if flags&0x20 != 0 {
			// declare a larger Content-Length than we actually send
			s.lyingLen = len(s.body) + int(r.u16()) + 1
		}
		specs = append(specs, s)
	}
	return specs
}

// sanitizeHeader strips CR/LF so a fuzzer-controlled header value cannot inject
// extra header lines — we want to test the CLIENT's parsing of a hostile server,
// not accidentally let the fuzzer forge a different response shape than declared.
func sanitizeHeader(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\r' || c == '\n' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) u8() int {
	if r.pos >= len(r.b) {
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return int(v)
}

func (r *reader) u16() int {
	return r.u8() | r.u8()<<8
}

// lenPrefixed reads a 2-byte length (capped at max) then that many bytes.
func (r *reader) lenPrefixed(max int) []byte {
	n := min(r.u16(), max)
	out := make([]byte, 0, n)
	for range n {
		if r.pos >= len(r.b) {
			break
		}
		out = append(out, r.b[r.pos])
		r.pos++
	}
	return out
}

// fakeServer is a loopback TCP server that answers every HTTP request it reads
// with the next respSpec in its cycle, writing bytes directly to the connection
// so framing is under fuzzer control.
type fakeServer struct {
	ln        net.Listener
	specs     []respSpec
	mu        sync.Mutex
	idx       int
	lastTrunc bool // did the most-recently-served response truncate its body?
	served    int  // number of responses served
	closed    chan struct{}
	tlsConfig *tls.Config
}

// bodyAllowedForStatus mirrors net/http's own rule: 1xx, 204 and 304 responses
// have no message body, so Content-Length / chunked framing on them is ignored
// by the client and reading nothing is correct, not truncation.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204, status == 304:
		return false
	}
	return true
}

// specTruncates mirrors writeResponse's branch precedence exactly: it reports
// whether the bytes actually put on the wire for s declare more body than they
// deliver AND the status is one for which the client will actually read a body
// (the condition under which the client MUST surface a read error). Gating on
// bodyAllowedForStatus closes a harness over-prediction: a lying Content-Length
// on a 204 is legitimately ignored (crasher c8f7163e047ef984, HARNESS-BUG).
func specTruncates(s respSpec) bool {
	if s.raw {
		return false // raw framing excluded from oracle (d)
	}
	status := s.status
	if status < 100 || status > 599 {
		status = 200 // matches writeResponse's normalisation
	}
	if !bodyAllowedForStatus(status) {
		return false
	}
	if s.chunked {
		return s.truncateInChunk
	}
	return s.lyingLen > len(s.body)
}

func newFakeServer(specs []respSpec) (*fakeServer, error) {
	if len(specs) == 0 {
		specs = []respSpec{{status: 200, contentType: "application/json", body: []byte("{}")}}
	}
	cert, err := loopbackCert()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	fs := &fakeServer{
		ln:        ln,
		specs:     specs,
		closed:    make(chan struct{}),
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	go fs.serve()
	return fs, nil
}

func (fs *fakeServer) url() string { return "https://" + fs.ln.Addr().String() }

func (fs *fakeServer) Close() {
	select {
	case <-fs.closed:
	default:
		close(fs.closed)
	}
	_ = fs.ln.Close()
}

func (fs *fakeServer) nextSpec() respSpec {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	s := fs.specs[fs.idx%len(fs.specs)]
	fs.idx++
	fs.served++
	fs.lastTrunc = specTruncates(s)
	return s
}

// lastResponseTruncated reports whether the response the client last received
// (i.e. the one it ultimately acted on) declared more body than it delivered.
func (fs *fakeServer) lastResponseTruncated() bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.served > 0 && fs.lastTrunc
}

func (fs *fakeServer) serve() {
	for {
		conn, err := fs.ln.Accept()
		if err != nil {
			return
		}
		go fs.handle(conn)
	}
}

func (fs *fakeServer) handle(rawConn net.Conn) {
	defer func() { _ = rawConn.Close() }()
	var conn = rawConn
	if fs.tlsConfig != nil {
		tconn := tls.Server(rawConn, fs.tlsConfig)
		if err := tconn.Handshake(); err != nil {
			return
		}
		conn = tconn
	}
	br := bufio.NewReader(conn)
	// Minimally consume the request: read the request line + headers until the
	// blank line. We ignore the body (the SDK sends small signed JSON/query
	// bodies). This is enough for the client transport to consider the request
	// written and move on to reading our response.
	drainRequest(br)
	spec := fs.nextSpec()
	writeResponse(conn, spec)
}

func drainRequest(br *bufio.Reader) {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			return
		}
	}
}

func writeResponse(conn net.Conn, s respSpec) {
	if s.raw {
		_, _ = conn.Write(s.body)
		return
	}
	var buf []byte
	appendf := func(format string, a ...any) {
		buf = append(buf, fmt.Sprintf(format, a...)...)
	}
	status := s.status
	if status < 100 || status > 599 {
		status = 200
	}
	appendf("HTTP/1.1 %d %s\r\n", status, statusText(status))
	if s.contentType != "" {
		appendf("Content-Type: %s\r\n", s.contentType)
	}
	if s.extraHdr != "" {
		appendf("%s\r\n", s.extraHdr)
	}
	if s.chunked {
		appendf("Transfer-Encoding: chunked\r\n\r\n")
		if s.truncateInChunk {
			// Announce a huge chunk, then send only the small body and close —
			// a classic "declared length >> bytes sent" shape the client must
			// not treat as a complete body.
			appendf("%x\r\n", len(s.body)+0x100000)
			buf = append(buf, s.body...)
			_, _ = conn.Write(buf)
			return // no terminating chunk => client sees short read
		}
		appendf("%x\r\n", len(s.body))
		buf = append(buf, s.body...)
		buf = append(buf, "\r\n0\r\n\r\n"...)
		_, _ = conn.Write(buf)
		return
	}
	clen := len(s.body)
	if s.lyingLen > 0 {
		clen = s.lyingLen
	}
	appendf("Content-Length: %d\r\n\r\n", clen)
	buf = append(buf, s.body...)
	_, _ = conn.Write(buf)
	if s.closeAfterBody || s.lyingLen > len(s.body) {
		// Close with fewer bytes than Content-Length promised: the client's body
		// read must fail rather than return a truncated-but-"successful" body.
		return
	}
}

func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 202:
		return "Accepted"
	case 206:
		return "Partial Content"
	case 301, 302, 303, 307, 308:
		return "Redirect"
	case 400:
		return "Bad Request"
	case 500:
		return "Internal Server Error"
	default:
		return "Status"
	}
}
