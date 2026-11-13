// Package hostile is a record-and-mutate hostile-backend fuzzing harness: it
// serves a hand-written VALID response sequence for a connector from a local
// httptest server and lets a byte-decoded mutation Program corrupt one route
// (JSON field-level ops, status/content-type/encoding/framing changes,
// redirects, network faults). The rules the harness enforces are pre-registered
// in RULES.md. Like internal/fuzzutil it is imported only from _test.go files
// and never imports "testing".
package hostile

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resp is a (valid) backend response.
type Resp struct {
	Status  int
	CT      string
	Body    []byte
	Headers [][2]string // extra response headers
}

// Route is one backend endpoint. Valid returns the pristine response for the
// n-th (1-based) request to this route.
type Route struct {
	Name   string
	Method string // "" matches any
	Prefix string // URL path prefix; the longest matching prefix wins
	Valid  func(n int, r *http.Request) Resp
	// Pass, when set, may answer a request itself (e.g. an auth challenge) with a
	// pristine response that is never mutated, counted or recorded.
	Pass func(r *http.Request) (Resp, bool)
}

// Served records what one request to a route actually received.
type Served struct {
	Route    string
	N        int
	Active   bool   // a mutation program applied to this request
	Pristine bool   // response was the valid one, byte for byte
	Status   int    // final status line sent (0 when the connection was broken before one)
	Seen     []byte // bytes the client would read from the body if it read it all
	Complete bool   // framing/transport/encoding delivered the whole body
	Redirect int    // 1-based redirect kind sent, 0 none
	Followed bool   // this request is the follow-up of a same-origin redirect
	Wire     int    // bytes written to the connection
}

type plan struct {
	hdrs     [][2]string
	status   int
	ct       string
	wire     []byte
	enc      string
	seen     []byte
	complete bool
	frame    string
	fault    string
	location string
	redirect int
}

var (
	bombOnce sync.Once
	bombGz   []byte
)

// bombBytes is a valid gzip stream that inflates to 256 MiB of zeros.
func bombBytes() []byte {
	bombOnce.Do(func() {
		var b bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&b, gzip.BestSpeed)
		chunk := make([]byte, 1<<20)
		for range 320 {
			_, _ = zw.Write(chunk)
		}
		_ = zw.Close()
		bombGz = b.Bytes()
	})
	return bombGz
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return out.Bytes()
}

// crossHost rewrites the sentinel URL's host name (127.0.0.1 -> localhost) so a
// redirect to it changes the host name but still reaches the sentinel.
func crossHost(u string) string { return strings.Replace(u, "127.0.0.1", "localhost", 1) }

// buildPlan applies the program (when active) to the valid response.
func buildPlan(valid Resp, p Program, active bool, selfURL, attackerURL string, followed bool) plan {
	pl := plan{status: valid.Status, ct: valid.CT, complete: true, hdrs: valid.Headers}
	if pl.status == 0 {
		pl.status = 200
	}
	body := valid.Body
	if active {
		body = p.MutateBody(body)
		if p.Status > 0 {
			pl.status = statuses[p.Status-1]
		}
		if p.CT > 0 {
			pl.ct = contentTypes[p.CT-1]
		}
	}
	pl.wire, pl.seen = body, body
	if active && p.Enc > 0 {
		switch encodings[p.Enc-1] {
		case "gzip":
			pl.wire, pl.enc = gz(body), "gzip"
		case "gzip-bomb":
			pl.wire, pl.enc, pl.seen, pl.complete = bombBytes(), "gzip", nil, false
		case "gzip-corrupt":
			w := gz(body)
			w[len(w)-5] ^= 0xff                             // corrupt the CRC32 trailer
			pl.wire, pl.enc, pl.complete = w, "gzip", false // decoded content is intact; only the CRC trailer is bad
		case "br-label":
			pl.enc = "br"
		case "gzip-label-raw":
			pl.enc, pl.seen, pl.complete = "gzip", nil, false
		}
	}
	if active && p.Frame > 0 {
		pl.frame = frames[p.Frame-1]
		switch pl.frame {
		case "cl-too-long", "chunk-unterminated", "chunk-huge-size":
			pl.complete = false // content arrives whole (inside the declared chunk/length); only the transport ends in error
		case "chunk-bad-size":
			pl.complete, pl.seen = false, nil // the client rejects the size line before any data
		case "cl-too-short":
			if n := len(pl.wire); n > 0 {
				k := min(1+n/4, n)
				if pl.enc == "" {
					pl.seen = pl.wire[:n-k]
				} else {
					pl.seen, pl.complete = nil, false
				}
			}
		}
	}
	if active && p.Fault > 0 {
		pl.fault = faults[p.Fault-1]
		if pl.fault != "slow-drip" {
			pl.complete, pl.seen = false, nil
		}
	}
	if active && p.Redir > 0 && !followed {
		pl.redirect = p.Redir
		pl.complete, pl.seen = false, nil
		switch redirects[p.Redir-1] {
		case "attacker-302":
			pl.status, pl.location = 302, crossHost(attackerURL)+"/internal"
		case "other-port-same-host-302":
			pl.status, pl.location = 302, attackerURL+"/internal"
		case "self-loop-307":
			pl.status, pl.location = 307, selfURL
		case "same-origin-once-307":
			sep := "?"
			if strings.Contains(selfURL, "?") {
				sep = "&"
			}
			pl.status, pl.location = 307, selfURL+sep+"kxr=1"
		case "attacker-301-with-body":
			pl.status, pl.location = 301, crossHost(attackerURL)+"/internal"
			pl.complete, pl.seen = false, nil
		}
	}
	if pl.status == 204 || pl.status == 304 {
		pl.seen = nil
	}
	return pl
}

// Config configures a Harness.
type Config struct {
	Routes  []Route
	Program Program
	TLS     bool // serve HTTPS with httptest's certificate (see CAPEM)

	// CallTimeout is the context deadline handed to the connector call
	// (default 500ms). The call must return within CallTimeout+1s.
	CallTimeout time.Duration
	// AllowRedirect: the connector legitimately follows SAME-ORIGIN redirects.
	// Redirects to the sentinel (cross-origin) address are never allowed.
	AllowRedirect bool
	// RequestCeiling is the max requests to the backend per Harness (O8).
	RequestCeiling int
	// RecoverPanics converts a panic in the call into a violation instead of
	// re-panicking (used by the planted-defect self-test).
	RecoverPanics bool
	// Retries: the connector (or its SDK) retries failed exchanges, so a success
	// is judged on the LAST exchange only; earlier failed attempts are expected.
	Retries bool
	// Credentials the connector sends; they must not leak (O7).
	Credentials []string
}

// Harness is one hostile backend plus the oracles' bookkeeping for one input.
type Harness struct {
	cfg      Config
	srv      *httptest.Server
	attacker *httptest.Server

	done chan struct{}
	mu   sync.Mutex

	counts   map[string]int
	hops     map[string]int
	served   []Served
	conns    []net.Conn
	unmatch  []string
	viol     []string
	logs     *logCapture
	total    atomic.Int32
	attHits  atomic.Int32
	wrote    atomic.Int64
	attHosts []string
	before   map[string]int
	fd0      int
	closeOne sync.Once
}

// New starts the hostile backend and the sentinel "internal address" server.
func New(cfg Config) *Harness {
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 500 * time.Millisecond
	}
	if cfg.RequestCeiling == 0 {
		cfg.RequestCeiling = 8
	}
	if cfg.Program.Enc == 2 {
		bombBytes() // pre-build outside any timed region
	}
	h := &Harness{cfg: cfg, done: make(chan struct{}), counts: map[string]int{}, hops: map[string]int{}}
	h.before, h.fd0 = census(), fdCount()
	h.attacker = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.attHits.Add(1)
		h.mu.Lock()
		h.attHosts = append(h.attHosts, r.Host)
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"ATTACKER-CONTROLLED"},"value":"ATTACKER-CONTROLLED"},"keys":[]}`))
	}))
	hd := http.HandlerFunc(h.handle)
	if cfg.TLS {
		h.srv = httptest.NewTLSServer(hd)
	} else {
		h.srv = httptest.NewServer(hd)
	}
	h.logs = captureLogs()
	return h
}

// URL is the backend base URL.
func (h *Harness) URL() string { return h.srv.URL }

// CAPEM is the PEM of the backend's certificate (TLS mode).
func (h *Harness) CAPEM() string {
	c := h.srv.Certificate()
	if c == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// CertPool trusts the backend's certificate (TLS mode).
func (h *Harness) CertPool() *x509.CertPool {
	p := x509.NewCertPool()
	if c := h.srv.Certificate(); c != nil {
		p.AddCert(c)
	}
	return p
}

// AttackerURL is the sentinel standing in for an internal address.
func (h *Harness) AttackerURL() string { return h.attacker.URL }

// Served returns the records for a route, oldest first.
func (h *Harness) Served(route string) []Served {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Served
	for _, s := range h.served {
		if s.Route == route {
			out = append(out, s)
		}
	}
	return out
}

// Intact reports whether every request the connector made to route received a
// complete response with an accepted status (default 200), no redirect, and
// returns the last such body. It is false when the route was never requested.
// This is the delivery half of the fail-closed oracle (O5); the caller adds
// its own strict body validation.
func (h *Harness) Intact(route string, okStatus ...int) ([]byte, bool) {
	if len(okStatus) == 0 {
		okStatus = []int{200}
	}
	recs := h.Served(route)
	if len(recs) == 0 {
		return nil, false
	}
	var last Served
	got := false
	for _, s := range recs {
		if s.Redirect != 0 && h.cfg.AllowRedirect {
			continue // the redirect response itself; the follow-up is judged below
		}
		if !s.Complete || s.Redirect != 0 || (s.Followed && !h.cfg.AllowRedirect) {
			return nil, false
		}
		ok := false
		for _, c := range okStatus {
			if s.Status == c {
				ok = true
			}
		}
		if !ok {
			return nil, false
		}
		last, got = s, true
	}
	if !got {
		return nil, false
	}
	return last.Seen, true
}

// Delivery classifies the exchanges a connector consumed on route, for a call
// that reported success. kind is "" when every exchange was complete with an
// accepted status; "transport" when the status was accepted and the delivered
// content passes contentOK but the transport/framing/encoding still ended in
// error (the connector read what it needed and never looked at the error);
// "status" for a final status outside okStatus (e.g. a 3xx that was not
// followed); "bad" for a redirect the connector must not follow, or content
// that was not fully delivered. seen is the last delivered body.
func (h *Harness) Delivery(route string, contentOK func(seen []byte) bool, okStatus ...int) (seen []byte, kind string) {
	if len(okStatus) == 0 {
		okStatus = []int{200}
	}
	recs := h.Served(route)
	if len(recs) == 0 {
		return nil, "bad"
	}
	if h.cfg.Retries {
		for i, rec := range slices.Backward(recs) {
			if rec.Redirect == 0 || !h.cfg.AllowRedirect {
				recs = recs[i : i+1]
				break
			}
		}
	}
	got := false
	for _, s := range recs {
		if s.Redirect != 0 && h.cfg.AllowRedirect {
			continue
		}
		if s.Redirect != 0 || (s.Followed && !h.cfg.AllowRedirect) {
			return nil, "bad"
		}
		ok := false
		for _, c := range okStatus {
			if s.Status == c {
				ok = true
			}
		}
		if !ok {
			return nil, "status"
		}
		if !s.Complete {
			if !contentOK(s.Seen) {
				return nil, "bad"
			}
			kind = "transport"
		}
		seen, got = s.Seen, true
	}
	if !got {
		return nil, "bad"
	}
	return seen, kind
}

// Requests is the number of requests the backend received.
func (h *Harness) Requests() int { return int(h.total.Load()) }

// AttackerHits is the number of requests the sentinel received.
func (h *Harness) AttackerHits() int { return int(h.attHits.Load()) }

// Program returns the decoded program under test.
func (h *Harness) Program() Program { return h.cfg.Program }

func (h *Harness) match(r *http.Request) (int, *Route) {
	best, bl := -1, -1
	for i := range h.cfg.Routes {
		rt := &h.cfg.Routes[i]
		if rt.Method != "" && rt.Method != r.Method {
			continue
		}
		if strings.HasPrefix(r.URL.Path, rt.Prefix) && len(rt.Prefix) > bl {
			best, bl = i, len(rt.Prefix)
		}
	}
	if best < 0 {
		return -1, nil
	}
	return best, &h.cfg.Routes[best]
}

func (h *Harness) track(c net.Conn) {
	h.mu.Lock()
	h.conns = append(h.conns, c)
	h.mu.Unlock()
}

func (h *Harness) handle(w http.ResponseWriter, r *http.Request) {
	h.total.Add(1)
	idx, rt := h.match(r)
	if rt == nil {
		h.mu.Lock()
		h.unmatch = append(h.unmatch, r.Method+" "+r.URL.RequestURI())
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"errors":["no such route in the hostile harness"]}`))
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	if rt.Pass != nil {
		if resp, ok := rt.Pass(r); ok {
			h.writePlain(w, buildPlan(resp, Program{}, false, "", "", false))
			return
		}
	}
	h.mu.Lock()
	h.counts[rt.Name]++
	n := h.counts[rt.Name]
	h.mu.Unlock()

	valid := rt.Valid(n, r)
	p := h.cfg.Program
	active := idx == p.Route%len(h.cfg.Routes) && !p.Pristine() &&
		(p.Occ == 1 || (p.Occ == 0 && n == 1) || (p.Occ == 2 && n >= 2))
	followed := r.URL.Query().Get("kxr") == "1"
	if active && p.Redir > 0 && redirects[p.Redir-1] == "self-loop-307" {
		// Bound the loop: after 12 hops answer with the (mutated) response, so a
		// connector with no hop limit ends in a visible request-count violation
		// (O8) instead of an endless run that also trips O4 as a side effect.
		h.mu.Lock()
		h.hops[rt.Name]++
		over := h.hops[rt.Name] > 12
		h.mu.Unlock()
		if over {
			followed = true
		}
	}
	scheme := "http"
	if h.cfg.TLS {
		scheme = "https"
	}
	self := scheme + "://" + r.Host + r.URL.RequestURI()
	pl := buildPlan(valid, p, active, self, h.attacker.URL, followed)

	rec := Served{Route: rt.Name, N: n, Active: active, Pristine: !active, Status: pl.status,
		Seen: pl.seen, Complete: pl.complete, Redirect: pl.redirect, Followed: followed}
	if pl.fault == "accept-close" || pl.fault == "garbage" || pl.fault == "tls-alert" || pl.fault == "partial-headers-hang" {
		rec.Status = 0
	}
	if pl.fault == "" && pl.frame == "" {
		rec.Wire = len(pl.wire)
		h.record(rec)
		h.writePlain(w, pl)
		return
	}
	h.record(rec)
	h.writeRaw(w, pl)
}

func (h *Harness) record(s Served) {
	h.mu.Lock()
	h.served = append(h.served, s)
	h.mu.Unlock()
	h.wrote.Add(int64(s.Wire))
}

func (h *Harness) writePlain(w http.ResponseWriter, pl plan) {
	hd := w.Header()
	if pl.ct != "" {
		hd.Set("Content-Type", pl.ct)
	} else {
		hd["Content-Type"] = nil // suppress sniffing
	}
	if pl.enc != "" {
		hd.Set("Content-Encoding", pl.enc)
	}
	for _, kv := range pl.hdrs {
		hd.Set(kv[0], kv[1])
	}
	if pl.location != "" {
		hd.Set("Location", pl.location)
	}
	w.WriteHeader(pl.status)
	if pl.status != 204 && pl.status != 304 {
		_, _ = w.Write(pl.wire) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- test fake: raw fuzz bytes by design, no HTML rendering
	}
}

func (h *Harness) hijack(w http.ResponseWriter) (net.Conn, bool) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, false
	}
	c, _, err := hj.Hijack()
	if err != nil {
		return nil, false
	}
	h.track(c)
	return c, true
}

func rawHead(status int, ct, enc, loc string, extra ...string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if ct != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", ct)
	}
	if enc != "" {
		fmt.Fprintf(&b, "Content-Encoding: %s\r\n", enc)
	}
	if loc != "" {
		fmt.Fprintf(&b, "Location: %s\r\n", loc)
	}
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

func rst(c net.Conn) {
	type unwrap interface{ NetConn() net.Conn }
	for {
		if u, ok := c.(unwrap); ok {
			c = u.NetConn()
			continue
		}
		break
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

func chunked(b []byte, pieces int, ext string) []byte {
	var out bytes.Buffer
	if pieces < 1 {
		pieces = 1
	}
	step := len(b)/pieces + 1
	for i := 0; i < len(b); i += step {
		j := min(i+step, len(b))
		fmt.Fprintf(&out, "%x%s\r\n", j-i, ext)
		out.Write(b[i:j])
		out.WriteString("\r\n")
	}
	return out.Bytes()
}

func (h *Harness) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-h.done:
		return false
	case <-t.C:
		return true
	}
}

func (h *Harness) writeRaw(w http.ResponseWriter, pl plan) {
	c, ok := h.hijack(w)
	if !ok {
		return
	}
	wr := func(b []byte) {
		if len(b) == 0 {
			return
		}
		n, _ := c.Write(b)
		h.wrote.Add(int64(n))
	}
	defer func() { _ = c.Close() }()
	cl := func(n int) string { return fmt.Sprintf("Content-Length: %d", n) }
	body := pl.wire
	head := func(extra ...string) []byte {
		for _, kv := range pl.hdrs {
			extra = append(extra, kv[0]+": "+kv[1])
		}
		return rawHead(pl.status, pl.ct, pl.enc, pl.location, append(extra, "Connection: close")...)
	}
	switch pl.fault {
	case "rst-after-headers":
		wr(head(cl(len(body) + 1)))
		rst(c)
		return
	case "close-after-headers":
		wr(head(cl(len(body) + 1)))
		return
	case "rst-mid-body":
		wr(head(cl(len(body) + 10)))
		wr(body[:len(body)/2])
		rst(c)
		return
	case "hang":
		<-h.done
		return
	case "slow-drip":
		wr(head(cl(len(body))))
		for i := range body {
			wr(body[i : i+1])
			if !h.sleep(15 * time.Millisecond) {
				return
			}
		}
		return
	case "garbage":
		wr([]byte("\x00\xff\xfeNOT-HTTP \r\n\r\n\x00"))
		return
	case "tls-alert":
		wr([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
		return
	case "accept-close":
		return
	case "partial-headers-hang":
		wr([]byte("HTTP/1.1 200 OK\r\nContent-Ty"))
		<-h.done
		return
	}
	switch pl.frame {
	case "cl-too-long":
		wr(head(cl(len(body) + 1 + len(body)/3)))
		wr(body)
	case "chunked":
		wr(head("Transfer-Encoding: chunked"))
		wr(chunked(body, 3, ""))
		wr([]byte("0\r\n\r\n"))
	case "cl-too-short":
		k := min(1+len(body)/4, len(body))
		wr(head(cl(len(body) - k)))
		wr(body)
	case "dup-cl":
		wr(head(cl(len(body)), cl(len(body)+1)))
		wr(body)
	case "chunk-bad-size":
		wr(head("Transfer-Encoding: chunked"))
		wr([]byte("zz\r\n"))
		wr(body)
	case "chunk-huge-size":
		wr(head("Transfer-Encoding: chunked"))
		wr([]byte("ffffffffff\r\n"))
		wr(body)
	case "chunk-unterminated":
		wr(head("Transfer-Encoding: chunked"))
		wr(chunked(body, 2, ""))
	case "te-and-cl":
		wr(head("Transfer-Encoding: chunked", cl(len(body))))
		wr(chunked(body, 2, ""))
		wr([]byte("0\r\n\r\n"))
	case "close-delimited":
		wr(head())
		wr(body)
	case "chunk-ext-giant":
		wr(head("Transfer-Encoding: chunked"))
		wr(chunked(body, 1, ";ext="+strings.Repeat("A", 70<<10)))
		wr([]byte("0\r\n\r\n"))
	case "header-giant":
		wr(head(cl(len(body)), "X-Pad: "+strings.Repeat("A", 1200<<10)))
		wr(body)
	case "trailer-giant":
		wr(head("Transfer-Encoding: chunked", "Trailer: X-T"))
		wr(chunked(body, 2, ""))
		wr([]byte("0\r\nX-T: " + strings.Repeat("A", 70<<10) + "\r\n\r\n"))
	}
}

// Close stops both servers and closes every hijacked connection. Idempotent.
func (h *Harness) Close() {
	h.closeOne.Do(func() {
		close(h.done)
		h.mu.Lock()
		cs := h.conns
		h.mu.Unlock()
		for _, c := range cs {
			_ = c.Close()
		}
		h.srv.CloseClientConnections()
		h.srv.Close()
		h.attacker.CloseClientConnections()
		h.attacker.Close()
		h.logs.restore()
	})
}
