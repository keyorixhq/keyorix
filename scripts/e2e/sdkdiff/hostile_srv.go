package main

// Raw-socket mock server for the hostile-server mode (hostile/RULES.md). It speaks just enough HTTP/1.1 to read a
// request and then writes a response exactly as a Plan says, including framings a normal HTTP library refuses to
// produce (lying Content-Length, EOF-framed bodies, malformed chunks, resets, stalls, drips).

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// After describes what happens once N body bytes (as put on the wire) were written.
type After struct {
	Kind string // reset | close | stall | drip
	N    int64
	Dur  time.Duration // stall length, or drip interval per byte
}

// ChunkSpec shapes a chunked body.
type ChunkSpec struct {
	Size      int    // payload bytes per chunk (default 4096)
	Ext       string // chunk extension, e.g. ";x=1"
	BigExt    int    // bytes of extension filler
	Trailers  bool
	BadSize   string // replace the first chunk size line with this text
	NoTerm    bool   // no terminating zero chunk
	OversizeN int    // first chunk declares this many extra bytes
	EarlyZero int64  // emit a zero chunk after this many payload bytes, then keep going
	BareLF    bool
}

// Plan is the complete description of one response.
type Plan struct {
	Status      int
	StatusLine  string // verbatim status line without CRLF (overrides Status)
	NoStatus    bool
	Interim     bool
	CT          string // Content-Type; "-" omits it
	Headers     [][2]string
	RawHeaders  []string // verbatim header lines, no CRLF
	Frame       string   // cl (honest, default) | decl | eof | chunked
	DeclCL      []string // Content-Length header values for Frame decl
	TEAndCL     bool
	BodyLen     int64 // known length of Body (for Frame cl / decl default), -1 unknown
	Body        func(w io.Writer) error
	Chunk       ChunkSpec
	After       After
	PreDelay    time.Duration
	HeadDrip    time.Duration
	ExtraHdrs   int // number of junk headers
	BigHdrBytes int
	Gzip        string // "" | "ok" (compress the body) | "raw" (label only) | name of a bogus coding
	GzipTrunc   bool
	RawResponse []byte // written verbatim, nothing else
	ResetNow    bool   // reset the connection right away
}

func bodyBytes(b []byte) func(io.Writer) error {
	return func(w io.Writer) error { _, err := w.Write(b); return err }
}

// validPlan is the ordinary response.
func validPlan(status int, b []byte) *Plan {
	return &Plan{Status: status, CT: "application/json", Frame: "cl", BodyLen: int64(len(b)), Body: bodyBytes(b)}
}

// HReq is one request as the mock server saw it.
type HReq struct {
	Method     string              `json:"method"`
	URI        string              `json:"uri"`
	Header     map[string][]string `json:"header,omitempty"`
	Class      string              `json:"class"`
	Mutated    bool                `json:"mutated,omitempty"`
	AcceptGzip bool                `json:"accept_gzip,omitempty"`
	Page       int                 `json:"page,omitempty"`
}

// route classifies a request into a class letter.
var (
	reEnvs    = regexp.MustCompile(`^/api/v1/projects/(\d+)/environments$`)
	reDeleted = regexp.MustCompile(`^/api/v1/projects/(\d+)/secrets/deleted$`)
	reSecID   = regexp.MustCompile(`^/api/v1/secrets/(\d+)$`)
)

func classify(method, path string) string {
	switch {
	case method == "GET" && path == "/health":
		return "H"
	case method == "POST" && path == "/auth/login":
		return "A"
	case method == "GET" && path == "/api/v1/projects":
		return "P"
	case method == "POST" && path == "/api/v1/projects":
		return "C"
	case method == "GET" && reEnvs.MatchString(path):
		return "E"
	case method == "GET" && reDeleted.MatchString(path):
		return "D"
	case method == "GET" && path == "/api/v1/secrets":
		return "L"
	case method == "GET" && (path == "/api/v1/secrets/value" || reSecID.MatchString(path)):
		return "V"
	}
	return "?"
}

// hSession is the arming of the server for one driver call.
type hSession struct {
	Mut    *Mut
	Target string // class the mutation applies to
	mu     sync.Mutex
	seen   map[string]int
	Reqs   []HReq
	done   chan struct{}
}

func newSession(m *Mut, target string) *hSession {
	return &hSession{Mut: m, Target: target, seen: map[string]int{}, done: make(chan struct{})}
}

// HostSrv is the mock server of one SDK instance.
type HostSrv struct {
	ln   net.Listener
	mu   sync.Mutex
	sess *hSession
	wg   sync.WaitGroup
}

// NewHostSrv listens on a free loopback port.
func NewHostSrv() (*HostSrv, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &HostSrv{ln: ln}
	go s.loop()
	return s, nil
}

// Addr is host:port.
func (s *HostSrv) Addr() string { return s.ln.Addr().String() }

// Close stops listening.
func (s *HostSrv) Close() { _ = s.ln.Close() }

// Arm installs the session for the next driver call.
func (s *HostSrv) Arm(se *hSession) {
	s.mu.Lock()
	s.sess = se
	s.mu.Unlock()
}

// Disarm ends the session, unblocks stalled handlers, waits for them and returns the recorded requests.
func (s *HostSrv) Disarm() []HReq {
	s.mu.Lock()
	se := s.sess
	s.sess = nil
	s.mu.Unlock()
	if se == nil {
		return nil
	}
	close(se.done)
	waitTimeout(&s.wg, 12*time.Second)
	se.mu.Lock()
	defer se.mu.Unlock()
	return append([]HReq(nil), se.Reqs...)
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	ch := make(chan struct{})
	go func() { wg.Wait(); close(ch) }()
	select {
	case <-ch:
	case <-time.After(d):
	}
}

func (s *HostSrv) loop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.serve(c) }()
	}
}

func readRequest(c net.Conn) (method, uri string, hdr map[string][]string, err error) {
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReaderSize(c, 64<<10)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", "", nil, err
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", nil, errors.New("bad request line")
	}
	method, uri = parts[0], parts[1]
	hdr = map[string][]string{}
	total := 0
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return "", "", nil, err
		}
		total += len(l)
		if total > 1<<20 {
			return "", "", nil, errors.New("request head too large")
		}
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			break
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		hdr[k] = append(hdr[k], strings.TrimSpace(v))
	}
	if cl := hdr["content-length"]; len(cl) > 0 {
		n, _ := strconv.Atoi(cl[0])
		if n > 0 && n <= 4<<20 {
			_, _ = io.CopyN(io.Discard, br, int64(n))
		}
	}
	return method, uri, hdr, nil
}

func (s *HostSrv) serve(c net.Conn) {
	defer c.Close() //nolint:errcheck
	method, uri, hdr, err := readRequest(c)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	s.mu.Lock()
	se := s.sess
	s.mu.Unlock()
	u, _ := url.ParseRequestURI(uri)
	path := uri
	page := 1
	if u != nil {
		path = u.Path
		if p, e := strconv.Atoi(u.Query().Get("page")); e == nil {
			page = p
		}
	}
	cls := classify(method, path)
	rec := HReq{Method: method, URI: uri, Header: hdr, Class: cls, Page: page}
	for _, v := range hdr["accept-encoding"] {
		if strings.Contains(strings.ToLower(v), "gzip") {
			rec.AcceptGzip = true
		}
	}
	if se == nil {
		_, _ = c.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	env := &Env{Cls: cls, Method: method, URI: uri, Path: path, Page: page, AcceptGzip: rec.AcceptGzip, Hdr: hdr}
	plan := validPlanFor(env)
	se.mu.Lock()
	apply := se.Mut != nil && cls == se.Target && (se.Mut.Times < 0 || se.seen[cls] == 0)
	se.seen[cls]++
	se.mu.Unlock()
	if apply {
		if p := se.Mut.Plan(env); p != nil {
			plan = p
			rec.Mutated = true
		}
	}
	se.mu.Lock()
	se.Reqs = append(se.Reqs, rec)
	se.mu.Unlock()
	writePlan(c, plan, se.done)
}

func sleepAbort(d time.Duration, done <-chan struct{}) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-done:
	}
}

var errAbort = errors.New("aborted by plan")

// shaper applies After to the wire body.
type shaper struct {
	c       net.Conn
	a       After
	written int64
	done    <-chan struct{}
	drip    bool
}

func (s *shaper) Write(p []byte) (int, error) {
	if s.a.Kind == "" {
		return s.c.Write(p)
	}
	n := 0
	for len(p) > 0 {
		if s.drip {
			if _, err := s.c.Write(p[:1]); err != nil {
				return n, err
			}
			p, n, s.written = p[1:], n+1, s.written+1
			select {
			case <-s.done:
				return n, errAbort
			case <-time.After(s.a.Dur):
			}
			continue
		}
		room := s.a.N - s.written
		if room > int64(len(p)) {
			m, err := s.c.Write(p)
			s.written += int64(m)
			return n + m, err
		}
		if room > 0 {
			m, err := s.c.Write(p[:room])
			s.written += int64(m)
			n += m
			p = p[m:]
			if err != nil {
				return n, err
			}
		}
		switch s.a.Kind {
		case "reset":
			if tc, ok := s.c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = s.c.Close()
			return n, errAbort
		case "close":
			_ = s.c.Close()
			return n, errAbort
		case "stall":
			sleepAbort(s.a.Dur, s.done)
			return n, errAbort
		case "drip":
			s.drip = true
		}
	}
	return n, nil
}

// chunker encodes writes as chunks according to ChunkSpec.
type chunker struct {
	w     io.Writer
	spec  ChunkSpec
	first bool
	sent  int64
	zeroD bool
}

func (c *chunker) eol() string {
	if c.spec.BareLF {
		return "\n"
	}
	return "\r\n"
}

func (c *chunker) Write(p []byte) (int, error) {
	size := c.spec.Size
	if size <= 0 {
		size = 4096
	}
	total := 0
	for len(p) > 0 {
		n := min(size, len(p))
		ext := c.spec.Ext
		if c.spec.BigExt > 0 && !c.first {
			ext = ";x=" + strings.Repeat("a", c.spec.BigExt)
		}
		line := fmt.Sprintf("%x%s%s", n, ext, c.eol())
		if !c.first {
			c.first = true
			if c.spec.BadSize != "" {
				line = c.spec.BadSize + c.eol()
			} else if c.spec.OversizeN > 0 {
				line = fmt.Sprintf("%x%s%s", n+c.spec.OversizeN, ext, c.eol())
			}
		}
		if _, err := io.WriteString(c.w, line); err != nil {
			return total, err
		}
		if _, err := c.w.Write(p[:n]); err != nil {
			return total, err
		}
		if _, err := io.WriteString(c.w, c.eol()); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
		c.sent += int64(n)
		if c.spec.EarlyZero > 0 && !c.zeroD && c.sent >= c.spec.EarlyZero {
			c.zeroD = true
			if _, err := io.WriteString(c.w, "0"+c.eol()+c.eol()); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func (c *chunker) finish() error {
	if c.spec.NoTerm || c.spec.OversizeN > 0 {
		return nil
	}
	t := "0" + c.eol()
	if c.spec.Trailers {
		t += "X-Trailer-A: 1" + c.eol() + "X-Trailer-B: two" + c.eol()
	}
	_, err := io.WriteString(c.w, t+c.eol())
	return err
}

func reasonFor(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 302:
		return "Found"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	case 503:
		return "Service Unavailable"
	}
	return "Status"
}

func writePlan(c net.Conn, p *Plan, done <-chan struct{}) {
	if p.PreDelay > 0 {
		sleepAbort(p.PreDelay, done)
	}
	if p.ResetNow {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		return
	}
	if p.RawResponse != nil {
		_, _ = c.Write(p.RawResponse)
		return
	}
	var head bytes.Buffer
	if p.Interim {
		head.WriteString("HTTP/1.1 100 Continue\r\n\r\n")
	}
	if !p.NoStatus {
		if p.StatusLine != "" {
			head.WriteString(p.StatusLine + "\r\n")
		} else {
			fmt.Fprintf(&head, "HTTP/1.1 %d %s\r\n", p.Status, reasonFor(p.Status))
		}
		switch {
		case p.CT == "-":
		case p.CT != "":
			head.WriteString("Content-Type: " + p.CT + "\r\n")
		}
		for _, h := range p.Headers {
			head.WriteString(h[0] + ": " + h[1] + "\r\n")
		}
		for _, h := range p.RawHeaders {
			head.WriteString(h + "\r\n")
		}
		for i := 0; i < p.ExtraHdrs; i++ {
			fmt.Fprintf(&head, "X-Junk-%d: v%d\r\n", i, i)
		}
		if p.BigHdrBytes > 0 {
			head.WriteString("X-Big: " + strings.Repeat("b", p.BigHdrBytes) + "\r\n")
		}
		switch p.Gzip {
		case "":
		case "ok", "raw":
			head.WriteString("Content-Encoding: gzip\r\n")
		default:
			head.WriteString("Content-Encoding: " + p.Gzip + "\r\n")
		}
		head.WriteString("Connection: close\r\n")
		switch p.Frame {
		case "", "cl":
			if p.BodyLen >= 0 && p.Body != nil {
				fmt.Fprintf(&head, "Content-Length: %d\r\n", p.BodyLen)
			}
		case "decl":
			for _, v := range p.DeclCL {
				head.WriteString("Content-Length: " + v + "\r\n")
			}
		case "chunked":
			head.WriteString("Transfer-Encoding: chunked\r\n")
			if p.TEAndCL && p.BodyLen >= 0 {
				fmt.Fprintf(&head, "Content-Length: %d\r\n", p.BodyLen)
			}
		}
		head.WriteString("\r\n")
	}
	if p.HeadDrip > 0 {
		for _, b := range head.Bytes() {
			if _, err := c.Write([]byte{b}); err != nil {
				return
			}
			select {
			case <-done:
				return
			case <-time.After(p.HeadDrip):
			}
		}
	} else if _, err := c.Write(head.Bytes()); err != nil {
		return
	}
	if p.Body == nil {
		return
	}
	var w io.Writer = &shaper{c: c, a: p.After, done: done, drip: p.After.Kind == "drip" && p.After.N == 0}
	var ch *chunker
	if p.Frame == "chunked" {
		ch = &chunker{w: w, spec: p.Chunk}
		w = ch
	}
	var gz *gzip.Writer
	if p.Gzip == "ok" {
		gz, _ = gzip.NewWriterLevel(w, gzip.BestSpeed)
		w = gz
	}
	err := p.Body(w)
	if gz != nil && err == nil && !p.GzipTrunc {
		err = gz.Close()
	}
	if err != nil {
		return
	}
	if ch != nil {
		_ = ch.finish()
	}
}

func newGzip(w io.Writer) *gzip.Writer {
	z, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	return z
}
