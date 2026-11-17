package main

// Wire-level checks of the hostile-server mock (hostile_srv.go): each mutation is armed on a real HostSrv, a raw TCP
// client sends one request, and the assertions are on the bytes the server put on the wire. No SDK driver.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// wireTrip arms mutation id on a fresh server, sends GET /health and returns what came back before wait elapsed (or
// the server closed) plus the requests the server recorded.
func wireTrip(t *testing.T, id string, wait time.Duration) ([]byte, []HReq) {
	t.Helper()
	m := mutByID(id)
	if m == nil {
		t.Fatalf("no mutation %s", id)
	}
	srv, err := NewHostSrv()
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer srv.Close()
	srv.Arm(newSession(m, "H"))
	return rawGet(t, srv, "/health", wait)
}

func rawGet(t *testing.T, srv *HostSrv, uri string, wait time.Duration) ([]byte, []HReq) {
	t.Helper()
	c, err := net.Dial("tcp4", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	_ = c.SetDeadline(time.Now().Add(wait))
	req := "GET " + uri + " HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nAuthorization: Bearer wire-test-token\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(c) // a deadline error is the expected end of a stalled response
	return raw, srv.Disarm()
}

func parseWire(t *testing.T, raw []byte) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("response does not parse: %v\n%q", err, trunc(string(raw), 300))
	}
	return resp
}

func TestHostSrvMutationsOnTheWire(t *testing.T) {
	doc := string(validDoc("H", 1))
	bodyOf := func(t *testing.T, raw []byte) string {
		t.Helper()
		b, err := io.ReadAll(parseWire(t, raw).Body)
		if err != nil {
			t.Fatalf("body: %v", err)
		}
		return string(b)
	}
	has := func(sub string) func(*testing.T, []byte) {
		return func(t *testing.T, raw []byte) {
			t.Helper()
			if !bytes.Contains(raw, []byte(sub)) {
				t.Errorf("missing %q in %q", sub, trunc(string(raw), 400))
			}
		}
	}
	hasNot := func(sub string) func(*testing.T, []byte) {
		return func(t *testing.T, raw []byte) {
			t.Helper()
			if bytes.Contains(raw, []byte(sub)) {
				t.Errorf("unexpected %q in %q", sub, trunc(string(raw), 400))
			}
		}
	}
	prefix := func(p string) func(*testing.T, []byte) {
		return func(t *testing.T, raw []byte) {
			t.Helper()
			if !bytes.HasPrefix(raw, []byte(p)) {
				t.Errorf("response starts %q, want %q", trunc(string(raw), 60), p)
			}
		}
	}
	valid := func(t *testing.T, raw []byte) {
		t.Helper()
		if got := bodyOf(t, raw); got != doc {
			t.Errorf("body %q, want %q", got, doc)
		}
	}
	count := func(sub string, n int) func(*testing.T, []byte) {
		return func(t *testing.T, raw []byte) {
			t.Helper()
			if got := bytes.Count(raw, []byte(sub)); got != n {
				t.Errorf("%q occurs %d times, want %d", sub, got, n)
			}
		}
	}
	cases := []struct {
		id    string
		wait  time.Duration
		check func(*testing.T, []byte)
	}{
		{"C0", 3 * time.Second, valid},
		{"C4", 3 * time.Second, has("Content-Type: application/json; charset=utf-8")},
		{"B04", 3 * time.Second, func(t *testing.T, raw []byte) {
			if cl := parseWire(t, raw).ContentLength; cl != int64(len(doc))-10 {
				t.Errorf("Content-Length %d, want %d", cl, len(doc)-10)
			}
		}},
		{"B05", 3 * time.Second, has("Content-Length: " + itoa(len(doc)+1000))},
		{"B06", 3 * time.Second, hasNot("Content-Length")},
		{"B07", 3 * time.Second, hasNot(`"uptime"`)},
		{"B08", 3 * time.Second, count("Content-Length:", 2)},
		{"B09a", 3 * time.Second, has("Content-Length: -1")},
		{"B10", 3 * time.Second, func(t *testing.T, raw []byte) {
			has("Transfer-Encoding: chunked")(t, raw)
			has("Content-Length:")(t, raw)
		}},
		{"R01", 3 * time.Second, hasNot(`"uptime"`)},
		{"R02", 3 * time.Second, hasNot(`"uptime"`)},
		{"R03", 3 * time.Second, func(t *testing.T, raw []byte) {
			if len(raw) != 0 {
				t.Errorf("reset-now answered %q", raw)
			}
		}},
		{"R04", 3 * time.Second, func(t *testing.T, raw []byte) {
			if string(raw) != "HTTP/1.1 20" {
				t.Errorf("got %q", raw)
			}
		}},
		{"R05a", 3 * time.Second, func(t *testing.T, raw []byte) {
			if b := raw[bytes.Index(raw, []byte("\r\n\r\n"))+4:]; string(b) != doc[:1] {
				t.Errorf("cut body %q", b)
			}
		}},
		{"R06", 3 * time.Second, hasNot("0\r\n\r\n")},
		{"R07", 3 * time.Second, valid},
		{"R08", 3 * time.Second, func(t *testing.T, raw []byte) {
			has(";x=1\r\n")(t, raw)
			valid(t, raw)
		}},
		{"R09", 3 * time.Second, func(t *testing.T, raw []byte) {
			has("X-Trailer-A: 1")(t, raw)
			valid(t, raw)
		}},
		{"R10", 3 * time.Second, valid},
		{"R11", 3 * time.Second, has("\r\nzz\r\n")},
		{"R12", 3 * time.Second, has("\r\nFFFFFFFFFFFFFFFFFF\r\n")},
		{"R13", 3 * time.Second, func(t *testing.T, raw []byte) {
			if _, err := io.ReadAll(parseWire(t, raw).Body); err == nil {
				t.Error("an oversized chunk must not read cleanly")
			}
		}},
		{"R14", 3 * time.Second, has("0\r\n\r\n")},
		{"R15", 3 * time.Second, has("0\n\n")},
		{"R16", 3 * time.Second, has(";x=aaaaaaaa")},
		{"U05", 3 * time.Second, func(t *testing.T, raw []byte) {
			if !bytes.Contains(raw, []byte("\r\n\r\n\xef\xbb\xbf{")) {
				t.Errorf("no BOM before the document: %q", trunc(string(raw), 200))
			}
		}},
		{"S06m", 3 * time.Second, prefix("HTTP/1.1 204 No Content")},
		{"S08m", 3 * time.Second, prefix("HTTP/1.1 999 Status")},
		{"S09m", 3 * time.Second, prefix("HTTP/1.1 200\r\n")},
		{"S10m", 3 * time.Second, prefix("HTTP/1.1 2000 OK")},
		{"S11m", 3 * time.Second, prefix("{")},
		{"S12m", 3 * time.Second, prefix("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK")},
		{"S13m", 3 * time.Second, has("Bearer wire-test-token")},
		{"S14m", 3 * time.Second, func(t *testing.T, raw []byte) {
			prefix("HTTP/1.1 503 Service Unavailable")(t, raw)
			has("Retry-After: 99999999")(t, raw)
		}},
		{"S15m", 3 * time.Second, prefix("HTTP/1.0 200 OK")},
		{"H01", 3 * time.Second, has("Content-Type: text/html")},
		{"H02", 3 * time.Second, hasNot("Content-Type")},
		{"H05", 3 * time.Second, count("X-Junk-", 10000)},
		{"H06", 3 * time.Second, has("X-Big: bbbbbbbb")},
		{"H07", 3 * time.Second, has("this line has no colon\r\n")},
		{"H08", 3 * time.Second, has("X-Nul: a\x00b")},
		{"H09", 3 * time.Second, func(t *testing.T, raw []byte) {
			has("Content-Encoding: gzip")(t, raw)
			zr, err := gzip.NewReader(bytes.NewReader(raw[bytes.Index(raw, []byte("\r\n\r\n"))+4:]))
			if err != nil {
				t.Fatal(err)
			}
			if b, _ := io.ReadAll(zr); string(b) != doc {
				t.Errorf("gunzipped %q", b)
			}
		}},
		{"H11", 3 * time.Second, has("Content-Encoding: foo")},
		{"H12", 3 * time.Second, has("Content-Encoding: gzip")},
		{"H13", 3 * time.Second, func(t *testing.T, raw []byte) {
			zr, err := gzip.NewReader(bytes.NewReader(raw[bytes.Index(raw, []byte("\r\n\r\n"))+4:]))
			if err != nil {
				return // a header error is as truncated as it gets
			}
			if _, err := io.ReadAll(zr); err == nil {
				t.Error("a truncated gzip stream read cleanly")
			}
		}},
		{"H14", 3 * time.Second, has("Content-Encoding: br")},
		// stalls and drips never finish on their own: the client gives up and Disarm releases the handler
		{"T01", 600 * time.Millisecond, hasNot(`"uptime"`)},
		{"T02", 400 * time.Millisecond, hasNot(`"status"`)},
		{"T03", 400 * time.Millisecond, hasNot(`"uptime"`)},
		{"T04", 400 * time.Millisecond, func(t *testing.T, raw []byte) {
			if len(raw) != 0 {
				t.Errorf("a delayed answer already wrote %q", raw)
			}
		}},
		{"T05", 400 * time.Millisecond, prefix("HTTP")}, // one head byte per 100 ms
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			start := time.Now()
			raw, reqs := wireTrip(t, tc.id, tc.wait)
			if len(reqs) != 1 || reqs[0].Class != "H" || reqs[0].Method != "GET" {
				t.Fatalf("recorded %+v", reqs)
			}
			if !reqs[0].Mutated || !reqs[0].AcceptGzip {
				t.Errorf("request record %+v: want mutated, accept_gzip", reqs[0])
			}
			if tc.check != nil {
				tc.check(t, raw)
			}
			if d := time.Since(start); d > 10*time.Second {
				t.Errorf("round trip took %s: Disarm did not release the handler", d)
			}
		})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestHostSrvWithoutASessionAnswers503(t *testing.T) {
	srv, err := NewHostSrv()
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer srv.Close()
	raw, reqs := rawGet(t, srv, "/health", 3*time.Second)
	if !bytes.HasPrefix(raw, []byte("HTTP/1.1 503")) {
		t.Errorf("unarmed server answered %q", raw)
	}
	if reqs != nil {
		t.Errorf("requests recorded without a session: %+v", reqs)
	}
}

func TestHostSrvRecordsClassPageAndTimesOnce(t *testing.T) {
	srv, err := NewHostSrv()
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer srv.Close()
	se := newSession(mutByID("D04"), "L") // data missing, first list request only (Times 0)
	srv.Arm(se)
	raw1 := rawGet2(t, srv, "/api/v1/secrets?page=2", 3*time.Second)
	raw2 := rawGet2(t, srv, "/api/v1/secrets?page=3", 3*time.Second)
	if bytes.Contains(raw1, []byte(`"secrets"`)) {
		t.Errorf("the first request of the class must carry the mutation: %q", trunc(string(raw1), 200))
	}
	if !bytes.Contains(raw2, []byte(`"page":3`)) {
		t.Errorf("the second request must get the valid document for its page: %q", trunc(string(raw2), 200))
	}
	srv.Disarm()
	if len(se.Reqs) != 2 || se.Reqs[0].Page != 2 || se.Reqs[1].Page != 3 || !se.Reqs[0].Mutated || se.Reqs[1].Mutated {
		t.Errorf("session record %+v", se.Reqs)
	}
	if se.Reqs[0].Class != "L" {
		t.Errorf("class = %q, want L", se.Reqs[0].Class)
	}
}

// rawGet2 is rawGet without the Disarm, so one session can see several requests.
func rawGet2(t *testing.T, srv *HostSrv, uri string, wait time.Duration) []byte {
	t.Helper()
	c, err := net.Dial("tcp4", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	_ = c.SetDeadline(time.Now().Add(wait))
	if _, err := io.WriteString(c, "GET "+uri+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(c)
	return raw
}

func TestHostSrvRejectsMalformedRequests(t *testing.T) {
	srv, err := NewHostSrv()
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer srv.Close()
	srv.Arm(newSession(mutByID("C0"), "H"))
	for name, req := range map[string]string{
		"no method and uri": "X\r\n\r\n",
		"closed mid-head":   "GET /health HTTP/1.1\r\nHost:",
	} {
		c, err := net.Dial("tcp4", srv.Addr())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(c, req)
		if cw, ok := c.(*net.TCPConn); ok {
			_ = cw.CloseWrite()
		}
		if raw, _ := io.ReadAll(c); len(raw) != 0 {
			t.Errorf("%s: answered %q", name, raw)
		}
		_ = c.Close()
	}
	if reqs := srv.Disarm(); len(reqs) != 0 {
		t.Errorf("malformed requests were recorded: %+v", reqs)
	}
}

func TestHostSrvDrainsARequestBody(t *testing.T) {
	srv, err := NewHostSrv()
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer srv.Close()
	srv.Arm(newSession(mutByID("C0"), "A"))
	c, err := net.Dial("tcp4", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	body := `{"username":"u","password":"p"}`
	_, _ = io.WriteString(c, "POST /auth/login HTTP/1.1\r\nHost: x\r\nContent-Length: "+itoa(len(body))+"\r\nno colon line\r\n\r\n"+body)
	raw, _ := io.ReadAll(c)
	reqs := srv.Disarm()
	if !bytes.HasPrefix(raw, []byte("HTTP/1.1 200 OK")) || !bytes.Contains(raw, []byte("SYNTHETIC-SESSION-TOKEN-0001")) {
		t.Errorf("login answer %q", trunc(string(raw), 200))
	}
	if len(reqs) != 1 || reqs[0].Class != "A" || reqs[0].Method != "POST" {
		t.Errorf("recorded %+v", reqs)
	}
}

func TestClassifyAndReasonFor(t *testing.T) {
	for _, tc := range []struct{ method, path, want string }{
		{"GET", "/health", "H"}, {"POST", "/auth/login", "A"}, {"GET", "/api/v1/projects", "P"}, {"POST", "/api/v1/projects", "C"},
		{"GET", "/api/v1/projects/2/environments", "E"}, {"GET", "/api/v1/projects/2/secrets/deleted", "D"},
		{"GET", "/api/v1/secrets", "L"}, {"GET", "/api/v1/secrets/value", "V"}, {"GET", "/api/v1/secrets/12", "V"},
		{"DELETE", "/api/v1/secrets/12", "?"}, {"GET", "/nope", "?"}, {"POST", "/health", "?"},
	} {
		if got := classify(tc.method, tc.path); got != tc.want {
			t.Errorf("classify(%s %s) = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
	for code, want := range map[int]string{200: "OK", 201: "Created", 204: "No Content", 302: "Found", 401: "Unauthorized",
		403: "Forbidden", 404: "Not Found", 500: "Internal Server Error", 503: "Service Unavailable", 999: "Status"} {
		if got := reasonFor(code); got != want {
			t.Errorf("reasonFor(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestChunkerFramesPayloadAndTerminator(t *testing.T) {
	var b bytes.Buffer
	ch := &chunker{w: &b, spec: ChunkSpec{Size: 4}}
	if n, err := ch.Write([]byte("abcdefghij")); err != nil || n != 10 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if err := ch.finish(); err != nil {
		t.Fatal(err)
	}
	if want := "4\r\nabcd\r\n4\r\nefgh\r\n2\r\nij\r\n0\r\n\r\n"; b.String() != want {
		t.Errorf("chunked %q, want %q", b.String(), want)
	}
	b.Reset()
	ch = &chunker{w: &b, spec: ChunkSpec{NoTerm: true}}
	_ = ch.finish()
	if b.Len() != 0 {
		t.Errorf("NoTerm still wrote %q", b.String())
	}
	b.Reset()
	ch = &chunker{w: &b, spec: ChunkSpec{BadSize: "zz", EarlyZero: 1, BareLF: true}}
	_, _ = ch.Write([]byte("ab"))
	if want := "zz\nab\n0\n\n"; b.String() != want {
		t.Errorf("bad size / early zero: %q, want %q", b.String(), want)
	}
	// a failing writer stops the encoder at the first error, whichever write it was
	for n := range 3 {
		w := &capWriter{n: int64(n)}
		if _, err := (&chunker{w: w, spec: ChunkSpec{}}).Write([]byte("abc")); err == nil {
			t.Errorf("writer capped at %d bytes: no error", n)
		}
	}
	if err := (&chunker{w: &capWriter{}, spec: ChunkSpec{}}).finish(); err == nil {
		t.Error("finish on a failing writer returned nil")
	}
}

func TestNewGzipRoundTrips(t *testing.T) {
	var b bytes.Buffer
	z := newGzip(&b)
	_, _ = z.Write([]byte("hello"))
	_ = z.Close()
	zr, err := gzip.NewReader(&b)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(zr); string(got) != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestSleepAbortReturnsOnDone(t *testing.T) {
	done := make(chan struct{})
	close(done)
	start := time.Now()
	sleepAbort(time.Minute, done)
	if time.Since(start) > 5*time.Second {
		t.Error("sleepAbort ignored a closed done channel")
	}
	sleepAbort(time.Millisecond, make(chan struct{})) // the timer branch
}
