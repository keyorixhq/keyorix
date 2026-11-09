//go:build !windows

package encryption_test

// process_crash_recovery_pg_proxy_seam_test.go checks the wire seam against a
// scripted fake server, so its counting does not depend on a real PostgreSQL. It
// says nothing about what a real server does; the PG-gated tests cover that.

import (
	"bufio"
	"encoding/binary"
	"net"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

func pcrashPGFrame(typ byte, body []byte) []byte {
	frame := make([]byte, 5, 5+len(body))
	frame[0] = typ
	binary.BigEndian.PutUint32(frame[1:5], uint32(4+len(body))) //nolint:gosec // short test frames
	return append(frame, body...)
}

func pcrashPGCStr(parts ...string) []byte {
	var b []byte
	for _, p := range parts {
		b = append(append(b, p...), 0)
	}
	return b
}

// pcrashPGFakeServer answers each Query and Sync with ReadyForQuery, reporting
// the transaction status status() gives, and records the frame types it received.
type pcrashPGFakeServer struct {
	l      net.Listener
	mu     sync.Mutex
	frames []string
	status func() byte
}

func newPCrashPGFakeServer(t *testing.T, status func() byte) *pcrashPGFakeServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	s := &pcrashPGFakeServer{l: l, status: status}
	go s.serve()
	return s
}

func (s *pcrashPGFakeServer) serve() {
	c, err := s.l.Accept()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	var hdr [4]byte
	if _, err := readFull(r, hdr[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if _, err := readFull(r, make([]byte, n-4)); err != nil {
		return
	}
	for {
		typ, frame, err := pcrashPGReadFrame(r)
		if err != nil {
			return
		}
		s.mu.Lock()
		switch typ {
		case 'Q':
			q, _ := pcrashPGCString(frame[5:])
			s.frames = append(s.frames, "Q:"+q)
		default:
			s.frames = append(s.frames, string(typ))
		}
		s.mu.Unlock()
		if typ == 'Q' || typ == 'S' {
			if _, err := c.Write(pcrashPGFrame('Z', []byte{s.status()})); err != nil {
				return
			}
		}
	}
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (s *pcrashPGFakeServer) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.frames)
}

// pcrashPGProxyClient is a connected client plus the seam labels the proxy ticked.
type pcrashPGProxyClient struct {
	c      net.Conn
	r      *bufio.Reader
	mu     *sync.Mutex
	labels *[]string
}

func newPCrashPGProxyClient(t *testing.T, srv *pcrashPGFakeServer, split *pcrashPGSplit, cutAt string) *pcrashPGProxyClient {
	t.Helper()
	var mu sync.Mutex
	labels := &[]string{}
	tick := func(label string) bool {
		mu.Lock()
		defer mu.Unlock()
		*labels = append(*labels, label)
		return label == cutAt
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go (&pcrashPGProxy{target: srv.l.Addr().String(), tick: tick, split: split}).serve(l)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 196608) // protocol 3.0
	startup := make([]byte, 4, 8)
	binary.BigEndian.PutUint32(startup, 8)
	if _, err := c.Write(append(startup, body...)); err != nil {
		t.Fatal(err)
	}
	return &pcrashPGProxyClient{c: c, r: bufio.NewReader(c), mu: &mu, labels: labels}
}

func (c *pcrashPGProxyClient) query(t *testing.T, q string) {
	t.Helper()
	if _, err := c.c.Write(pcrashPGFrame('Q', pcrashPGCStr(q))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pcrashPGReadFrame(c.r); err != nil {
		t.Fatalf("query %q: no reply: %v", q, err)
	}
}

func (c *pcrashPGProxyClient) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(*c.labels)
}

func TestPCrashPGClassify(t *testing.T) {
	for _, tc := range []struct {
		q, want string
		write   bool
	}{
		{"SELECT 1", "", false},
		{"begin", "", false},
		{"commit", "commit", true},
		{"UPDATE secret_versions SET x = $1", "update:secret_versions", true},
		{`INSERT INTO "public"."roles" (name) VALUES ($1)`, "insert:roles", true},
		{"DELETE FROM system_metadata WHERE k = $1", "delete:system_metadata", true},
		{"CREATE UNIQUE INDEX i ON t (c)", "ddl:create:unique", true},
		{"COPY secret_nodes FROM STDIN", "copy:secret_nodes", true},
		{"WITH x AS (SELECT 1) SELECT * FROM x", "", false},
		{"WITH x AS (DELETE FROM t RETURNING id) SELECT * FROM x", "with", true},
		{"  ", "", false},
	} {
		got, write := pcrashPGClassify(tc.q)
		if got != tc.want || write != tc.write {
			t.Errorf("%q: got %q,%v want %q,%v", tc.q, got, write, tc.want, tc.write)
		}
	}
}

// TestPCrashPGProxySeams pins the order and meaning of the seams: a write before
// it is forwarded, a commit before and after the server answered.
func TestPCrashPGProxySeams(t *testing.T) {
	status := byte('T')
	var mu sync.Mutex
	srv := newPCrashPGFakeServer(t, func() byte {
		mu.Lock()
		defer mu.Unlock()
		return status
	})
	c := newPCrashPGProxyClient(t, srv, nil, "")
	c.query(t, "begin")
	c.query(t, "SELECT 1")
	c.query(t, "UPDATE secret_versions SET x = 1")
	mu.Lock()
	status = 'I'
	mu.Unlock()
	c.query(t, "commit")
	want := []string{"sql:pre:update:secret_versions", "sql:pre:commit", "sql:acked:commit"}
	if got := c.seen(); !reflect.DeepEqual(got, want) {
		t.Fatalf("seams: got %v want %v", got, want)
	}
}

// TestPCrashPGProxySeamsExtendedProtocol checks that Parse/Bind/Execute is
// attributed to the statement the Bind named, and that the seam comes before Execute.
func TestPCrashPGProxySeamsExtendedProtocol(t *testing.T) {
	srv := newPCrashPGFakeServer(t, func() byte { return 'T' })
	c := newPCrashPGProxyClient(t, srv, nil, "sql:pre:update:secret_versions")
	send := func(frames ...[]byte) {
		for _, f := range frames {
			if _, err := c.c.Write(f); err != nil {
				t.Fatal(err)
			}
		}
	}
	send(
		pcrashPGFrame('P', append(pcrashPGCStr("s1", "UPDATE secret_versions SET x = $1"), 0, 0)),
		pcrashPGFrame('B', append(pcrashPGCStr("", "s1"), 0, 0, 0, 0, 0, 0)),
		pcrashPGFrame('E', append(pcrashPGCStr(""), 0, 0, 0, 0)),
		pcrashPGFrame('S', nil),
	)
	// The cut closes the connection instead of answering.
	if _, _, err := pcrashPGReadFrame(c.r); err == nil {
		t.Fatal("a cut at Execute must close the connection")
	}
	if got := c.seen(); !reflect.DeepEqual(got, []string{"sql:pre:update:secret_versions"}) {
		t.Fatalf("seams: got %v", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.received()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := srv.received(); !reflect.DeepEqual(got, []string{"P", "B"}) {
		t.Fatalf("the server must not receive Execute or Sync after the cut: %v", got)
	}
}

// TestPCrashPGProxySplitInjects checks the red-proof split on the simple
// protocol: COMMIT and BEGIN reach the server before the second UPDATE and the
// client never sees their replies. Without commit nothing is injected.
func TestPCrashPGProxySplitInjects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		commit bool
		want   []string
	}{
		{"commit", true, []string{"Q:UPDATE secret_versions SET x = 1", "Q:COMMIT", "Q:BEGIN", "Q:UPDATE secret_versions SET x = 2"}},
		{"no-commit", false, []string{"Q:UPDATE secret_versions SET x = 1", "Q:UPDATE secret_versions SET x = 2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newPCrashPGFakeServer(t, func() byte { return 'T' })
			died := make(chan struct{})
			c := newPCrashPGProxyClient(t, srv, &pcrashPGSplit{commit: tc.commit, die: func() { close(died); select {} }}, "")
			c.query(t, "UPDATE secret_versions SET x = 1")
			if _, err := c.c.Write(pcrashPGFrame('Q', pcrashPGCStr("UPDATE secret_versions SET x = 2"))); err != nil {
				t.Fatal(err)
			}
			select {
			case <-died:
			case <-time.After(5 * time.Second):
				t.Fatal("the split never fired its kill")
			}
			if got := srv.received(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("server received %v want %v", got, tc.want)
			}
		})
	}
}

func TestPCrashPGKillPoints(t *testing.T) {
	trace := []string{
		"sql:pre:update:a", "sql:pre:update:a", "sql:pre:update:a", "sql:pre:commit", "sql:acked:commit",
		"file:manifest:write", "sweep:after", "sql:pre:ddl:create:index", "sql:pre:ddl:create:index", "sql:pre:ddl:create:index",
	}
	got := pcrashPGKillPoints(trace, pcrashPGModeKill, 0)
	want := []int64{1, 3, 4, 5, 6, 7, 8, 10}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kill mode: got %v want %v", got, want)
	}
	got = pcrashPGKillPoints(trace, pcrashPGModeCut, 0)
	if want := []int64{1, 4, 5}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cut mode: got %v want %v", got, want)
	}
	got = pcrashPGKillPoints(trace, pcrashPGModeKill, 2)
	if len(got) != 6 || !slices.Contains(got, 6) || !slices.Contains(got, 7) {
		t.Fatalf("maxper keeps essential seams only: %v", got)
	}
}
