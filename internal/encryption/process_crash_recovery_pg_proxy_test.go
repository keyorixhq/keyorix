//go:build !windows

package encryption_test

// process_crash_recovery_pg_proxy_test.go is the PostgreSQL seam of
// FuzzProcessCrashRecoveryPG: a wire-protocol forwarder that runs inside the
// child process, between pgx and the server, so nothing in production changes.
//
// It counts, in order and together with the key-file seams:
//   - every write statement, just before it leaves for the server (sql:pre:*);
//   - every COMMIT, the same way (sql:pre:commit);
//   - every ReadyForQuery that reports an idle session after a write, just
//     before the client hears it (sql:acked:*). At that point the server has
//     committed and the client does not know yet, a window SQLite's hooks do
//     not have.
//
// Reads are not seams: dying before a statement that changes nothing is the
// same state as dying before the write that follows it.
//
// What it does not see: a statement the first keyword does not identify as a
// write (the list is in pcrashPGClassify, derived from the statement forms the
// operations under test send; a new form is simply not a seam). It requires
// sslmode=disable, because an encrypted stream cannot be parsed; startup refuses
// an SSLRequest rather than silently forwarding opaque bytes with no seams.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
)

const (
	pcrashPGModeKill = "kill" // SIGKILL this process at the seam
	pcrashPGModeCut  = "cut"  // abruptly close the connection at the seam, process lives

	pcrashPGSSLRequestCode = 80877103
	pcrashPGGSSRequestCode = 80877104
)

// pcrashPGClassify names a statement's seam, or reports that it is not a write.
// Recognised write forms: COMMIT, INSERT, UPDATE, DELETE, MERGE, COPY, DO, CALL,
// CREATE, ALTER, DROP, TRUNCATE, COMMENT, and WITH containing a data-changing verb.
func pcrashPGClassify(query string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(query))
	if len(fields) == 0 {
		return "", false
	}
	verb := strings.ToLower(strings.TrimRight(fields[0], ";"))
	table := func(i int) string {
		if i >= len(fields) {
			return "?"
		}
		t := strings.ToLower(strings.Trim(fields[i], `"();`))
		if _, after, ok := strings.Cut(t, "."); ok {
			t = strings.Trim(after, `"`)
		}
		return t
	}
	switch verb {
	case "commit", "end":
		return "commit", true
	case "insert", "copy":
		if verb == "copy" {
			return "copy:" + table(1), true
		}
		return "insert:" + table(2), true
	case "update":
		return "update:" + table(1), true
	case "delete":
		return "delete:" + table(2), true
	case "merge":
		return "merge:" + table(2), true
	case "do", "call":
		return verb, true
	case "create", "alter", "drop", "truncate", "comment":
		if len(fields) > 1 {
			return "ddl:" + verb + ":" + strings.ToLower(fields[1]), true
		}
		return "ddl:" + verb, true
	case "with":
		if pcrashPGCTEWrite.MatchString(query) {
			return "with", true
		}
	}
	return "", false
}

// pcrashPGCTEWrite finds a data-changing verb inside a WITH statement. It also
// matches SELECT ... FOR UPDATE in a CTE, an extra seam and not a missed one.
var pcrashPGCTEWrite = regexp.MustCompile(`(?i)(^|[\s(])(insert\s+into|delete\s+from|update\s)`)

// pcrashPGSplit is the red-proof's transaction wrapper remover: it commits the
// open transaction before the second secret_versions UPDATE and dies right after
// that statement returns. With commit false it dies at the same place without
// the early commit, which is the control.
type pcrashPGSplit struct {
	commit   bool
	updates  atomic.Int64
	armedDie atomic.Bool
	die      func()
}

// pcrashPGProxy forwards to target and calls tick at each seam. tick reports
// whether this connection must be cut at that seam.
type pcrashPGProxy struct {
	target string
	tick   func(label string) bool
	split  *pcrashPGSplit
}

func (p *pcrashPGProxy) serve(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

// pcrashPGConn is one client connection's protocol state. Statement names and
// portals are per-connection in the PostgreSQL protocol.
type pcrashPGConn struct {
	p          *pcrashPGProxy
	client     net.Conn
	server     net.Conn
	statements map[string]string
	portals    map[string]string
	wrote      atomic.Bool
	lastKind   atomic.Pointer[string]
	swallowZ   atomic.Int64 // injected queries whose responses the client must not see
	cut        atomic.Bool
}

func (c *pcrashPGConn) cutNow() {
	if !c.cut.CompareAndSwap(false, true) {
		return
	}
	for _, conn := range []net.Conn{c.client, c.server} {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = conn.Close()
	}
}

func (p *pcrashPGProxy) handle(client net.Conn) {
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = client.Close()
		return
	}
	c := &pcrashPGConn{p: p, client: client, server: server, statements: map[string]string{}, portals: map[string]string{}}
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()
	cr := bufio.NewReaderSize(client, 1<<16)
	sr := bufio.NewReaderSize(server, 1<<16)
	if err := c.startup(cr); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.serverToClient(sr)
		// The server side ended: unblock the client side.
		_ = client.Close()
	}()
	c.clientToServer(cr)
	_ = server.Close()
	<-done
}

// startup forwards the first, untyped message. A TLS or GSS request means the
// rest of the stream is opaque, so it is refused rather than forwarded blindly.
func (c *pcrashPGConn) startup(cr *bufio.Reader) error {
	var hdr [4]byte
	if _, err := io.ReadFull(cr, hdr[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 8 || n > 1<<16 {
		return fmt.Errorf("bad startup length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(cr, body); err != nil {
		return err
	}
	code := binary.BigEndian.Uint32(body[:4])
	if code == pcrashPGSSLRequestCode || code == pcrashPGGSSRequestCode {
		return errors.New("the crash seam cannot see through an encrypted connection; use sslmode=disable")
	}
	_, err := c.server.Write(append(hdr[:], body...))
	return err
}

func pcrashPGReadFrame(r *bufio.Reader) (byte, []byte, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 4 {
		return 0, nil, fmt.Errorf("bad frame length %d", n)
	}
	frame := make([]byte, 1+n)
	frame[0] = typ
	copy(frame[1:5], hdr[:])
	if _, err := io.ReadFull(r, frame[5:]); err != nil {
		return 0, nil, err
	}
	return typ, frame, nil
}

func pcrashPGCString(b []byte) (string, []byte) {
	before, after, _ := bytes.Cut(b, []byte{0})
	return string(before), after
}

// seam runs a write's seam before the frame is forwarded; false means the
// connection was cut there.
func (c *pcrashPGConn) seam(query string) bool {
	label, write := pcrashPGClassify(query)
	if !write {
		return true
	}
	c.lastKind.Store(&label)
	c.wrote.Store(true)
	if c.p.tick("sql:pre:" + label) {
		c.cutNow()
		return false
	}
	return true
}

// pcrashPGInject sends one simple query whose response the client must not see.
func (c *pcrashPGConn) inject(query string) error {
	c.swallowZ.Add(1)
	body := append([]byte(query), 0)
	frame := make([]byte, 5, 5+len(body))
	frame[0] = 'Q'
	binary.BigEndian.PutUint32(frame[1:5], uint32(4+len(body))) //nolint:gosec // short constant query
	_, err := c.server.Write(append(frame, body...))
	return err
}

// splitBefore applies the red-proof's split at the Bind or simple Query of the
// sweep's second secret_versions UPDATE. Injecting there keeps a named prepared
// statement intact; a simple Query would destroy an unnamed one mid-sequence.
func (c *pcrashPGConn) splitBefore(query string) error {
	s := c.p.split
	if s == nil {
		return nil
	}
	label, write := pcrashPGClassify(query)
	if !write || label != "update:secret_versions" || s.updates.Add(1) != 2 {
		return nil
	}
	if s.commit {
		for _, q := range []string{"COMMIT", "BEGIN"} {
			if err := c.inject(q); err != nil {
				return err
			}
		}
	}
	s.armedDie.Store(true)
	return nil
}

func (c *pcrashPGConn) clientToServer(cr *bufio.Reader) {
	for {
		typ, frame, err := pcrashPGReadFrame(cr)
		if err != nil {
			return
		}
		body := frame[5:]
		switch typ {
		case 'Q':
			query, _ := pcrashPGCString(body)
			if err := c.splitBefore(query); err != nil {
				return
			}
			if !c.seam(query) {
				return
			}
		case 'P':
			name, rest := pcrashPGCString(body)
			query, _ := pcrashPGCString(rest)
			c.statements[name] = query
		case 'B':
			portal, rest := pcrashPGCString(body)
			stmt, _ := pcrashPGCString(rest)
			query := c.statements[stmt]
			c.portals[portal] = query
			if err := c.splitBefore(query); err != nil {
				return
			}
		case 'E':
			portal, _ := pcrashPGCString(body)
			if !c.seam(c.portals[portal]) {
				return
			}
		}
		if _, err := c.server.Write(frame); err != nil {
			return
		}
		if typ == 'X' {
			return
		}
	}
}

func (c *pcrashPGConn) serverToClient(sr *bufio.Reader) {
	for {
		typ, frame, err := pcrashPGReadFrame(sr)
		if err != nil {
			return
		}
		if c.swallowZ.Load() > 0 {
			if typ == 'Z' {
				c.swallowZ.Add(-1)
			}
			continue
		}
		if typ == 'Z' && len(frame) >= 6 {
			if s := c.p.split; s != nil && s.armedDie.Load() {
				s.die()
			}
			if c.wrote.Swap(false) && frame[5] == 'I' {
				label := "write"
				if k := c.lastKind.Load(); k != nil {
					label = *k
				}
				if c.p.tick("sql:acked:" + label) {
					c.cutNow()
					return
				}
			}
		}
		if _, err := c.client.Write(frame); err != nil {
			return
		}
	}
}
