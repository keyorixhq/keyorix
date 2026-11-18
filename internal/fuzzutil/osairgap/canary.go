package osairgap

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"time"
)

// canarySink is a loopback TCP listener that pretends to be an HTTP(S) proxy.
// Any egress intent that honours HTTP_PROXY/HTTPS_PROXY/ALL_PROXY lands here as
// a CONNECT (for https) or an absolute-URI GET/POST (for http). We record the
// first request line so the oracle can name exactly where the child tried to go
// — a deterministic signal that does not depend on /proc sampling timing.
//
// It lives on loopback, so by the Allowlist it is itself "allowed"; the SIGNAL
// is that the child formed an egress intent at all, captured as a CanaryHit.
type canarySink struct {
	addr string
	ln   net.Listener
	mu   sync.Mutex
	seen []string
	done chan struct{}
}

func startCanary() (*canarySink, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	c := &canarySink{addr: ln.Addr().String(), ln: ln, done: make(chan struct{})}
	go c.accept()
	return c, nil
}

func (c *canarySink) accept() {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				return
			}
		}
		go c.handle(conn)
	}
}

func (c *canarySink) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		c.record("(connect, no request line)")
		return
	}
	line = strings.TrimRight(line, "\r\n")
	// For CONNECT the first line is "CONNECT host:port HTTP/1.1"; for a plain
	// proxied GET it is "GET http://host/path HTTP/1.1". Record method+target.
	parts := strings.Fields(line)
	switch {
	case len(parts) >= 2:
		c.record(parts[0] + " " + parts[1])
	default:
		c.record(line)
	}
}

func (c *canarySink) record(s string) {
	c.mu.Lock()
	c.seen = append(c.seen, s)
	c.mu.Unlock()
}

func (c *canarySink) hits() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.seen))
	copy(out, c.seen)
	return out
}

func (c *canarySink) Close() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	_ = c.ln.Close()
}
