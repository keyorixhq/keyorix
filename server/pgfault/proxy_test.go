// Package pgfault adds REAL PostgreSQL fault coverage (task FS-PG): a TCP fault
// proxy that cuts or stalls the connection between keyorix's storage layer and a
// real PostgreSQL server at a chosen point of the v3 wire protocol — including
// the ambiguous-commit window (COMMIT sent, acknowledgement not yet received).
//
// This is the real-fault counterpart to server/faultops, whose faults are
// injected at the Go storage-interface layer (internal/faultstorage) and never
// touch the wire, the driver's error path, or PostgreSQL's own crash-consistent
// commit. Here the backend is a real PostgreSQL server and the fault is a real
// TCP close/stall mid-exchange; recovery relies on PostgreSQL's atomicity, not
// on a mock.
//
// Everything is in _test.go files: no production code is added or changed.
//
// What this does NOT cover: disk-full / read-only-FS (SQLSTATE 53100/57P01) and
// crash-recovery of a throwaway cluster both need a cluster this host cannot
// start (no initdb/pg_ctl/postgres binary present), so
// only connection-loss (class a) is implemented. It also does not model a lying
// NIC or mid-byte corruption — a clean TCP close/stall only.
package pgfault

import (
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// faultMode selects what the proxy does when it reaches its armed fault point.
type faultMode uint8

const (
	faultNone  faultMode = iota // pass-through
	faultCut                    // close both halves (a TCP RST/close)
	faultStall                  // stop forwarding for stallFor, then close
)

// direction of a message stream.
const (
	dirFrontend = 0 // client -> server (where COMMIT/Sync is sent)
	dirBackend  = 1 // server -> client (where the commit ack / ReadyForQuery returns)
)

// faultSpec is the whole fault: cut/stall the Nth typed message (1-based) in
// direction dir, counted from the moment the proxy is armed. mode faultNone
// arms nothing (a pure pass-through reference run).
type faultSpec struct {
	mode     faultMode
	dir      int
	n        int // 1-based message index since arm; <=0 means "never reach it"
	stallFor time.Duration
}

// proxy is a single-upstream TCP fault proxy. Start it, point a client DSN at
// Addr(), run warmup traffic, then Arm(spec) and run the target operation.
type proxy struct {
	ln       net.Listener
	upstream string

	armed atomic.Bool
	spec  atomic.Pointer[faultSpec]

	feCount atomic.Int64 // typed frontend messages forwarded since arm
	beCount atomic.Int64 // typed backend messages forwarded since arm

	tripped atomic.Bool // set once the fault fired (so the oracle can tell)

	mu    sync.Mutex
	pairs []*connPair
	done  chan struct{}
}

type connPair struct {
	client net.Conn
	server net.Conn
	once   sync.Once
}

func (p *connPair) close() {
	p.once.Do(func() {
		_ = p.client.Close()
		_ = p.server.Close()
	})
}

// newProxy starts a proxy listening on 127.0.0.1:0 forwarding to upstream
// (host:port). Call Close to stop it.
func newProxy(upstream string) (*proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &proxy{ln: ln, upstream: upstream, done: make(chan struct{})}
	go p.acceptLoop()
	return p, nil
}

// Addr is the host:port a client DSN should connect to.
func (p *proxy) Addr() string { return p.ln.Addr().String() }

// Arm resets the per-direction counters and installs spec. After Arm, the proxy
// cuts/stalls the Nth typed message in spec.dir counted from now.
func (p *proxy) Arm(spec faultSpec) {
	p.feCount.Store(0)
	p.beCount.Store(0)
	p.tripped.Store(false)
	s := spec
	p.spec.Store(&s)
	p.armed.Store(true)
}

// Disarm returns the proxy to pass-through (used for warmup / the reference run).
func (p *proxy) Disarm() { p.armed.Store(false) }

// Tripped reports whether the fault actually fired since the last Arm.
func (p *proxy) Tripped() bool { return p.tripped.Load() }

func (p *proxy) Close() error {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	err := p.ln.Close()
	p.mu.Lock()
	for _, pr := range p.pairs {
		pr.close()
	}
	p.mu.Unlock()
	return err
}

func (p *proxy) acceptLoop() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *proxy) handle(client net.Conn) {
	server, err := net.Dial("tcp", p.upstream)
	if err != nil {
		_ = client.Close()
		return
	}
	pr := &connPair{client: client, server: server}
	p.mu.Lock()
	p.pairs = append(p.pairs, pr)
	p.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	// frontend: client -> server, first message is the untyped StartupMessage.
	go func() { defer wg.Done(); p.pump(pr, client, server, dirFrontend, true) }()
	// backend: server -> client, all typed messages.
	go func() { defer wg.Done(); p.pump(pr, server, client, dirBackend, false) }()
	wg.Wait()
	pr.close()
}

// pump copies PostgreSQL v3 messages from src to dst, one framed message at a
// time, honouring the armed fault. startup=true means the very first message is
// the untyped StartupMessage (int32 length + body, no type byte).
func (p *proxy) pump(pr *connPair, src, dst net.Conn, dir int, startup bool) {
	br := src
	first := startup
	for {
		msg, err := readPGMessage(br, first)
		first = false
		if err != nil {
			pr.close()
			return
		}
		if p.armed.Load() {
			spec := p.spec.Load()
			if spec != nil && spec.dir == dir && spec.mode != faultNone {
				var c int64
				if dir == dirFrontend {
					c = p.feCount.Add(1)
				} else {
					c = p.beCount.Add(1)
				}
				if spec.n > 0 && c == int64(spec.n) {
					// Reached the armed point: do NOT forward this message.
					p.tripped.Store(true)
					if spec.mode == faultStall {
						// Hold the stream, then cut (an ambiguous stall). The
						// cut, not a client deadline, ends the commit: the
						// audit write path detaches from the caller's context.
						select {
						case <-time.After(spec.stallFor):
						case <-p.done:
						}
					}
					pr.close()
					return
				}
			}
		}
		if _, err := dst.Write(msg); err != nil {
			pr.close()
			return
		}
	}
}

// readPGMessage reads one framed message. If startup, it is the untyped startup
// packet (4-byte big-endian length including itself, then body). Otherwise it is
// a typed message (1 type byte + 4-byte length including the 4 but not the type,
// then body). Returns the complete raw bytes to forward.
func readPGMessage(r net.Conn, startup bool) ([]byte, error) {
	if startup {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, err
		}
		total := int(be32(lenBuf[:]))
		if total < 4 || total > maxPGMessage {
			return nil, errors.New("pgfault: implausible startup length")
		}
		body := make([]byte, total-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		return append(lenBuf[:], body...), nil
	}
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(be32(hdr[1:5])) // length counts itself (the 4 bytes) + body
	if length < 4 || length > maxPGMessage {
		return nil, errors.New("pgfault: implausible message length")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	out := make([]byte, 5+len(body))
	copy(out, hdr[:])
	copy(out[5:], body)
	return out, nil
}

// maxPGMessage bounds a single framed message so a corrupt length never makes
// the proxy allocate unboundedly (resource bound: per-message allocation cap).
const maxPGMessage = 64 << 20 // 64 MiB, well above any real audit/secret row

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// proxyClientDSN rewrites base's host:port to point at proxyAddr (the proxy's
// listen address) while keeping userinfo, database, and every query parameter.
// It returns the rewritten client DSN and the original upstream host:port the
// proxy must dial. base must be a postgres:// URL DSN (the KEYORIX_TEST_PG_DSN form).
func proxyClientDSN(base, proxyAddr string) (clientDSN, upstream string, err error) {
	u, err := url.Parse(base)
	if err != nil {
		// Never echo base: it carries the password.
		return "", "", errors.New("pgfault: cannot parse base DSN (details withheld: contains password)")
	}
	upstream = u.Host
	if upstream == "" {
		return "", "", errors.New("pgfault: base DSN has no host:port")
	}
	if _, _, e := net.SplitHostPort(upstream); e != nil {
		upstream = net.JoinHostPort(upstream, "5432")
	}
	u.Host = proxyAddr
	return u.String(), upstream, nil
}
