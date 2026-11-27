package egressref

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// This file is the DNS-rebinding oracle for the sites that build their own
// netutil.Dialer with no resolver field (S09, S11, S12 to S14, S18). The only seam those
// sites have is the standard library's net.DefaultResolver, which netutil.DefaultResolver
// calls. RebindDNS installs a net.Resolver whose Dial hands the Go DNS client an in-process
// connection, so the site's REAL DialContext resolves through the real stdlib resolver
// code against a server that answers one set of addresses to the first lookup and another
// to every later one.
//
// What it does NOT verify: a real DNS server, real network resolution, the cgo resolver,
// /etc/hosts or search-domain handling (the name is rooted), or a site configured with an
// egress proxy (the dial then targets the proxy). It replaces a process-global variable,
// so a caller must not run in parallel with a test that resolves names.

// rebindName is the rooted host the targets dial. It is not any site's real host: the
// guard is the same netutil.Dialer whatever the name is.
const rebindName = "rebind.example.test."

// RebindDNS is an in-process DNS server for one dial: the first A and the first AAAA query
// are answered from first, every later query from after.
type RebindDNS struct {
	mu        sync.Mutex
	first     []Addr
	after     []Addr
	nA, nAAAA int
}

// NewRebindDNS returns a server answering first, then after. An address is served as an A
// record when its Kind is "ipv4" and as an AAAA record otherwise (so an IPv4-mapped IPv6
// address is an AAAA record, as on the wire).
func NewRebindDNS(first, after []Addr) *RebindDNS {
	return &RebindDNS{first: first, after: after}
}

// Install points net.DefaultResolver at the server (Go's own resolver, PreferGo) and
// returns the function that puts the previous one back.
func (s *RebindDNS) Install() (restore func()) {
	orig := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: s.dial}
	return func() { net.DefaultResolver = orig }
}

// Queries returns how many A and AAAA queries the server has answered.
func (s *RebindDNS) Queries() (a, aaaa int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nA, s.nAAAA
}

// dial returns a stream-framed connection (a net.Conn that is not a net.PacketConn makes
// the Go client use the two-byte length prefix of DNS over TCP, even for "udp").
func (s *RebindDNS) dial(_ context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	go s.serve(server)
	return client, nil
}

func (s *RebindDNS) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return
	}
	msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(c, msg); err != nil {
		return
	}
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	resp := s.answer(h, q)
	out, err := resp.Pack()
	if err != nil {
		return
	}
	_, _ = c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(out)))) // #nosec G115 -- a DNS message is far below 64 KiB
	_, _ = c.Write(out)
}

func (s *RebindDNS) answer(h dnsmessage.Header, q dnsmessage.Question) dnsmessage.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	switch q.Type {
	case dnsmessage.TypeA:
		s.nA++
		n = s.nA
	case dnsmessage.TypeAAAA:
		s.nAAAA++
		n = s.nAAAA
	}
	set := s.first
	if n > 1 {
		set = s.after
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true},
		Questions: []dnsmessage.Question{q},
	}
	for _, a := range set {
		hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 0}
		switch {
		case q.Type == dnsmessage.TypeA && a.Kind == "ipv4":
			var v [4]byte
			copy(v[:], a.IP.To4())
			hdr.Type = dnsmessage.TypeA
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: v}})
		case q.Type == dnsmessage.TypeAAAA && a.Kind != "ipv4":
			var v [16]byte
			copy(v[:], a.IP.To16())
			hdr.Type = dnsmessage.TypeAAAA
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: v}})
		}
	}
	return msg
}

// rstClose closes c with a zero linger when it is a TCP connection.
func rstClose(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

// rebindDialTimeout bounds a dial that a regressed guard lets through to a real address.
const rebindDialTimeout = 2 * time.Second

// CheckRebind drives dial (a site's real DialContext) at a hostname whose first answer set
// is {first, second} and whose every later answer is the cloud metadata address
// 169.254.169.254, and asserts the DNS-rebinding properties:
//
//   - the whole first answer set is refused when the site policy refuses ANY address in it
//     (a mixed public/link-local answer), decided from that first set alone;
//   - when the policy permits the set, the connection goes to the address that was
//     validated, never to the later (rebound) answer: the set is then the loopback
//     address, so the dial lands on a listener this function owns and no packet leaves
//     the machine;
//   - the guard asked the resolver once per record type for the one dial, so no second,
//     unvalidated lookup sits between validation and connect.
//
// refuse must permit loopback (the link-local tier does; the private tier does not, and
// this check then reports that it cannot run harmlessly). An address that the policy
// permits is replaced by loopback in the served set, so over-blocking of a legitimate
// public address is not judged here: the Probe-based targets judge that on literals.
func CheckRebind(t TB, dial DialFunc, first, second Addr, refuse func(Addr) bool) {
	t.Helper()
	loop := Decode(0, 127, 0, 0, 1)
	if refuse(loop) {
		t.Fatalf("CheckRebind needs a tier that permits loopback; this policy refuses %s", loop)
	}
	wantRefuse := refuse(first) || refuse(second)

	served := []Addr{first, second}
	if !wantRefuse {
		served = []Addr{loop}
	}
	dns := NewRebindDNS(served, []Addr{Decode(0, 169, 254, 169, 254)})
	defer dns.Install()()

	// A listener only when a connection is expected. Connections are closed with a
	// zero linger (RST), so a fuzz worker running thousands of inputs a second does not
	// pile up TIME_WAIT sockets until it runs out of ephemeral ports.
	port := "443"
	if !wantRefuse {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("cannot open the loopback listener: %v", err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				// Hold it until the dialer's RST-close arrives, so the connect itself
				// is never the thing that sees a reset.
				go func() {
					_, _ = io.Copy(io.Discard, c)
					_ = c.Close()
				}()
			}
		}()
		port = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	}

	ctx, cancel := context.WithTimeout(context.Background(), rebindDialTimeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", net.JoinHostPort(rebindName, port))
	connectedTo := ""
	if conn != nil {
		connectedTo = conn.RemoteAddr().String()
		rstClose(conn)
	}
	refused := err != nil && strings.Contains(err.Error(), refusalMarker)

	switch {
	case wantRefuse && conn != nil:
		t.Fatalf("BYPASS: answer set {%s, %s} contains an address the policy refuses, but the dial connected to %s", first, second, connectedTo)
	case wantRefuse && !refused:
		t.Fatalf("BYPASS: answer set {%s, %s} contains an address the policy refuses, dial returned %v", first, second, err)
	case !wantRefuse && refused:
		t.Fatalf("OVER-BLOCK: answer set {%s, %s} is permitted, dial returned %v", first, second, err)
	case !wantRefuse && connectedTo != net.JoinHostPort("127.0.0.1", port):
		t.Fatalf("NOT PINNED: the validated address was 127.0.0.1:%s, the dial reached %q (err %v); a later answer was used", port, connectedTo, err)
	}
	if a, aaaa := dns.Queries(); a != 1 || aaaa != 1 {
		t.Fatalf("resolver saw %d A and %d AAAA queries for one dial; want exactly one of each (0 means the stub is not in the path, more means a second lookup)", a, aaaa)
	}
}

// RunRebind registers the seeds and the fuzz body of one site's rebinding target. The
// inputs are two destinations in ten encodings each (the first answer set is both).
func RunRebind(f *testing.F, dial func() DialFunc, refuse func(Addr) bool) {
	f.Helper()
	f.Add(byte(0), byte(8), byte(8), byte(8), byte(8), byte(0), byte(8), byte(8), byte(4), byte(4))         // public, public: pinned, later answer ignored
	f.Add(byte(0), byte(8), byte(8), byte(8), byte(8), byte(0), byte(169), byte(254), byte(169), byte(254)) // mixed: public + IMDS
	f.Add(byte(0), byte(8), byte(8), byte(8), byte(8), byte(2), byte(169), byte(254), byte(169), byte(254)) // mixed: public + NAT64 IMDS
	f.Add(byte(0), byte(8), byte(8), byte(8), byte(8), byte(1), byte(169), byte(254), byte(169), byte(254)) // mixed: public + IPv4-mapped IMDS
	f.Add(byte(6), byte(169), byte(254), byte(169), byte(254), byte(0), byte(8), byte(8), byte(8), byte(8)) // Teredo IMDS first
	f.Add(byte(7), byte(0), byte(0), byte(0), byte(1), byte(9), byte(1), byte(2), byte(3), byte(4))         // fe80:: then public IPv6
	f.Add(byte(0), byte(10), byte(0), byte(0), byte(1), byte(8), byte(0), byte(0), byte(0), byte(0))        // RFC-1918 + fd00:ec2::254: permitted by the link-local tier
	f.Add(byte(0), byte(127), byte(0), byte(0), byte(1), byte(0), byte(100), byte(100), byte(100), byte(200))

	f.Fuzz(func(t *testing.T, k1, a1, b1, c1, d1, k2, a2, b2, c2, d2 byte) {
		CheckRebind(t, dial(), Decode(k1, a1, b1, c1, d1), Decode(k2, a2, b2, c2, d2), refuse)
	})
}
