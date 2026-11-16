package resguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"
)

// NetMeter is the network seam and the air-gap oracle. It hands the harness a
// *http.Transport and a net.Dialer that count every dial, the destinations, and
// the bytes each way — and, unless AllowNonLoopback is set, FAIL any dial to a
// non-loopback address. A fuzz target under test that reaches the real network
// instead of its hardened/fake client (ADR #1949) therefore turns an input into
// a reproducer instead of silently exfiltrating or hanging on a real host.
//
// Counts are per-input: the Probe calls reset() before fn and read() after.
type NetMeter struct {
	// AllowNonLoopback, when true, meters non-loopback dials instead of failing
	// them (for a target that legitimately must reach a fake server on a
	// non-loopback test address). Default false = air-gap.
	AllowNonLoopback bool

	dials       atomic.Int64
	nonLoopback atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64

	// onWrite, when set (by a Sentinel), is handed every outbound byte slice so
	// the secret sentinel can scan the wire for a planted secret. nil = no scan.
	onWrite func([]byte)
}

// NewNetMeter returns an air-gapped NetMeter (non-loopback dials fail).
func NewNetMeter() *NetMeter { return &NetMeter{} }

func (m *NetMeter) reset() {
	m.dials.Store(0)
	m.nonLoopback.Store(0)
	m.bytesIn.Store(0)
	m.bytesOut.Store(0)
}

func (m *NetMeter) read() (dials, nonLoopback int, in, out int64) {
	return int(m.dials.Load()), int(m.nonLoopback.Load()), m.bytesIn.Load(), m.bytesOut.Load()
}

// Count/NonLoopback expose live totals outside the Probe (e.g. a TestMain-level
// assertion that no non-loopback dial happened across the whole run).
func (m *NetMeter) Count() int       { return int(m.dials.Load()) }
func (m *NetMeter) NonLoopback() int { return int(m.nonLoopback.Load()) }

// ErrAirGap is returned for a blocked non-loopback dial. The destination is in
// the message so the reproducer names what the code tried to reach.
type ErrAirGap struct{ Addr string }

func (e *ErrAirGap) Error() string {
	return fmt.Sprintf("resguard air-gap: blocked non-loopback dial to %q", e.Addr)
}

// DialContext is the metered, air-gapped dial function. Install it on any
// http.Transport or anywhere a DialContext is accepted.
func (m *NetMeter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	m.dials.Add(1)
	if !isLoopbackAddr(address) {
		m.nonLoopback.Add(1)
		if !m.AllowNonLoopback {
			return nil, &ErrAirGap{Addr: address}
		}
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: c, m: m}, nil
}

// Dialer returns a *net.Dialer whose Control hook refuses non-loopback (so even
// a caller that bypasses DialContext but uses this *net.Dialer is air-gapped).
func (m *NetMeter) Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			m.dials.Add(1)
			if !isLoopbackAddr(address) {
				m.nonLoopback.Add(1)
				if !m.AllowNonLoopback {
					return &ErrAirGap{Addr: address}
				}
			}
			return nil
		},
	}
}

// Transport returns an *http.Transport routed through DialContext, with
// redirects left to the caller. The returned transport is safe to set as a
// client's Transport or (via InstallDefault) as http.DefaultTransport.
func (m *NetMeter) Transport() *http.Transport {
	t := &http.Transport{
		DialContext:           m.DialContext,
		DialTLSContext:        nil, // let the transport wrap DialContext with TLS
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return t
}

// InstallDefault swaps http.DefaultTransport for this meter's air-gapped
// transport and returns a restore func. Call it in TestMain BEFORE m.Run() so
// any code under test that reaches for http.DefaultClient / http.Get hits the
// oracle instead of the network. Pair with a resolver block (see
// BlockDefaultResolver) to also catch bare DNS lookups.
func (m *NetMeter) InstallDefault() (restore func()) {
	prev := http.DefaultTransport
	http.DefaultTransport = m.Transport()
	return func() { http.DefaultTransport = prev }
}

// BlockDefaultResolver points net.DefaultResolver at a dialer that refuses any
// non-loopback DNS server, so a lookup that would leave the host fails loudly.
// Returns a restore func. Loopback DNS (a fake resolver on 127.0.0.1) still
// works. Install in TestMain alongside InstallDefault.
func (m *NetMeter) BlockDefaultResolver() (restore func()) {
	prev := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return m.DialContext(ctx, network, address)
		},
	}
	return func() { net.DefaultResolver = prev }
}

type countingConn struct {
	net.Conn
	m *NetMeter
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.m.bytesIn.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.m.bytesOut.Add(int64(n))
	if c.m.onWrite != nil && n > 0 {
		c.m.onWrite(b[:n])
	}
	return n, err
}

// isLoopbackAddr reports whether a "host:port" names a loopback destination.
// A bare "localhost" counts; a hostname that would need DNS does NOT (it is
// treated as non-loopback so the oracle fires rather than resolving it).
func isLoopbackAddr(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
