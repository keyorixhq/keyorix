// Package osairgap is the OS-level air-gap / egress harness for AGP1. Where the
// resguard NetMeter is an IN-PROCESS oracle (it only sees dials routed through
// the *http.Transport / net.Dialer the harness hands the code under test —
// resguard.go:37-44), osairgap runs real Keyorix code AS A CHILD PROCESS inside
// a fresh network namespace (CLONE_NEWNET, loopback-only) and proves, at the OS,
// that the child makes no egress attempt to anything outside loopback and the
// one configured database endpoint.
//
// Two complementary detectors, because each is blind to what the other catches:
//
//   - Containment (the air-gap itself): inside the netns only `lo` is up, so any
//     non-loopback connect(2)/sendto(2) fails immediately with ENETUNREACH. This
//     is the property under test — a real egress CANNOT leave the host.
//   - Attempt detection (did it TRY): a loopback canary that the child's proxy
//     and resolver env point at records any proxy-routed/DNS egress INTENT with
//     its target; and a /proc/<pid>/net/{tcp,tcp6,udp,udp6} sampler catches a
//     direct (non-proxy) dial that got far enough to create a socket entry
//     (SYN_SENT to an unreachable host lingers briefly).
//
// What this does NOT establish is stated on each type and in the AGP1 report:
// the /proc sampler is timing-best-effort (a connect that fails faster than the
// sample interval leaves no entry); raw/packet sockets and a connect that never
// reaches the socket layer are invisible to it; the canary only catches egress
// that honours HTTP(S)_PROXY. The containment half, by contrast, is not
// best-effort: the kernel enforces it.
//
// Test-only: nothing outside *_test.go may import this package
// (TestOsairgapImportedOnlyFromTests).
package osairgap

import (
	"net"
	"strconv"
	"strings"
)

// Endpoint is a parsed remote peer (IP + port) observed on a socket.
type Endpoint struct {
	IP   net.IP
	Port int
}

func (e Endpoint) String() string { return net.JoinHostPort(e.IP.String(), strconv.Itoa(e.Port)) }

// Allowlist decides which remote endpoints a child is permitted to reach. The
// air-gap rule: loopback always, plus AT MOST the one configured database
// endpoint (an operator setting, not egress). Everything else is an egress
// attempt — the oracle fires.
//
// The classifier is the oracle's eyes: a bug here (e.g. treating a private-range
// address as "internal/allowed") makes the whole harness blind, which is exactly
// why FuzzEgressClassifier fuzzes it against adversarial endpoints.
type Allowlist struct {
	// DB, when non-nil, is the single permitted non-loopback endpoint (the
	// configured database). Matched on IP AND port, both must equal. A nil DB
	// means loopback-only (the storage-less / local-SQLite air-gap shape).
	DB *Endpoint
}

// Classify reports whether e is Allowed, and a one-word reason. It NEVER treats
// any non-loopback address as allowed unless it exactly equals the configured
// DB endpoint. It must not panic on any input (fuzzed).
func (a Allowlist) Classify(e Endpoint) (allowed bool, reason string) {
	if e.IP == nil {
		// An unparseable/zero address is not loopback and not the DB: treat as
		// egress, never as allowed. (Fails closed on garbage.)
		return false, "unparseable"
	}
	if e.IP.IsLoopback() {
		return true, "loopback"
	}
	// Unspecified (0.0.0.0 / ::) is a bind-any, never a real remote peer; a
	// socket in a non-LISTEN state should never show it as a peer, but if it
	// does, it is not egress to a real host — classify as not-egress but not
	// "allowed DB" either. We treat it as allowed=true/reason "unspecified" so
	// the oracle does not false-fire on a transient 0.0.0.0 peer row; the report
	// documents this. (It can never be a successful egress: you cannot route a
	// packet to 0.0.0.0.)
	if e.IP.IsUnspecified() {
		return true, "unspecified"
	}
	if a.DB != nil && a.DB.IP != nil && e.IP.Equal(a.DB.IP) && e.Port == a.DB.Port {
		return true, "configured-db"
	}
	return false, "egress"
}

// parseProcNetLine parses one data row of /proc/net/tcp|tcp6|udp|udp6 and
// returns the REMOTE endpoint. The format: the 2nd whitespace field is
// "local_addr:port", the 3rd is "rem_addr:port", both as big-endian hex of the
// address bytes in host order (little-endian per 32-bit word on x86). Returns
// ok=false for a header line or an unparseable row (never panics — fuzzed).
func parseProcNetLine(line string, v6 bool) (local, rem Endpoint, state int, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Endpoint{}, Endpoint{}, 0, false
	}
	// fields[0] is "sl" index "N:"; the header row's fields[1] == "local_address".
	if fields[1] == "local_address" || fields[1] == "local_addr" {
		return Endpoint{}, Endpoint{}, 0, false
	}
	lip, lport, ok1 := parseHexAddr(fields[1], v6)
	rip, rport, ok2 := parseHexAddr(fields[2], v6)
	if !ok1 || !ok2 {
		return Endpoint{}, Endpoint{}, 0, false
	}
	st, err := strconv.ParseInt(fields[3], 16, 32)
	if err != nil {
		return Endpoint{}, Endpoint{}, 0, false
	}
	return Endpoint{IP: lip, Port: lport}, Endpoint{IP: rip, Port: rport}, int(st), true
}

// parseHexAddr parses "AABBCCDD:PORT" (v4, 8 hex addr digits) or a 32-hex-digit
// v6 form, both big-endian-hex-of-wire-bytes-in-word-LE as the kernel emits.
func parseHexAddr(s string, v6 bool) (net.IP, int, bool) {
	before, after, ok := strings.CutLast(s, ":")
	if !ok {
		return nil, 0, false
	}
	addrHex, portHex := before, after
	port64, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil || port64 < 0 || port64 > 65535 {
		return nil, 0, false
	}
	if v6 {
		if len(addrHex) != 32 {
			return nil, 0, false
		}
		ip := make(net.IP, 16)
		// Four 32-bit words, each little-endian within the hex.
		for w := range 4 {
			word := addrHex[w*8 : w*8+8]
			var b [4]byte
			for i := range 4 {
				v, err := strconv.ParseUint(word[i*2:i*2+2], 16, 8)
				if err != nil {
					return nil, 0, false
				}
				b[i] = byte(v)
			}
			// little-endian word: byte order within the word is reversed.
			for i := range 4 {
				ip[w*4+i] = b[3-i]
			}
		}
		return ip, int(port64), true
	}
	if len(addrHex) != 8 {
		return nil, 0, false
	}
	var b [4]byte
	for i := range 4 {
		v, err := strconv.ParseUint(addrHex[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, 0, false
		}
		b[i] = byte(v)
	}
	// Kernel emits the v4 address as a 32-bit little-endian word, so the wire
	// bytes are reversed: byte 0 of the hex is the low-order octet.
	ip := net.IPv4(b[3], b[2], b[1], b[0])
	return ip, int(port64), true
}
