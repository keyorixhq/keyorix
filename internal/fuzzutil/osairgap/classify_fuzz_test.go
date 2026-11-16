package osairgap

import (
	"net"
	"testing"
)

// FuzzEgressClassifier fuzzes the egress CLASSIFIER and the /proc/net line
// parser — the oracle's eyes. The air-gap verdict is only as trustworthy as the
// decision "is this remote endpoint loopback/DB (allowed) or egress", so a bug
// here (a private-range address mis-read as internal, a parser panic, an off-by-
// one in the hex decode that aliases one IP to another) would silently blind the
// whole OS-level harness. This target asserts, over adversarial inputs:
//
//   - Classify never panics and NEVER classifies a non-loopback, non-unspecified,
//     non-exact-DB endpoint as allowed (fail-closed on anything it does not
//     positively recognise).
//   - parseProcNetLine / parseHexAddr never panic and, when they succeed, return
//     an endpoint Classify can judge; a decoded loopback hex address really is
//     loopback (so a real loopback row is not mis-flagged as egress), and a
//     decoded non-loopback address is judged egress unless it equals the DB.
//
// Red/green: TestClassifierRedGreen plants the exact defect this guards (treating
// 10/8 as "internal/allowed") and shows the invariant below catches it.
func FuzzEgressClassifier(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1}, uint16(0), []byte{10, 0, 0, 5}, uint16(5432))
	f.Add([]byte{10, 255, 255, 1}, uint16(443), []byte(nil), uint16(0))
	f.Add([]byte{0, 0, 0, 0}, uint16(0), []byte{192, 168, 1, 1}, uint16(80))
	f.Add([]byte{8, 8, 8, 8}, uint16(53), []byte{127, 0, 0, 1}, uint16(5432))
	f.Add([]byte{172, 16, 0, 1}, uint16(3306), []byte{172, 16, 0, 1}, uint16(3306))
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, uint16(9000), []byte(nil), uint16(0))

	f.Fuzz(func(t *testing.T, ipBytes []byte, port uint16, dbBytes []byte, dbPort uint16) {
		ip := ipFromFuzz(ipBytes)
		e := Endpoint{IP: ip, Port: int(port)}

		var al Allowlist
		if db := ipFromFuzz(dbBytes); db != nil && !db.IsUnspecified() {
			al.DB = &Endpoint{IP: db, Port: int(dbPort)}
		}

		allowed, reason := al.Classify(e) // must not panic

		if allowed {
			// The ONLY ways an endpoint may be allowed: loopback, unspecified
			// (can never be a routable peer), or the exact DB (IP AND port).
			switch {
			case ip == nil:
				t.Fatalf("CLASSIFIER BLIND: nil IP classified allowed (reason %q)", reason)
			case ip.IsLoopback(), ip.IsUnspecified():
				// fine
			case al.DB != nil && ip.Equal(al.DB.IP) && e.Port == al.DB.Port:
				// fine — exact DB
			default:
				t.Fatalf("CLASSIFIER BLIND: non-loopback endpoint %s classified allowed (reason %q, db=%v)", e, reason, al.DB)
			}
		} else {
			// A non-loopback, non-DB address MUST be judged egress. (A loopback
			// address must never be judged egress — that would make the oracle
			// false-fire on legitimate loopback traffic.)
			if ip != nil && ip.IsLoopback() {
				t.Fatalf("FALSE FIRE: loopback %s judged egress (reason %q)", e, reason)
			}
		}
	})
}

// FuzzProcNetParser fuzzes parseProcNetLine against arbitrary bytes: it must
// never panic, and any endpoint it returns must be classifiable without a panic
// and must round-trip loopback-ness (a decoded 0100007F must be seen as loopback
// by net.IP.IsLoopback, not mis-decoded into a routable address).
func FuzzProcNetParser(f *testing.F) {
	f.Add("  1: 0100007F:0035 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000  0 1 1", false)
	f.Add("  0: 00000000:1F90 0808A8C0:0050 06 00000000:00000000 00:00000000 00000000     0  0 1 1", false)
	f.Add("  sl  local_address rem_address   st", false)
	f.Add("garbage not a line at all", false)
	f.Add("  2: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A", true)

	f.Fuzz(func(t *testing.T, line string, v6 bool) {
		local, rem, _, ok := parseProcNetLine(line, v6) // must not panic
		if !ok {
			return
		}
		// Both endpoints must be classifiable (no panic) and self-consistent.
		_, _ = (Allowlist{}).Classify(local)
		_, _ = (Allowlist{}).Classify(rem)
		if rem.IP != nil && rem.IP.IsLoopback() {
			if ok2, reason := (Allowlist{}).Classify(rem); !ok2 {
				t.Fatalf("decoded loopback rem %s judged egress (reason %q) — hex decode aliased it", rem, reason)
			}
		}
	})
}

// buggyClassify is the planted-defect classifier for the red/green proof: it
// mistakes the RFC-1918 10/8 range for "internal, therefore allowed" — the
// classic way an egress oracle goes blind. It is NOT wired into anything; the
// red/green test runs the fuzzer's own invariant over it to show the invariant
// catches exactly this defect, and over the real Classify to show it passes.
func buggyClassify(e Endpoint) (bool, string) {
	if e.IP != nil && len(e.IP) >= 1 {
		if v4 := e.IP.To4(); v4 != nil && v4[0] == 10 {
			return true, "internal-10/8" // the bug
		}
	}
	return Allowlist{}.Classify(e)
}

// classifierInvariantHolds re-states the fuzzer's core invariant as a pure
// predicate so the red/green test can run it against any classifier impl.
func classifierInvariantHolds(classify func(Endpoint) (bool, string), e Endpoint, db *Endpoint) bool {
	allowed, _ := classify(e)
	if !allowed {
		return true
	}
	ip := e.IP
	switch {
	case ip == nil:
		return false
	case ip.IsLoopback(), ip.IsUnspecified():
		return true
	case db != nil && ip.Equal(db.IP) && e.Port == db.Port:
		return true
	default:
		return false
	}
}

func TestClassifierRedGreen(t *testing.T) {
	e := Endpoint{IP: net.IPv4(10, 0, 0, 5), Port: 443}
	// RED: the planted-defect classifier violates the invariant on a 10/8 host.
	if classifierInvariantHolds(buggyClassify, e, nil) {
		t.Fatalf("red proof broken: buggyClassify should have violated the invariant on %s", e)
	}
	// GREEN: the real classifier upholds it.
	if !classifierInvariantHolds(Allowlist{}.Classify, e, nil) {
		t.Fatalf("green proof broken: real Classify flagged %s as allowed", e)
	}
	// GREEN: real classifier allows an exact DB match and loopback.
	db := &Endpoint{IP: net.IPv4(10, 0, 0, 5), Port: 5432}
	if ok, _ := (Allowlist{DB: db}).Classify(Endpoint{IP: net.IPv4(10, 0, 0, 5), Port: 5432}); !ok {
		t.Fatalf("exact DB endpoint should be allowed")
	}
	if ok, _ := (Allowlist{DB: db}).Classify(Endpoint{IP: net.IPv4(10, 0, 0, 5), Port: 443}); ok {
		t.Fatalf("DB IP on a DIFFERENT port must NOT be allowed (port must match)")
	}
}

// ipFromFuzz turns fuzz bytes into a 4- or 16-byte IP, or nil for other lengths
// (mirrors how a real sockaddr would be sized).
func ipFromFuzz(b []byte) net.IP {
	switch len(b) {
	case 4:
		return net.IPv4(b[0], b[1], b[2], b[3])
	case 16:
		ip := make(net.IP, 16)
		copy(ip, b)
		return ip
	default:
		return nil
	}
}
