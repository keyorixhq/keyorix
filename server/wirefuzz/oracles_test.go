package wirefuzz

// oracles_test.go holds the oracle predicates and the response-capture plumbing every
// wire target shares, so each guard exists once and each is watched failing in
// oracle_redproof_test.go / anti_vacuity_test.go.
//
// HARNESS RULE (the root of review finding F1): a driver must NOT half-close the socket
// (FIN) before it has read the response. net/http and grpc-go treat that EOF as "the
// client went away" and cancel the request/stream context; the auth middleware's DB
// lookup then fails, isTransientValidationError (server/middleware/auth.go) classifies
// it as transient, and EVERY request carrying a token gets a fail-closed 503. That is
// correct production behaviour, but it means a driver that half-closes can never see an
// authorized response, so the authz/leak oracle would be structurally dead. Drivers
// therefore write, keep the connection open, read until the response is complete (or a
// short idle deadline), and only then close.

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net"
	"runtime"
	"slices"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// wireAllocCap bounds the per-input heap-alloc delta on every target (coarse, generous).
const wireAllocCap = 512 << 20

// evalAlloc is the shared allocation oracle: "" when the delta is within wireAllocCap.
func evalAlloc(delta uint64) string {
	if delta > wireAllocCap {
		return fmt.Sprintf("UNBOUNDED ALLOC: heap grew %d bytes (cap %d)", delta, uint64(wireAllocCap))
	}
	return ""
}

// measureAlloc runs fn between two MemStats reads (after a GC) and returns the
// heap-allocation delta, the same measurement every fuzz body uses.
func measureAlloc(fn func()) uint64 {
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	fn()
	runtime.ReadMemStats(&m1)
	return heapDelta(m0, m1)
}

// evalLeak is the authz/leak predicate for ONE response unit (one HTTP/1 response, or
// one HTTP/2 stream): a seeded secret's plaintext may appear only if the credential
// that unit's request carried is authorized to read it. valB (projB) requires admin;
// valA (projA) requires admin or the projA-scoped reader.
func evalLeak(resp []byte, cred credsSent, valA, valB string) string {
	if bytes.Contains(resp, []byte(valB)) && !cred.admin {
		return "LEAK: secret B plaintext in response without the admin credential on that request"
	}
	if bytes.Contains(resp, []byte(valA)) && !cred.admin && !cred.reader {
		return "LEAK: secret A plaintext in response without an authorizing credential on that request"
	}
	return ""
}

// credFromPrincipal maps the recorder's resolved principal label to the credential class.
func credFromPrincipal(principal string) credsSent {
	switch principal {
	case adminUser:
		return credsSent{admin: true}
	case readerUser:
		return credsSent{reader: true}
	}
	return credsSent{}
}

// credsSent records which seeded credential class a request carried.
type credsSent struct {
	admin  bool
	reader bool
}

// h2Result is what an HTTP/2 exchange returned, attributed per stream so the leak
// oracle judges each stream against the credential sent on THAT stream's HEADERS (not
// against "some stream on this connection had an admin token", review finding F2).
type h2Result struct {
	streams map[uint32][]byte    // DATA payload + decoded header fields per stream; 0 = connection level
	creds   map[uint32]credsSent // credential sent on each stream's HEADERS
}

func newH2Result() *h2Result {
	return &h2Result{streams: map[uint32][]byte{}, creds: map[uint32]credsSent{}}
}

func (r *h2Result) add(id uint32, b []byte) { r.streams[id] = append(r.streams[id], b...) }

// all returns every captured byte in stream order (for logs and positive controls).
func (r *h2Result) all() []byte {
	ids := slices.Sorted(maps.Keys(r.streams))
	var out []byte
	for _, id := range ids {
		out = append(out, r.streams[id]...)
	}
	return out
}

// evalH2Leak applies evalLeak to every stream with that stream's own credential.
func evalH2Leak(r *h2Result, valA, valB string) string {
	for id, b := range r.streams {
		if v := evalLeak(b, r.creds[id], valA, valB); v != "" {
			return fmt.Sprintf("%s (stream %d)", v, id)
		}
	}
	return ""
}

// h2ReadIdle bounds how long readH2 waits for the next frame while at least one
// stream we opened is unanswered; h2ReadIdleNoStream applies when we opened none.
const (
	h2ReadIdle         = 1500 * time.Millisecond
	h2ReadIdleNoStream = 300 * time.Millisecond
)

// newH2Framer builds a Framer that decodes the server's header blocks, so response
// header fields (":status", "grpc-status") are visible to the oracles and probes.
func newH2Framer(conn net.Conn) *http2.Framer {
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	return fr
}

// readH2 reads server frames WITHOUT half-closing the connection, attributing DATA and
// decoded header fields to their stream, until every stream in open has ended
// (END_STREAM or RST_STREAM), the server sends GOAWAY, the connection fails, or no
// frame arrives within the idle deadline.
func readH2(conn net.Conn, fr *http2.Framer, open map[uint32]bool, res *h2Result) {
	idle := h2ReadIdleNoStream
	if len(open) > 0 {
		idle = h2ReadIdle
	}
	ended := map[uint32]bool{}
	done := func() bool {
		if len(open) == 0 {
			return false
		}
		for id := range open {
			if !ended[id] {
				return false
			}
		}
		return true
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		f, err := fr.ReadFrame()
		if err != nil {
			if se, ok := errors.AsType[http2.StreamError](err); ok {
				ended[se.StreamID] = true
				if done() {
					return
				}
				continue
			}
			return
		}
		switch fv := f.(type) {
		case *http2.MetaHeadersFrame:
			for _, h := range fv.Fields {
				res.add(fv.StreamID, []byte(h.Name+": "+h.Value+"\n"))
			}
			if fv.StreamEnded() {
				ended[fv.StreamID] = true
			}
		case *http2.DataFrame:
			res.add(fv.StreamID, fv.Data())
			if fv.StreamEnded() {
				ended[fv.StreamID] = true
			}
		case *http2.RSTStreamFrame:
			ended[fv.StreamID] = true
		case *http2.GoAwayFrame:
			res.add(0, fv.DebugData())
			return
		}
		if done() {
			return
		}
	}
}
