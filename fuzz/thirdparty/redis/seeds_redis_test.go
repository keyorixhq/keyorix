package redisfuzz

// RESP3 reply builders, the host-safety length clamp, and the seed corpus for
// FuzzRedisReply. The byte layout matches redis/go-redis/v9 internal/proto
// reader.go (traced 2026-11-12). The fuzz input IS the raw reply byte stream the
// fake server sends as the answer to the client's command; the client's real
// internal/proto.Reader parses it.

const (
	canaryPassword = "s3cr3t-canary-pw-9f3a2b1c"
	canaryUser     = "canaryuser"
	// markerCmd is a command name the go-redis handshake never issues, so the
	// fake server can tell the client's actual Do() apart from the HELLO/AUTH
	// pre-amble and stream the fuzz bytes only as the reply to Do().
	markerCmd = "FUZZREPLY"
)

// maxRESPLen caps any length/count field the fuzzer injects, so a hostile header
// cannot drive a multi-GB allocation or (via nesting) a stack overflow on this
// shared host. go-redis's real behaviour above this cap is characterised in
// dedicated tests, not exercised in the loop.
const maxRESPLen = 4096

// maxReplyBytes truncates the fuzz reply stream. With the depth of a nested
// aggregate bounded by the byte length (each "*1\r\n" level is 4 bytes), a 32 KiB
// cap keeps recursion well below Go's default 1 GiB max stack so the fuzzer
// itself cannot crash the host; TestRedis_NestedRecursion_Characterise probes
// the unbounded-recursion behaviour under a deliberately lowered max stack.
const maxReplyBytes = 32 << 10

// clampRESP lowers every run of ASCII digits whose value exceeds maxRESPLen to
// maxRESPLen, in place. It is deliberately conservative — it clamps numbers
// anywhere, including inside bulk-string content (harmless over-clamp), because
// a length prefix can appear mid-stream and under-clamping a real length is the
// only unsafe direction (h1 run 3). Nil markers ("-1") and small counts pass
// through unchanged, so RESP3 nesting and the truncation oracle are unaffected.
func clampRESP(in []byte) []byte {
	out := append([]byte(nil), in...)
	if len(out) > maxReplyBytes {
		out = out[:maxReplyBytes]
	}
	for i := 0; i < len(out); {
		if out[i] < '0' || out[i] > '9' {
			i++
			continue
		}
		j := i
		var v int
		over := false
		for j < len(out) && out[j] >= '0' && out[j] <= '9' {
			if !over {
				v = v*10 + int(out[j]-'0')
				if v > maxRESPLen {
					over = true
				}
			}
			j++
		}
		if over {
			// Rewrite the digit run to the cap (left-padded with the cap's
			// digits, remaining positions set to '0' so the byte length and the
			// surrounding CRLF framing are preserved).
			capStr := []byte("4096")
			k := i
			for ; k < i+len(capStr) && k < j; k++ {
				out[k] = capStr[k-i]
			}
			for ; k < j; k++ {
				out[k] = '0'
			}
		}
		i = j
	}
	return out
}

// --- RESP builders (used by seeds and oracle tests) ---

func respStatus(s string) []byte    { return []byte("+" + s + "\r\n") }
func respError(s string) []byte     { return []byte("-" + s + "\r\n") }
func respInt(n int) []byte          { return []byte(itoa(":", n)) }
func respNull() []byte              { return []byte("_\r\n") }
func respDouble(s string) []byte    { return []byte("," + s + "\r\n") }
func respBool(b bool) []byte {
	if b {
		return []byte("#t\r\n")
	}
	return []byte("#f\r\n")
}
func respBigInt(s string) []byte { return []byte("(" + s + "\r\n") }

func respBulk(s string) []byte {
	return []byte(itoa("$", len(s)) + s + "\r\n")
}
func respVerbatim(format, s string) []byte {
	body := format + ":" + s
	return []byte(itoa("=", len(body)) + body + "\r\n")
}
func respBlobErr(s string) []byte {
	return []byte(itoa("!", len(s)) + s + "\r\n")
}

// respAgg builds an aggregate header (type byte + count + CRLF). Caller appends
// the elements.
func respAgg(typ byte, count int) []byte {
	return []byte(itoa(string(typ), count))
}

func itoa(prefix string, n int) string {
	return prefix + intToString(n) + "\r\n"
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// nestedArray builds `*1\r\n` repeated depth times, then a terminal int.
func nestedArray(depth int) []byte {
	var out []byte
	for i := 0; i < depth; i++ {
		out = append(out, respAgg('*', 1)...)
	}
	out = append(out, respInt(1)...)
	return out
}

// redisSeeds builds the seed corpus: valid replies of every RESP3 type plus
// known-interesting shapes. The fuzz input is the reply byte stream verbatim.
func redisSeeds() [][]byte {
	return [][]byte{
		respStatus("OK"),
		respStatus("PONG"),
		respError("ERR unknown command"),
		respInt(12345),
		respNull(),
		respDouble("3.14"),
		respDouble("inf"),
		respBool(true),
		respBool(false),
		respBigInt("1234567890123456789012345"),
		respBulk("hello world"),
		respVerbatim("txt", "some text"),
		respBlobErr("SYNTAX invalid"),
		// array of mixed scalars
		cat(respAgg('*', 3), respInt(1), respBulk("two"), respStatus("three")),
		// set
		cat(respAgg('~', 2), respBulk("a"), respBulk("b")),
		// map
		cat(respAgg('%', 2), respBulk("k1"), respInt(1), respBulk("k2"), respInt(2)),
		// push message
		cat(respAgg('>', 3), respBulk("pubsub"), respBulk("message"), respBulk("payload")),
		// attribute followed by a reply (RESP3)
		cat(respAgg('|', 1), respBulk("ttl"), respInt(60), respStatus("OK")),
		// nested array (shallow — deep nesting is characterised, not seeded)
		nestedArray(8),
		// nil array
		[]byte("*-1\r\n"),
		// nil bulk
		[]byte("$-1\r\n"),
		// empty array
		respAgg('*', 0),
		// bulk declaring more than it sends (truncation shape)
		[]byte("$100\r\nshort"),
		// empty
		{},
	}
}
