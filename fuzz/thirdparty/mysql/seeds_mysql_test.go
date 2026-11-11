package mysqlfuzz

import "encoding/binary"

// This file builds the MySQL seed corpus in the buildScript encoding (see
// hostile_mysql_test.go) plus the raw protocol-packet helpers used by both the
// seeds and the explicit oracle tests. Byte offsets in mysqlHandshake match
// go-sql-driver/mysql@v1.10.1 packets.go readHandshakePacket exactly (traced
// 2026-11-11); a mis-laid field would make the client reject the seed and the
// fuzzer would never reach the post-auth states.

const (
	// Capability flags (go-sql-driver const.go, iota order).
	capClientMySQL      = 0x00000001 // bit 0
	capClientProtocol41 = 0x00000200 // bit 9
	capClientSecureConn = 0x00008000 // bit 15
	capClientPluginAuth = 0x00080000 // bit 19
)

func le16(b []byte, v uint16) []byte {
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], v)
	return append(b, t[:]...)
}

// mysqlHandshake builds a protocol-v10 initial handshake payload (the packet
// body, without the 4-byte frame header) for the given auth plugin and 20-byte
// scramble. Field layout is pinned to the driver's parser offsets.
func mysqlHandshake(plugin string, scramble [20]byte) []byte {
	var p []byte
	p = append(p, 0x0a)                   // protocol version 10
	p = append(p, []byte("8.0.0")...)     // server version
	p = append(p, 0x00)                   // version terminator
	p = append(p, 0x01, 0x00, 0x00, 0x00) // thread id
	p = append(p, scramble[0:8]...)       // auth-plugin-data part 1
	p = append(p, 0x00)                   // filler
	capsLower := uint16(capClientMySQL | capClientProtocol41 | capClientSecureConn)
	p = le16(p, capsLower)                       // capability flags lower
	p = append(p, 0x21)                          // charset (utf8_general_ci)
	p = le16(p, 0x0002)                          // status flags (AUTOCOMMIT)
	p = le16(p, uint16(capClientPluginAuth>>16)) // capability flags upper
	p = append(p, 21)                            // auth-plugin-data length
	p = append(p, make([]byte, 10)...)           // reserved
	p = append(p, scramble[8:20]...)             // auth-plugin-data part 2 (12 bytes)
	p = append(p, 0x00)                          // part-2 terminator (13th byte)
	p = append(p, []byte(plugin)...)             // auth plugin name
	p = append(p, 0x00)
	return p
}

// okPayload is a minimal OK packet body (used for auth-success and COM_PING reply).
func okPayload() []byte {
	return []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
}

// errPayload is a minimal ERR packet body with a server-controlled message.
func errPayload(code uint16, sqlState, msg string) []byte {
	b := []byte{0xff}
	b = le16(b, code)
	b = append(b, '#')
	st := []byte(sqlState)
	for len(st) < 5 {
		st = append(st, '0')
	}
	b = append(b, st[:5]...)
	return append(b, []byte(msg)...)
}

// authSwitchPayload is an AuthSwitchRequest body: 0xfe, plugin\0, auth-data.
func authSwitchPayload(plugin string, data []byte) []byte {
	b := []byte{0xfe}
	b = append(b, []byte(plugin)...)
	b = append(b, 0x00)
	return append(b, data...)
}

// localInfilePayload is a LOCAL INFILE request body: 0xfb, filename.
func localInfilePayload(path string) []byte {
	return append([]byte{0xfb}, []byte(path)...)
}

var fixedScramble = [20]byte{
	1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
}

// --- buildScript encoding helpers (op/seq/len) ---

// encPkt encodes one framed MySQL packet with no extra declared length.
func encPkt(seq byte, payload []byte) []byte {
	out := []byte{0x00, seq} // action 0, claim idx 0
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	return append(append(out, l[:]...), payload...)
}

// encPktClaim is like encPkt but declares extra body bytes (claim idx 0..7).
func encPktClaim(seq byte, payload []byte, claimIdx byte) []byte {
	out := []byte{(claimIdx << 2) & 0x1c, seq}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	return append(append(out, l[:]...), payload...)
}

// encRaw encodes unframed raw bytes.
func encRaw(b []byte) []byte {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(b)))
	return append(append([]byte{0x01}, l[:]...), b...)
}

func encClose() []byte { return []byte{0x02} }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func mysqlSeeds() [][]byte {
	hs := mysqlHandshake("mysql_native_password", fixedScramble)

	// Full valid exchange: handshake(seq0), auth OK(seq2), ping OK(seq1).
	valid := cat(
		encPkt(0, hs),
		encPkt(2, okPayload()),
		encPkt(1, okPayload()),
		encClose(),
	)

	// Handshake then auth failure.
	authFail := cat(
		encPkt(0, hs),
		encPkt(2, errPayload(1045, "28000", "Access denied for user")),
		encClose(),
	)

	// Handshake with auth-switch to mysql_native_password (full 20-byte scramble)
	// then OK. NOTE: a SHORT (<20 byte) scramble here panics the driver
	// (auth.go:310, authData[:20] with no bounds check) — that crashing shape is
	// NOT seeded here so `go test` stays green; it is reproduced deterministically
	// in TestMySQL_AuthSwitchShortScramble_Reproducer.
	authSwitch := cat(
		encPkt(0, hs),
		encPkt(2, authSwitchPayload("mysql_native_password", append(fixedScramble[:], 0))),
		encPkt(4, okPayload()),
		encClose(),
	)

	// Handshake advertising caching_sha2_password.
	sha2 := cat(
		encPkt(0, mysqlHandshake("caching_sha2_password", fixedScramble)),
		encPkt(2, []byte{0x01, 0x03}), // AuthMoreData: fast-auth success
		encPkt(2, okPayload()),
		encClose(),
	)

	// Server immediately returns an ERR instead of a handshake.
	errFirst := cat(
		encPkt(0, errPayload(1040, "08004", "Too many connections")),
		encClose(),
	)

	return [][]byte{
		valid,
		authFail,
		authSwitch,
		sha2,
		errFirst,
		// known-bad: handshake with huge declared body, tiny payload.
		cat(encPktClaim(0, hs[:4], 7), encClose()),
		// known-bad: protocol version too low.
		cat(encPkt(0, append([]byte{0x05}, hs[1:]...)), encClose()),
		// known-bad: raw garbage.
		encRaw([]byte{0xff, 0x00, 0x00, 0x00, 'x', 'y'}),
		// NOTE: a truncated initial handshake (e.g. hs[:12]) PANICS the driver
		// (packets.go:209, data[pos:pos+8] with no bounds check). That crashing
		// shape is intentionally NOT seeded so `go test` stays green; it is
		// reproduced in TestMySQL_ShortHandshake_Reproducer.
		// empty.
		{},
	}
}
