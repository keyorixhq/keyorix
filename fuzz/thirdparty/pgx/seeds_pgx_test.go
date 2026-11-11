package pgxfuzz

import "encoding/binary"

// This file builds the seed corpus in the buildScript encoding (see
// hostile_pgx_test.go). Seeds are valid protocol exchanges plus known-bad
// shapes; go test -fuzz mutates outward from them.

// encMsg encodes one framed backend message with no extra declared length
// (claim index 0): op=0x00, type, uint16 payload length, payload.
func encMsg(typ byte, payload []byte) []byte {
	op := []byte{0x00, typ}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	return append(append(op, l[:]...), payload...)
}

// encMsgClaim is like encMsg but selects a claim index 0..7 so the server
// declares more body bytes than it sends (truncation / allocation pressure).
func encMsgClaim(typ byte, payload []byte, claimIdx byte) []byte {
	op := []byte{(claimIdx << 2) & 0x1c, typ}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	return append(append(op, l[:]...), payload...)
}

// encRaw encodes unframed raw bytes (action 1): op=0x01, uint16 length, bytes.
func encRaw(b []byte) []byte {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(b)))
	return append(append([]byte{0x01}, l[:]...), b...)
}

// encClose encodes a stop/close action.
func encClose() []byte { return []byte{0x02} }

// authPayload builds an Authentication message body: int32 subtype + extra.
func authPayload(subtype int32, extra ...byte) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(subtype))
	return append(b, extra...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// paramStatus is a ParameterStatus body: name\0 value\0.
func paramStatus(name, value string) []byte {
	return append(append(append([]byte(name), 0), []byte(value)...), 0)
}

// backendKeyData is 8 bytes: int32 pid, int32 secret.
func backendKeyData() []byte { return []byte{0, 0, 0, 1, 0, 0, 0, 2} }

// readyForQuery body is a single status byte.
func readyForQuery() []byte { return []byte{'I'} }

// errorResponse builds an ErrorResponse/NoticeResponse body: a series of
// (fieldcode, string\0) pairs terminated by a zero byte.
func errorResponse(fields map[byte]string) []byte {
	var out []byte
	for code, val := range fields {
		out = append(out, code)
		out = append(out, []byte(val)...)
		out = append(out, 0)
	}
	return append(out, 0)
}

func pgxSeeds() [][]byte {
	okHandshake := cat(
		encMsg('R', authPayload(0)), // AuthenticationOk
		encMsg('S', paramStatus("server_version", "16.0")),
		encMsg('S', paramStatus("client_encoding", "UTF8")),
		encMsg('K', backendKeyData()),
		encMsg('Z', readyForQuery()),
		encClose(),
	)

	cleartext := cat(
		encMsg('R', authPayload(3)), // AuthenticationCleartextPassword
		encMsg('R', authPayload(0)),
		encMsg('Z', readyForQuery()),
		encClose(),
	)

	md5 := cat(
		encMsg('R', authPayload(5, 0xDE, 0xAD, 0xBE, 0xEF)), // MD5 + 4-byte salt
		encMsg('R', authPayload(0)),
		encMsg('Z', readyForQuery()),
		encClose(),
	)

	sasl := cat(
		encMsg('R', authPayload(10, []byte("SCRAM-SHA-256\x00\x00")...)), // AuthenticationSASL
		// A SCRAM server-first-ish message (r=nonce,s=salt,i=iterations).
		encMsg('R', authPayload(11, []byte("r=abcdef0123456789,s=QSXCR+Q6sek8bf92,i=4096")...)),
		encClose(),
	)

	errResp := cat(
		encMsg('E', errorResponse(map[byte]string{
			'S': "FATAL", 'C': "28000", 'M': "password authentication failed",
		})),
		encClose(),
	)

	noticeThenOK := cat(
		encMsg('N', errorResponse(map[byte]string{'S': "NOTICE", 'M': "hi there"})),
		encMsg('R', authPayload(0)),
		encMsg('Z', readyForQuery()),
		encClose(),
	)

	return [][]byte{
		okHandshake,
		cleartext,
		md5,
		sasl,
		errResp,
		noticeThenOK,
		// known-bad: huge declared body, tiny payload (truncation + allocation).
		cat(encMsgClaim('D', []byte{0x00, 0x01, 0xff}, 7), encClose()),
		// known-bad: message length field < 4 (invalid message length).
		encRaw([]byte{'R', 0x00, 0x00, 0x00, 0x02}),
		// known-bad: raw garbage.
		encRaw([]byte{0xff, 0xfe, 0x00, 'x', 'y', 'z', 0x01, 0x02, 0x03}),
		// known-bad: bare AuthenticationOk then immediate close (no ReadyForQuery).
		cat(encMsg('R', authPayload(0)), encClose()),
		// empty.
		{},
	}
}
