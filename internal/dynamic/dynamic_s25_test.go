package dynamic

// dynamic_s25_test.go – coverage blitz targeting the remaining < 90% functions.
//
// Strategy:
//   - MySQL Issue/Revoke success paths: a minimal fake MySQL wire-protocol TCP
//     server that handles the MySQL handshake (HandshakeV10 → HandshakeResponse →
//     OK) and then responds OK to every subsequent command packet. This lets
//     go-sql-driver/mysql's PingContext succeed and all ExecContext calls return
//     success, without a real MySQL installation.
//   - Postgres Issue: covers the CREATE ROLE failure branch (using the existing
//     startFakePGServerFailOnNthQuery from dynamic_s23_test.go).
//   - MongoDB Issue/Revoke: a minimal MongoDB wire-protocol (OP_MSG) fake server
//     so that connectMongo + Ping + RunCommand paths are exercised.
//   - AWSSTSEngine: additional edge-case branches.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Minimal fake MySQL wire-protocol TCP server
// ═══════════════════════════════════════════════════════════════════════════════
//
// The MySQL client-server protocol (v10) begins with:
//   1. Server → HandshakeV10 packet (capabilities, auth plugin name, etc.)
//   2. Client → HandshakeResponse41
//   3. Server → OK_Packet (0x00)
//
// After auth, every client packet is a command packet. For our purposes:
//   - COM_PING (0x0E) → OK
//   - COM_QUERY (0x03) → OK (no result set; sufficient for ExecContext)
//   - COM_QUIT  (0x01) → close conn
//
// Packet format: 3-byte length (LE) + 1-byte sequence number + payload.
//
// This covers the INSERT/DROP/GRANT/KILL statement paths in Issue and Revoke
// without requiring a live MySQL server.

// writeMySQLPkt sends a MySQL packet with the given sequence number and payload.
func writeMySQLPkt(conn net.Conn, seq uint8, payload []byte) error {
	hdr := make([]byte, 4)
	hdr[0] = byte(len(payload))
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload) >> 16)
	hdr[3] = seq
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// readMySQLPkt reads one MySQL packet and returns (sequence, payload, error).
func readMySQLPkt(conn net.Conn) (uint8, []byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq := hdr[3]
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return seq, payload, nil
}

// mysqlErrPkt returns a MySQL ERR packet with a generic error message.
func mysqlErrPkt(seq uint8) []byte {
	msg := []byte("query failed")
	pkt := make([]byte, 0, 10+len(msg))
	pkt = append(pkt, 0xFF)               // ERR header
	pkt = append(pkt, 0x01, 0x04)         // error code 1025 (LE)
	pkt = append(pkt, '#')                 // SQL state marker
	pkt = append(pkt, []byte("HY000")...) // generic SQL state
	pkt = append(pkt, msg...)
	return pkt
}

// mysqlOKPkt returns a minimal OK packet.
func mysqlOKPkt() []byte {
	return []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
}

// sendMySQLHandshake sends the initial HandshakeV10 and consumes the client response,
// then sends an OK. Returns false on error.
func sendMySQLHandshake(conn net.Conn) bool {
	serverVersion := "8.0.0-fake\x00"
	authData := "12345678" // auth-plugin-data part 1 (8 bytes)
	authData2 := "123456789012\x00"
	pluginName := "mysql_native_password\x00"

	// Capability flags: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
	capsLo := uint16(0x8200 | 0x0004 | 0x0200)
	capsHi := uint16(0x0008) // CLIENT_PLUGIN_AUTH

	hs := make([]byte, 0, 128)
	hs = append(hs, 0x0a)                          // protocol version 10
	hs = append(hs, []byte(serverVersion)...)       // null-terminated server version
	hs = append(hs, 0x01, 0x00, 0x00, 0x00)         // connection id = 1
	hs = append(hs, []byte(authData)...)            // auth-plugin-data part 1 (8 bytes)
	hs = append(hs, 0x00)                           // filler
	hs = append(hs, byte(capsLo), byte(capsLo>>8))  // capability flags lo
	hs = append(hs, 0x21)                           // character set utf8mb4
	hs = append(hs, 0x02, 0x00)                     // status flags
	hs = append(hs, byte(capsHi), byte(capsHi>>8))  // capability flags hi
	hs = append(hs, byte(len(authData)+len(authData2))) // auth-plugin-data-len (20 bytes, padded to 13)
	hs = append(hs, make([]byte, 10)...)            // reserved (10 zeros)
	hs = append(hs, []byte(authData2)...)           // auth-plugin-data part 2
	hs = append(hs, []byte(pluginName)...)           // plugin name

	if err := writeMySQLPkt(conn, 0, hs); err != nil {
		return false
	}
	// Read HandshakeResponse from client.
	if _, _, err := readMySQLPkt(conn); err != nil {
		return false
	}
	// Send OK.
	return writeMySQLPkt(conn, 2, mysqlOKPkt()) == nil
}

// mysqlStmtPrepareOKPkt returns a COM_STMT_PREPARE_OK response for a
// statement with 1 parameter and 0 columns (covers SELECT ... WHERE x = ?).
// Format: 0x00 + stmt_id(4) + num_columns(2) + num_params(2) + reserved(1) + warning_count(2)
// If numParams > 0, we send numParams column-definition packets + EOF.
// If numColumns > 0, we send numColumns column-definition packets + EOF.
func mysqlStmtPrepareOKPkt(stmtID uint32, numParams, numColumns uint16) []byte {
	pkt := make([]byte, 12)
	pkt[0] = 0x00              // OK header
	pkt[1] = byte(stmtID)
	pkt[2] = byte(stmtID >> 8)
	pkt[3] = byte(stmtID >> 16)
	pkt[4] = byte(stmtID >> 24)
	pkt[5] = byte(numColumns)
	pkt[6] = byte(numColumns >> 8)
	pkt[7] = byte(numParams)
	pkt[8] = byte(numParams >> 8)
	pkt[9] = 0x00 // reserved
	pkt[10] = 0x00 // warning_count lo
	pkt[11] = 0x00 // warning_count hi
	return pkt
}

// mysqlColumnDefPkt returns a minimal column definition packet.
func mysqlColumnDefPkt(name string) []byte {
	// Simplified column definition packet (catalog, schema, table, etc. all empty).
	// Enough for the driver to parse: catalog(lenenc "")+schema(lenenc "")+
	// table(lenenc "")+org_table(lenenc "")+name(lenenc name)+org_name(lenenc name)+
	// 0x0c(length of fixed fields)+charset(2)+column_len(4)+type(1)+flags(2)+decimals(1)+filler(2)
	nameBytes := []byte(name)
	pkt := make([]byte, 0, 50)
	pkt = append(pkt, 0x03, 'd', 'e', 'f') // catalog = "def"
	pkt = append(pkt, 0x00)                 // schema (empty lenenc string)
	pkt = append(pkt, 0x00)                 // table (empty lenenc string)
	pkt = append(pkt, 0x00)                 // org_table (empty lenenc string)
	pkt = append(pkt, byte(len(nameBytes))) // name length
	pkt = append(pkt, nameBytes...)         // name
	pkt = append(pkt, 0x00)                 // org_name (empty)
	pkt = append(pkt, 0x0c)                 // length of fixed-length fields
	pkt = append(pkt, 0x3f, 0x00)           // charset (utf8)
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // column length
	pkt = append(pkt, 0x08)                 // type: LONGLONG (8 = int64)
	pkt = append(pkt, 0x00, 0x00)           // flags
	pkt = append(pkt, 0x00)                 // decimals
	pkt = append(pkt, 0x00, 0x00)           // filler
	return pkt
}

// mysqlEOFPkt returns a MySQL EOF packet.
func mysqlEOFPkt() []byte {
	return []byte{0xfe, 0x00, 0x00, 0x02, 0x00} // EOF + 0 warnings + status OK
}

// handleMySQLCommands runs the command loop, responding OK to all commands.
// queryCount is advanced for COM_QUERY; if failAfterQuery >= 0, queries after
// that count return ERR instead of OK.  Pass failAfterQuery = -1 for always-OK.
// COM_STMT_PREPARE returns a stmt prepare OK (1 param, 0 cols for SELECT;
// 0 params 0 cols for everything else).
// COM_STMT_EXECUTE returns OK (empty result set) — the caller parses rows.
// COM_STMT_CLOSE is consumed silently.
func handleMySQLCommands(conn net.Conn, failAfterQuery int) {
	stmtIDCounter := uint32(1)
	queryCount := 0
	var seq uint8
	for {
		_, payload, err := readMySQLPkt(conn)
		if err != nil {
			return
		}
		if len(payload) == 0 {
			continue
		}
		seq = 1
		cmd := payload[0]
		switch cmd {
		case 0x01: // COM_QUIT
			return
		case 0x0e: // COM_PING
			_ = writeMySQLPkt(conn, seq, mysqlOKPkt())

		case 0x03: // COM_QUERY (non-parametrized)
			queryCount++
			if failAfterQuery >= 0 && queryCount > failAfterQuery {
				_ = writeMySQLPkt(conn, seq, mysqlErrPkt(seq))
			} else {
				_ = writeMySQLPkt(conn, seq, mysqlOKPkt())
			}

		case 0x16: // COM_STMT_PREPARE
			// Return a STMT_PREPARE_OK with 1 param and 0 columns.
			// Then send 1 column-definition packet + EOF for the parameter.
			stmtID := stmtIDCounter
			stmtIDCounter++
			_ = writeMySQLPkt(conn, seq, mysqlStmtPrepareOKPkt(stmtID, 1, 0))
			seq++
			// Send 1 param definition (for the ? placeholder).
			_ = writeMySQLPkt(conn, seq, mysqlColumnDefPkt("param0"))
			seq++
			// EOF after param defs.
			_ = writeMySQLPkt(conn, seq, mysqlEOFPkt())

		case 0x17: // COM_STMT_EXECUTE
			queryCount++
			if failAfterQuery >= 0 && queryCount > failAfterQuery {
				_ = writeMySQLPkt(conn, seq, mysqlErrPkt(seq))
			} else {
				// Return an empty result set (0 rows):
				// 1. Column count packet (field_count = 1 for the "id" column)
				// 2. 1 column definition
				// 3. EOF (end of column defs)
				// 4. EOF (end of rows — empty result set)
				_ = writeMySQLPkt(conn, seq, []byte{0x01}) // 1 column
				seq++
				_ = writeMySQLPkt(conn, seq, mysqlColumnDefPkt("id"))
				seq++
				_ = writeMySQLPkt(conn, seq, mysqlEOFPkt())
				seq++
				_ = writeMySQLPkt(conn, seq, mysqlEOFPkt()) // no rows
			}

		case 0x19: // COM_STMT_CLOSE — no response expected
			// do nothing

		default:
			_ = writeMySQLPkt(conn, seq, mysqlOKPkt())
		}
	}
}

// startFakeMySQLServer starts a minimal MySQL-protocol TCP server on a random
// local port.  All queries succeed.  Returns a go-sql-driver/mysql DSN string.
func startFakeMySQLServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				if !sendMySQLHandshake(c) {
					c.Close() //nolint:errcheck
					return
				}
				handleMySQLCommands(c, -1) // -1 = never fail
				c.Close()                  //nolint:errcheck
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return fmt.Sprintf("admin:pass@tcp(127.0.0.1:%s)/testdb", port)
}

// startFakeMySQLServerFailOnNthQuery starts a MySQL server that succeeds on
// the first failAfter COM_QUERY / COM_STMT_EXECUTE packets and returns ERR for
// subsequent ones.
func startFakeMySQLServerFailOnNthQuery(t *testing.T, failAfter int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				if !sendMySQLHandshake(c) {
					c.Close() //nolint:errcheck
					return
				}
				handleMySQLCommands(c, failAfter)
				c.Close() //nolint:errcheck
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return fmt.Sprintf("admin:pass@tcp(127.0.0.1:%s)/testdb", port)
}

// ── MySQL Issue happy paths ───────────────────────────────────────────────────

func TestMySQLEngine_Issue_Success_NoTemplate(t *testing.T) {
	dsn := startFakeMySQLServer(t)
	e := &MySQLEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cred, role, err := e.Issue(ctx, dsn, "", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, role)
	assert.NotEmpty(t, cred.Username)
	assert.NotEmpty(t, cred.Password)
}

func TestMySQLEngine_Issue_Success_WithTemplate(t *testing.T) {
	dsn := startFakeMySQLServer(t)
	e := &MySQLEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cred, role, err := e.Issue(ctx, dsn, "GRANT SELECT ON app.* TO {{name}}", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, role)
	assert.NotEmpty(t, cred.Username)
}

func TestMySQLEngine_Issue_WhitespaceTemplate_Success(t *testing.T) {
	dsn := startFakeMySQLServer(t)
	e := &MySQLEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Whitespace-only template is treated as empty → no GRANT executed.
	cred, role, err := e.Issue(ctx, dsn, "   ", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, role)
	assert.NotEmpty(t, cred.Username)
}

// TestMySQLEngine_Issue_CreateUserFails verifies that if CREATE USER itself
// fails, Issue returns a "create user" error.
func TestMySQLEngine_Issue_CreateUserFails(t *testing.T) {
	// failAfter=0: the very first COM_QUERY (CREATE USER) fails.
	dsn := startFakeMySQLServerFailOnNthQuery(t, 0)
	e := &MySQLEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, dsn, "", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create user")
}

// TestMySQLEngine_Issue_TemplateFails verifies that if CREATE USER succeeds
// but the template GRANT fails, Issue returns a "run creation template" error.
func TestMySQLEngine_Issue_TemplateFails(t *testing.T) {
	// failAfter=1: CREATE USER (query 1) succeeds, GRANT (query 2) fails.
	dsn := startFakeMySQLServerFailOnNthQuery(t, 1)
	e := &MySQLEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, dsn, "GRANT SELECT ON app.* TO {{name}}", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creation template")
}

// ── MySQL Revoke happy path ───────────────────────────────────────────────────

func TestMySQLEngine_Revoke_Success(t *testing.T) {
	dsn := startFakeMySQLServer(t)
	e := &MySQLEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := e.Revoke(ctx, dsn, "kx_dyn_abc123xyz")
	require.NoError(t, err)
}

// TestMySQLEngine_Revoke_DropUserFails verifies that if DROP USER fails,
// Revoke returns a "drop user" error.
// killUserConnections runs a SELECT processlist first (query 1 → OK/empty result),
// then DROP USER (query 2) which fails.
func TestMySQLEngine_Revoke_DropUserFails(t *testing.T) {
	// failAfter=1: processlist SELECT passes, DROP USER fails.
	dsn := startFakeMySQLServerFailOnNthQuery(t, 1)
	e := &MySQLEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := e.Revoke(ctx, dsn, "kx_dyn_abc123xyz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "drop user")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Minimal fake MongoDB wire-protocol TCP server (OP_MSG)
// ═══════════════════════════════════════════════════════════════════════════════
//
// MongoDB 3.6+ uses OP_MSG. The wire-protocol header is 16 bytes:
//   int32 messageLength   (total, including header)
//   int32 requestID
//   int32 responseTo
//   int32 opCode          (2013 = OP_MSG)
//
// OP_MSG body:
//   uint32 flagBits
//   sections: section kind(1 byte=0x00) + BSON document body
//
// The fake server responds with {ok: 1} to every message.

// bsonDouble encodes a BSON element of type Double (0x01).
func bsonDouble(key string, val float64) []byte {
	b := make([]byte, 0, 1+len(key)+1+8)
	b = append(b, 0x01) // type Double
	b = append(b, []byte(key)...)
	b = append(b, 0x00)
	// IEEE 754 LE bytes for val.
	bits := math.Float64bits(val)
	bv := make([]byte, 8)
	binary.LittleEndian.PutUint64(bv, bits)
	b = append(b, bv...)
	return b
}

// bsonBool encodes a BSON element of type Boolean (0x08).
func bsonBool(key string, val bool) []byte {
	b := []byte{0x08}
	b = append(b, []byte(key)...)
	b = append(b, 0x00)
	if val {
		b = append(b, 0x01)
	} else {
		b = append(b, 0x00)
	}
	return b
}

// bsonInt32 encodes a BSON element of type Int32 (0x10).
func bsonInt32(key string, val int32) []byte {
	b := []byte{0x10}
	b = append(b, []byte(key)...)
	b = append(b, 0x00)
	bv := make([]byte, 4)
	binary.LittleEndian.PutUint32(bv, uint32(val))
	b = append(b, bv...)
	return b
}

// bsonString encodes a BSON element of type String (0x02).
func bsonString(key, val string) []byte {
	b := []byte{0x02}
	b = append(b, []byte(key)...)
	b = append(b, 0x00)
	bv := make([]byte, 4)
	binary.LittleEndian.PutUint32(bv, uint32(len(val)+1))
	b = append(b, bv...)
	b = append(b, []byte(val)...)
	b = append(b, 0x00)
	return b
}

// bsonDoc wraps elements into a BSON document (adds int32 totalLen + 0x00 terminator).
func bsonDoc(elems ...[]byte) []byte {
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	totalLen := 4 + len(body) + 1
	doc := make([]byte, 4)
	binary.LittleEndian.PutUint32(doc, uint32(totalLen))
	doc = append(doc, body...)
	doc = append(doc, 0x00)
	return doc
}

// bsonDocOK returns a minimal BSON document encoding {"ok": 1.0}.
func bsonDocOK() []byte {
	return bsonDoc(bsonDouble("ok", 1.0))
}

// bsonDocHello returns a BSON document for the MongoDB `hello` handshake
// response that satisfies the Go driver's wire version check (>= 6).
func bsonDocHello() []byte {
	return bsonDoc(
		bsonBool("ismaster", true),
		bsonBool("isWritablePrimary", true),
		bsonInt32("minWireVersion", 0),
		bsonInt32("maxWireVersion", 17), // MongoDB 6.0+ wire version
		bsonInt32("maxBsonObjectSize", 16*1024*1024),
		bsonInt32("maxMessageSizeBytes", 48*1024*1024),
		bsonInt32("maxWriteBatchSize", 100000),
		bsonString("me", "127.0.0.1:27017"),
		bsonDouble("ok", 1.0),
	)
}

// writeOPMsgWithBody sends an OP_MSG response with the given BSON body.
func writeOPMsgWithBody(conn net.Conn, responseTo int32, bsonBody []byte) error {
	// OP_MSG body: uint32 flagBits(0) + kind(0x00) + BSON body
	msgBody := make([]byte, 0, 5+len(bsonBody))
	msgBody = append(msgBody, 0x00, 0x00, 0x00, 0x00) // flagBits = 0
	msgBody = append(msgBody, 0x00)                   // section kind = 0 (body)
	msgBody = append(msgBody, bsonBody...)

	totalLen := 16 + len(msgBody)
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(hdr[4:8], 1)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(hdr[12:16], 2013) // OP_MSG

	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(msgBody)
	return err
}

// isHelloCommand returns true if the OP_MSG body contains a "hello" or
// "isMaster" command (the first key of the BSON document body section).
// We do a simple search for the key bytes rather than full BSON decoding.
func isHelloCommand(body []byte) bool {
	// body = uint32 flagBits + sections...
	// section kind 0: 0x00 + BSON doc
	// BSON doc = int32(len) + elements + 0x00 terminator
	// First element after the length is: type(1B) + key(cstring) + value
	// We look for the key "hello" or "isMaster" or "ismaster" in the payload.
	bodyStr := string(body)
	return containsAny(bodyStr, "hello", "isMaster", "ismaster", "topologyVersion")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// handleFakeMongoConn handles one MongoDB wire-protocol connection.
// For hello/isMaster commands it returns a proper wire-version response;
// for all other commands it returns {ok: 1}.
func handleFakeMongoConn(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	for {
		// Read 16-byte wire header.
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		totalLen := int(binary.LittleEndian.Uint32(hdr[0:4]))
		requestID := int32(binary.LittleEndian.Uint32(hdr[4:8]))
		bodyLen := totalLen - 16
		if bodyLen < 0 {
			return
		}
		// Read the message body.
		var body []byte
		if bodyLen > 0 {
			body = make([]byte, bodyLen)
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
		}
		// Choose the response based on the command type.
		var respBody []byte
		if isHelloCommand(body) {
			respBody = bsonDocHello()
		} else {
			respBody = bsonDocOK()
		}
		if err := writeOPMsgWithBody(conn, requestID, respBody); err != nil {
			return
		}
	}
}

// startFakeMongoServer starts a minimal MongoDB-wire-protocol server on a
// random local port and returns the connection URI.
func startFakeMongoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeMongoConn(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	// No credentials — avoids SASL auth handshake with the fake server.
	// directConnection=true prevents topology discovery; serverSelectionTimeoutMS
	// keeps the test from hanging if something goes wrong.
	return fmt.Sprintf(
		"mongodb://127.0.0.1:%s/admin?directConnection=true&serverSelectionTimeoutMS=5000",
		port,
	)
}

// ── MongoDB Issue happy path via fake server ─────────────────────────────────

func TestMongoEngine_Issue_Success(t *testing.T) {
	uri := startFakeMongoServer(t)
	e := &MongoEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cred, role, err := e.Issue(ctx, uri, `{"roles": ["readWrite"]}`, time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, role)
	assert.NotEmpty(t, cred.Username)
	assert.NotEmpty(t, cred.Password)
}

func TestMongoEngine_Issue_EmptyTemplate_Success(t *testing.T) {
	uri := startFakeMongoServer(t)
	e := &MongoEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Empty template → empty roles slice, no roles.
	cred, role, err := e.Issue(ctx, uri, "", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, role)
	assert.NotEmpty(t, cred.Username)
}

// ── MongoDB Revoke happy path via fake server ────────────────────────────────

func TestMongoEngine_Revoke_Success(t *testing.T) {
	uri := startFakeMongoServer(t)
	e := &MongoEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := e.Revoke(ctx, uri, "kx_dyn_validname123")
	require.NoError(t, err)
}

// ── Postgres Issue: CREATE ROLE failure (first query fails) ──────────────────
//
// startFakePGServerFailOnNthQuery(t, 0): the very first simple-protocol query
// (CREATE ROLE) returns an error.

func TestPostgresEngine_Issue_CreateRoleFails(t *testing.T) {
	host, port := startFakePGServerFailOnNthQuery(t, 0)
	e := &PostgresEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, fakePGDSN(host, port), "", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create role")
}

// ── AWSSTSEngine additional coverage ─────────────────────────────────────────

// TestAWSSTSEngine_Issue_WithPolicy verifies that a non-empty creationTemplate
// is forwarded as an inline session policy in the AssumeRole request.
func TestAWSSTSEngine_Issue_WithPolicy(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	fake := &fakeSTS{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     aws.String("AKID"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      &exp,
	}}}
	eng := newFakeSTSEngine(fake)
	_, _, err := eng.Issue(context.Background(),
		`{"role_arn":"arn:aws:iam::1:role/r","region":"us-east-1"}`,
		`{"Version":"2012-10-17","Statement":[]}`,
		time.Hour)
	require.NoError(t, err)
	require.NotNil(t, fake.in.Policy)
	assert.Contains(t, *fake.in.Policy, "2012-10-17")
}

// TestAWSSTSEngine_Issue_NoRegion_NoRegionField verifies that when no region
// is in the config, the "region" field is absent from the returned Fields.
func TestAWSSTSEngine_Issue_NoRegion_NoRegionField(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	fake := &fakeSTS{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     aws.String("AKID"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      &exp,
	}}}
	eng := newFakeSTSEngine(fake)
	cred, _, err := eng.Issue(context.Background(),
		`{"role_arn":"arn:aws:iam::1:role/r"}`, "", time.Hour)
	require.NoError(t, err)
	_, hasRegion := cred.Fields["region"]
	assert.False(t, hasRegion, "region field must be absent when not in config")
}

// TestAWSSTSEngine_Issue_NoExpiration_NoExpirationField verifies that when
// the STS response has no Expiration, the "expiration" field is absent.
func TestAWSSTSEngine_Issue_NoExpiration_NoExpirationField(t *testing.T) {
	fake := &fakeSTS{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     aws.String("AKID"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      nil, // no expiry timestamp
	}}}
	eng := newFakeSTSEngine(fake)
	cred, _, err := eng.Issue(context.Background(),
		`{"role_arn":"arn:aws:iam::1:role/r"}`, "", time.Hour)
	require.NoError(t, err)
	_, hasExp := cred.Fields["expiration"]
	assert.False(t, hasExp, "expiration field must be absent when STS returns no expiry")
}

// TestMongoEngine_connectMongo_InvalidURIScheme covers the ApplyURI error
// branch in connectMongo where the URI scheme is not recognized.
func TestMongoEngine_connectMongo_InvalidURIScheme(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := connectMongo(ctx, "http://admin:pass@localhost:27017/admin")
	require.Error(t, err)
}
