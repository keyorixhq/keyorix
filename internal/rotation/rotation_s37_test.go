// rotation_s37_test.go — coverage for the concrete adapter types that sit behind
// the interface seams: pgxConn, mongoClientConn, redisClientConn, gcpIAMClient.
// All existing rotation tests inject fakes via newConn/newClient hooks; the
// concrete structs live at 0%.  This file uses fake wire-protocol servers and an
// httptest.Server to exercise the real adapters end-to-end.
package rotation

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/redis/go-redis/v9"
	iamv1 "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	mongoDriver "go.mongodb.org/mongo-driver/mongo"
	mongoOpts "go.mongodb.org/mongo-driver/mongo/options"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Fake PostgreSQL server ───────────────────────────────────────────────────
//
// pgx.Connect performs an actual TCP handshake (SSLRequest → 'N' → StartupMessage
// → AuthenticationOk + BackendKeyData + ReadyForQuery).  Simple-query DDL then
// follows (Query → CommandComplete + ReadyForQuery).  Terminate closes the conn.

func startFakePGServer_S37(t *testing.T) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakePGConn_S37(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

func handleFakePGConn_S37(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	be := pgproto3.NewBackend(conn, conn)

	// Startup loop: handle optional SSLRequest before the real StartupMessage.
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.SSLRequest:
			if _, err := conn.Write([]byte("N")); err != nil {
				return
			}
		case *pgproto3.StartupMessage:
			be.Send(&pgproto3.AuthenticationOk{})
			be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
			goto messageLoop
		default:
			return
		}
	}

messageLoop:
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.Query:
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("DO")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

// TestPGXConn_S37_ExecAndClose exercises pgxConn.Exec and pgxConn.Close via a
// fake PostgreSQL server.  pgxConn wraps a *pgx.Conn and is only instantiated
// by the real conn() path; existing tests always inject a pgConn fake.
func TestPGXConn_S37_ExecAndClose(t *testing.T) {
	host, port := startFakePGServer_S37(t)
	dsn := fmt.Sprintf(
		"host=%s port=%s user=admin dbname=testdb sslmode=disable connect_timeout=5",
		host, port,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)

	c := &pgxConn{c: raw}
	require.NoError(t, c.Exec(ctx, "SELECT 1"))
	c.Close(ctx) // returns nothing; must not panic
}

// ─── Fake MongoDB OP_MSG server ───────────────────────────────────────────────
//
// The MongoDB Go driver uses OP_MSG (opCode 2013).  Wire header: 16 bytes
// (totalLen, requestID, responseTo, opCode).  Body: uint32 flagBits + section
// (kind=0x00 + BSON document).  We respond with {ok:1} to all commands and
// with a wire-version-17 hello document to the initial handshake.

func s37BsonDouble(key string, val float64) []byte {
	b := []byte{0x01}
	b = append(b, key...)
	b = append(b, 0x00)
	bv := make([]byte, 8)
	binary.LittleEndian.PutUint64(bv, math.Float64bits(val))
	return append(b, bv...)
}

func s37BsonBool(key string, val bool) []byte {
	b := []byte{0x08}
	b = append(b, key...)
	b = append(b, 0x00)
	if val {
		return append(b, 0x01)
	}
	return append(b, 0x00)
}

func s37BsonInt32(key string, val int32) []byte {
	b := []byte{0x10}
	b = append(b, key...)
	b = append(b, 0x00)
	bv := make([]byte, 4)
	binary.LittleEndian.PutUint32(bv, uint32(val))
	return append(b, bv...)
}

func s37BsonString(key, val string) []byte {
	b := []byte{0x02}
	b = append(b, key...)
	b = append(b, 0x00)
	bv := make([]byte, 4)
	binary.LittleEndian.PutUint32(bv, uint32(len(val)+1))
	b = append(b, bv...)
	b = append(b, val...)
	return append(b, 0x00)
}

func s37BsonDoc(elems ...[]byte) []byte {
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	total := 4 + len(body) + 1
	doc := make([]byte, 4)
	binary.LittleEndian.PutUint32(doc, uint32(total))
	doc = append(doc, body...)
	return append(doc, 0x00)
}

func s37BsonDocOK() []byte { return s37BsonDoc(s37BsonDouble("ok", 1.0)) }

func s37BsonDocHello() []byte {
	return s37BsonDoc(
		s37BsonBool("ismaster", true),
		s37BsonBool("isWritablePrimary", true),
		s37BsonInt32("minWireVersion", 0),
		s37BsonInt32("maxWireVersion", 17),
		s37BsonInt32("maxBsonObjectSize", 16*1024*1024),
		s37BsonInt32("maxMessageSizeBytes", 48*1024*1024),
		s37BsonInt32("maxWriteBatchSize", 100000),
		s37BsonString("me", "127.0.0.1:27017"),
		s37BsonDouble("ok", 1.0),
	)
}

func s37WriteOPMsg(conn net.Conn, responseTo int32, bsonBody []byte) error {
	msgBody := append([]byte{0x00, 0x00, 0x00, 0x00, 0x00}, bsonBody...) // flagBits + kind=0
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(16+len(msgBody)))
	binary.LittleEndian.PutUint32(hdr[4:8], 1)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(hdr[12:16], 2013) // OP_MSG
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(msgBody)
	return err
}

func s37IsHelloCmd(body []byte) bool {
	s := string(body)
	for _, kw := range []string{"hello", "isMaster", "ismaster", "topologyVersion"} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func handleFakeMongoConn_S37(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		totalLen := int(binary.LittleEndian.Uint32(hdr[0:4]))
		requestID := int32(binary.LittleEndian.Uint32(hdr[4:8]))
		bodyLen := totalLen - 16
		var body []byte
		if bodyLen > 0 {
			body = make([]byte, bodyLen)
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
		}
		var resp []byte
		if s37IsHelloCmd(body) {
			resp = s37BsonDocHello()
		} else {
			resp = s37BsonDocOK()
		}
		if err := s37WriteOPMsg(conn, requestID, resp); err != nil {
			return
		}
	}
}

func startFakeMongoServer_S37(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeMongoConn_S37(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return fmt.Sprintf(
		"mongodb://127.0.0.1:%s/admin?directConnection=true&serverSelectionTimeoutMS=5000",
		port,
	)
}

// TestMongoClientConn_S37_UpdateUserPassword exercises mongoClientConn.UpdateUserPassword
// via the fake OP_MSG server.  The driver sends an updateUser command; the fake
// server returns {ok:1}.
func TestMongoClientConn_S37_UpdateUserPassword(t *testing.T) {
	uri := startFakeMongoServer_S37(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := mongoDriver.Connect(ctx, mongoOpts.Client().ApplyURI(uri))
	require.NoError(t, err)

	c := &mongoClientConn{client: client}
	defer c.Close(ctx)

	require.NoError(t, c.UpdateUserPassword(ctx, "admin", "new-pass"))
}

// TestMongoClientConn_S37_Close exercises mongoClientConn.Close.  mongo.Connect
// is lazy (no TCP dial until the first operation), so Disconnect on an idle
// client succeeds without a live server.
func TestMongoClientConn_S37_Close(t *testing.T) {
	client, err := mongoDriver.Connect(
		context.Background(),
		mongoOpts.Client().ApplyURI(
			"mongodb://127.0.0.1:1/test?serverSelectionTimeoutMS=100&connectTimeoutMS=100",
		),
	)
	require.NoError(t, err) // Connect returns immediately (lazy)
	c := &mongoClientConn{client: client}
	c.Close(context.Background()) // Disconnect cleans up the empty pool
}

// ─── Fake Redis RESP2 server ──────────────────────────────────────────────────
//
// With Protocol:2, go-redis v9 skips the HELLO handshake.  The client sends the
// actual ACL SETUSER command (and possibly CLIENT SETNAME / PING) directly.
// Our fake answers +PONG to PING and +OK to everything else.

func startFakeRedisServer_S37(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeRedisConn_S37(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func handleFakeRedisConn_S37(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	rd := bufio.NewReader(conn)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '*' {
			continue
		}
		var count int
		fmt.Sscanf(line[1:], "%d", &count)

		args := make([]string, 0, count)
		for i := 0; i < count; i++ {
			if _, err := rd.ReadString('\n'); err != nil { // $N\r\n
				return
			}
			val, err := rd.ReadString('\n') // value\r\n
			if err != nil {
				return
			}
			args = append(args, strings.TrimSpace(val))
		}

		var reply string
		if len(args) == 0 {
			reply = "+OK\r\n"
		} else {
			switch strings.ToUpper(args[0]) {
			case "PING":
				reply = "+PONG\r\n"
			case "HELLO":
				// Respond with a Redis error so go-redis falls back to RESP2.
				// A "+OK" here can't be parsed as the RESP3 Map that HELLO normally
				// returns, causing "can't parse map reply" from the client.
				reply = "-ERR unknown command 'HELLO'\r\n"
			default:
				reply = "+OK\r\n"
			}
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

// TestRedisClientConn_S37_SetUserPassword exercises redisClientConn.SetUserPassword
// via the minimal RESP2 fake server.
func TestRedisClientConn_S37_SetUserPassword(t *testing.T) {
	addr := startFakeRedisServer_S37(t)
	c := &redisClientConn{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Protocol: 2, // RESP2: no HELLO handshake, simpler fake server
		}),
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, c.SetUserPassword(ctx, "alice", "s3cret"))
}

// TestRedisClientConn_S37_Close exercises redisClientConn.Close.  redis.NewClient
// does not dial eagerly; Close just shuts down the connection pool and always
// succeeds regardless of whether a server is listening.
func TestRedisClientConn_S37_Close(t *testing.T) {
	c := &redisClientConn{
		client: redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}),
	}
	require.NoError(t, c.Close())
}

// ─── Fake GCP IAM HTTP server ─────────────────────────────────────────────────
//
// gcpIAMClient makes HTTP calls to the IAM v1 REST API.  With
// option.WithEndpoint the SDK directs all requests at our httptest.Server.
// Three operations are covered:
//   GET  v1/{saName}/keys              → list user-managed keys
//   POST v1/{saName}/keys              → create a new key
//   DELETE v1/{saName}/keys/{keyName}  → delete a key

func startFakeIAMServer_S37(t *testing.T, saName string) *httptest.Server {
	t.Helper()
	rawJSON := `{"type":"service_account","project_id":"test-proj"}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]string{
					{"name": saName + "/keys/old-key", "keyType": "USER_MANAGED"},
				},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/keys"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":           saName + "/keys/new-key",
				"privateKeyData": base64.StdEncoding.EncodeToString([]byte(rawJSON)),
			})
		case r.Method == http.MethodDelete:
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			http.Error(w, `{"error":{"code":404}}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// TestGCPIAMClient_S37_AllMethods exercises gcpIAMClient.ListKeyNames,
// CreateKey, and DeleteKey against a local httptest.Server.  gcpIAMClient is
// the concrete adapter behind the gcpKeyAPI seam; existing tests inject a fake.
func TestGCPIAMClient_S37_AllMethods(t *testing.T) {
	saName := "projects/-/serviceAccounts/sa@test-proj.iam.gserviceaccount.com"
	ts := startFakeIAMServer_S37(t, saName)

	svc, err := iamv1.NewService(
		context.Background(),
		option.WithEndpoint(ts.URL+"/"),
		option.WithoutAuthentication(),
	)
	require.NoError(t, err)

	cl := &gcpIAMClient{svc: svc}
	ctx := context.Background()

	// ListKeyNames
	keys, err := cl.ListKeyNames(ctx, saName)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, saName+"/keys/old-key", keys[0])

	// CreateKey
	keyName, keyJSON, err := cl.CreateKey(ctx, saName)
	require.NoError(t, err)
	assert.Equal(t, saName+"/keys/new-key", keyName)
	assert.Contains(t, keyJSON, "service_account")

	// DeleteKey
	require.NoError(t, cl.DeleteKey(ctx, saName+"/keys/old-key"))
}
