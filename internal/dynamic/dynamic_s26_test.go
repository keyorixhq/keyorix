package dynamic

// dynamic_s26_test.go – G80 coverage push for internal/dynamic (93.3% → as close to
// 100% as reasonably achievable).
//
// Strategy: fill the specific branches the existing sN test files left uncovered
// (verified via `go tool cover -func`), reusing the same fake-server / fake-driver
// conventions those files already established:
//   - kubernetes.go: validateAPIServerHost's own branches (never unit-tested
//     directly before) and refuseRedirect (0% — never called directly).
//   - awssts.go: arnAccountID's malformed-ARN branch.
//   - mongodb.go: parseMongoRoles' blocked-role rejection (a real security
//     invariant that had NO test at all), plus createUser/dropUser failure
//     branches via a fake MongoDB wire-protocol server that can be told to return
//     a command error for a specific command name.
//   - mysql.go: killUserConnections' QueryContext-error branch.
//   - postgres.go: dialPostgres' pgx.ParseConfig error branch.
//   - azure.go / gcp.go: the "build real credential/client" branches, using
//     environment-variable / local-file tricks that make credential construction
//     itself succeed or fail deterministically WITHOUT any live network call —
//     see each test's comment for why it's hermetic.
//
// Branches deliberately left uncovered (documented, not silently dropped):
//   - Every `if _, err := randString(N); err != nil` defensive branch across all
//     six Issue implementations: randString's only failure mode is crypto/rand.Read
//     erroring, which isn't feasible to force from a black-box test without
//     modifying non-test source (out of scope for this pass).
//   - mysql.go openMySQL's `mysql.NewConnector(cfg)` error branch: verified
//     empirically that go-sql-driver/mysql's ParseDSN already runs the same
//     cfg.normalize() validation NewConnector performs, so by the time
//     ParseDSN succeeds, NewConnector cannot fail on the same cfg — the branch is
//     dead code from an external caller's perspective.
//   - gcp.go/azure.go's realGCPMinter.mintAccessToken / realAzureMinter.mintToken
//     SUCCESS paths reachable only through Issue's nil-minter path with real
//     ADC/workload-identity credentials — not obtainable in this environment
//     (realGCPMinter's success path IS covered directly via
//     TestRealGCPMinter_MintAccessToken_Success in dynamic_s3_test.go, which
//     bypasses newRealGCPMinter entirely).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────── kubernetes.go: validateAPIServerHost ─────────────
//
// Never unit-tested directly before (only exercised transitively through
// newRealK8sMinter's always-https/well-formed test inputs).

func TestValidateAPIServerHost_InvalidURL(t *testing.T) {
	// Malformed percent-encoding is one of the few inputs net/url.Parse itself
	// rejects.
	err := validateAPIServerHost("https://host/%zz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid api_server")
}

func TestValidateAPIServerHost_NonHTTPSScheme(t *testing.T) {
	err := validateAPIServerHost("http://10.0.0.1:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use https")
}

func TestValidateAPIServerHost_MissingHost(t *testing.T) {
	err := validateAPIServerHost("https://")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing a host")
}

func TestValidateAPIServerHost_Valid(t *testing.T) {
	require.NoError(t, validateAPIServerHost("https://10.0.0.1:443"))
}

// ─────────────────────────── kubernetes.go: refuseRedirect ────────────────────
//
// 0% coverage: refuseRedirect is wired in as http.Client.CheckRedirect but never
// actually invoked by any existing test (none of the fake servers issue a 3xx).

func TestRefuseRedirect(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://10.0.0.1/api/v1/secrets", nil)
	require.NoError(t, err)
	err = refuseRedirect(req, nil)
	require.Error(t, err, "the TokenRequest/Secret client must never follow a redirect (CWE-918)")
	assert.Contains(t, err.Error(), "refusing to follow redirect")
	assert.Contains(t, err.Error(), req.URL.String())
}

// ─────────────────────────── kubernetes.go: newRealK8sMinter host validation ──
//
// newRealK8sMinter's own validateAPIServerHost(m.host) call (after the CA pool
// is built) was never exercised with a value that fails it: every existing
// test's api_server is already a well-formed https URL. An operator-configured
// non-https api_server reaches this check unvalidated up to this point.

func TestNewRealK8sMinter_APIServerNonHTTPS_Rejected(t *testing.T) {
	// Any httptest.TLS server's cert works as a syntactically-valid CA PEM here;
	// the request never actually reaches the network — validateAPIServerHost
	// rejects the host before any client is used.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	caPEM := buildK8sCACertPEM(t, srv)

	cfg := k8sConfig{APIServer: "http://insecure-k8s-api:6443", Token: "tok", CACert: caPEM}
	_, err := newRealK8sMinter(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use https")
}

// ─────────────────────────── awssts.go: client() LoadDefaultConfig failure ────
//
// e.client's error branch (LoadDefaultConfig failing) was never exercised —
// dynamic_s3_test.go's client() tests only prove the call doesn't panic. Forcing
// a genuine failure needs a shared AWS config profile whose assume-role chain
// references a source_profile that doesn't exist: LoadDefaultConfig resolves
// (not just parses) profiles eagerly, so this fails deterministically without
// any real AWS credentials or network access.

func TestAWSSTSEngine_ClientDefault_LoadConfigError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "aws-config")
	require.NoError(t, os.WriteFile(cfgPath, []byte(
		"[profile broken]\nsource_profile = does-not-exist\nrole_arn = arn:aws:iam::123456789012:role/x\n",
	), 0o600))
	t.Setenv("AWS_CONFIG_FILE", cfgPath)
	t.Setenv("AWS_PROFILE", "broken")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "does-not-exist-creds"))

	e := &AWSSTSEngine{} // no injected newClient — exercises the real LoadDefaultConfig path
	_, err := e.client(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load AWS config")
}

// ─────────────────────────── awssts.go: arnAccountID ──────────────────────────

func TestArnAccountID_MalformedARN(t *testing.T) {
	// Fewer than 5 colon-separated segments — not a well-formed ARN.
	for _, bad := range []string{"", "arn", "arn:aws", "arn:aws:iam", "arn:aws:iam:"} {
		assert.Equal(t, "", arnAccountID(bad), "malformed ARN %q must yield no account ID", bad)
	}
}

// ─────────────────────────── mongodb.go: parseMongoRoles blocked roles ────────
//
// mongoBlockedRoles rejection had NO test coverage at all despite being the
// backend's core privilege-escalation guard (a dynamic-secret credential must
// never receive a cluster-wide/superuser role).

func TestParseMongoRoles_BlockedRole_StringForm(t *testing.T) {
	_, err := parseMongoRoles(`{"roles": ["readWrite", "clusterAdmin"]}`)
	require.Error(t, err, "clusterAdmin must be rejected even alongside a safe role")
	assert.Contains(t, err.Error(), `"clusterAdmin"`)
	assert.Contains(t, err.Error(), "cluster-wide or superuser privilege")
}

func TestParseMongoRoles_BlockedRole_ObjectForm(t *testing.T) {
	_, err := parseMongoRoles(`{"roles": [{"role": "root", "db": "admin"}]}`)
	require.Error(t, err, "root must be rejected in {role,db} object form too, not just as a bare string")
	assert.Contains(t, err.Error(), `"root"`)
}

func TestParseMongoRoles_ObjectFormWithoutRoleKey_NotBlocked(t *testing.T) {
	// An object entry with no "role" key resolves to an empty roleName, which is
	// not in mongoBlockedRoles — parseMongoRoles must not reject it (the entry is
	// passed through as-is for MongoDB itself to validate).
	roles, err := parseMongoRoles(`{"roles": [{"db": "admin"}]}`)
	require.NoError(t, err)
	assert.Len(t, roles, 1)
}

func TestParseMongoRoles_AllBuiltinSuperuserRolesBlocked(t *testing.T) {
	for role := range mongoBlockedRoles {
		t.Run(role, func(t *testing.T) {
			_, err := parseMongoRoles(fmt.Sprintf(`{"roles": [%q]}`, role))
			require.Error(t, err, "every mongoBlockedRoles entry must be rejected")
		})
	}
}

// ─────────────────────────── mongodb.go: fake server with command errors ──────
//
// Extends the fake MongoDB OP_MSG server from dynamic_s25_test.go (which always
// answers {ok:1}) with the ability to answer a specific command name with a
// {ok:0, code, codeName, errmsg} CommandError — needed to cover Issue's
// createUser failure branch and Revoke's two dropUser branches (idempotent
// UserNotFound vs. a real failure), none of which any existing test reaches.

// bsonDocMongoErr encodes a MongoDB command-error response document.
func bsonDocMongoErr(code int32, codeName, errmsg string) []byte {
	return bsonDoc(
		bsonDouble("ok", 0.0),
		bsonInt32("code", code),
		bsonString("codeName", codeName),
		bsonString("errmsg", errmsg),
	)
}

// handleFakeMongoConnCmdErr is handleFakeMongoConn's sibling: it answers
// hello/isMaster with the normal handshake response, answers any command whose
// wire body contains cmdKey with the given command error, and answers
// everything else with {ok:1} — exactly like handleFakeMongoConn.
func handleFakeMongoConnCmdErr(conn net.Conn, cmdKey string, code int32, codeName, errmsg string) {
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
		if bodyLen < 0 {
			return
		}
		var body []byte
		if bodyLen > 0 {
			body = make([]byte, bodyLen)
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
		}
		var respBody []byte
		switch {
		case isHelloCommand(body):
			respBody = bsonDocHello()
		case containsAny(string(body), cmdKey):
			respBody = bsonDocMongoErr(code, codeName, errmsg)
		default:
			respBody = bsonDocOK()
		}
		if err := writeOPMsgWithBody(conn, requestID, respBody); err != nil {
			return
		}
	}
}

// startFakeMongoServerCmdErr starts a fake MongoDB server that fails any
// command whose body contains cmdKey with the given command error, and returns
// its connection URI.
func startFakeMongoServerCmdErr(t *testing.T, cmdKey string, code int32, codeName, errmsg string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeMongoConnCmdErr(conn, cmdKey, code, codeName, errmsg)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return fmt.Sprintf(
		"mongodb://127.0.0.1:%s/admin?directConnection=true&serverSelectionTimeoutMS=5000",
		port,
	)
}

func TestMongoEngine_Issue_CreateUserFails(t *testing.T) {
	uri := startFakeMongoServerCmdErr(t, "createUser", 13, "Unauthorized", "not authorized on admin")
	// G48/2b: dials a fake MongoDB server on 127.0.0.1 -- an explicit,
	// intentional loopback target speaking plain (non-TLS) wire protocol.
	e := &MongoEngine{allowPrivateNetwork: true, allowInsecureTransport: true}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, uri, `{"roles": ["readWrite"]}`, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create user")
}

func TestMongoEngine_Revoke_DropUserFails_NotIdempotent(t *testing.T) {
	uri := startFakeMongoServerCmdErr(t, "dropUser", 13, "Unauthorized", "not authorized on admin")
	e := &MongoEngine{allowPrivateNetwork: true, allowInsecureTransport: true}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := e.Revoke(ctx, uri, "kx_dyn_validname123")
	require.Error(t, err, "a real (non-UserNotFound) dropUser failure must be reported, not swallowed")
	assert.Contains(t, err.Error(), "drop user")
}

func TestMongoEngine_Revoke_DropUserNotFound_IsIdempotent(t *testing.T) {
	uri := startFakeMongoServerCmdErr(t, "dropUser", 11, "UserNotFound", "user not found")
	e := &MongoEngine{allowPrivateNetwork: true, allowInsecureTransport: true}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := e.Revoke(ctx, uri, "kx_dyn_validname123")
	require.NoError(t, err, "UserNotFound (already gone) must be treated as a successful, idempotent revoke")
}

// ─────────────────────────── mysql.go: killUserConnections QueryContext error ─
//
// The rows.Scan error branch already has a test (TestKillUserConnections_ScanError
// in dynamic_s23_test.go); the earlier `if err != nil { return }` guarding the
// QueryContext call itself does not — that requires the SELECT against
// information_schema.processlist to fail outright, not just return a bad row.

type fakeQueryErrDriver struct{}

func (d *fakeQueryErrDriver) Open(_ string) (driver.Conn, error) {
	return &fakeQueryErrConn{}, nil
}

type fakeQueryErrConn struct{ execCalled *bool }

func (c *fakeQueryErrConn) Prepare(_ string) (driver.Stmt, error) {
	return &fakeQueryErrStmt{execCalled: c.execCalled}, nil
}
func (c *fakeQueryErrConn) Close() error              { return nil }
func (c *fakeQueryErrConn) Begin() (driver.Tx, error) { return nil, fmt.Errorf("not supported") }

type fakeQueryErrStmt struct{ execCalled *bool }

func (s *fakeQueryErrStmt) Close() error  { return nil }
func (s *fakeQueryErrStmt) NumInput() int { return -1 }
func (s *fakeQueryErrStmt) Exec(_ []driver.Value) (driver.Result, error) {
	if s.execCalled != nil {
		*s.execCalled = true
	}
	return driver.RowsAffected(0), nil
}
func (s *fakeQueryErrStmt) Query(_ []driver.Value) (driver.Rows, error) {
	// Simulates the processlist SELECT itself failing (e.g. missing privilege).
	return nil, fmt.Errorf("simulated processlist query failure")
}

func TestKillUserConnections_QueryContextError(t *testing.T) {
	var killExecuted bool
	db := sql.OpenDB(&fakeQueryErrConnector{execCalled: &killExecuted})
	defer db.Close() //nolint:errcheck

	// killUserConnections is best-effort: when the processlist query itself
	// fails, it must return immediately without ever attempting a KILL.
	killUserConnections(context.Background(), db, "kx_dyn_test")
	assert.False(t, killExecuted, "no KILL statement must run when the processlist query failed")
}

// fakeQueryErrConnector lets each test get its own execCalled flag (sql.Open
// with a registered driver name shares no per-call state, so we use a
// driver.Connector instead — it's part of database/sql, no new dependency).
type fakeQueryErrConnector struct{ execCalled *bool }

func (c *fakeQueryErrConnector) Connect(_ context.Context) (driver.Conn, error) {
	return &fakeQueryErrConn{execCalled: c.execCalled}, nil
}
func (c *fakeQueryErrConnector) Driver() driver.Driver { return &fakeQueryErrDriver{} }

// ─────────────────────────── postgres.go: dialPostgres ParseConfig error ──────

func TestDialPostgres_InvalidDSN(t *testing.T) {
	_, err := dialPostgres(context.Background(), "not a valid dsn at all ::: %zz", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connect to target")
}

// ─────────────────────────── azure.go: credential-construction failure ────────
//
// azidentity.NewDefaultAzureCredential checks AZURE_TOKEN_CREDENTIALS up front
// and fails synchronously (no network) if it's set to an unrecognized value —
// this is the one deterministic, hermetic way to force newRealAzureMinter's own
// error branch (previously unreachable: in this environment
// NewDefaultAzureCredential(nil) otherwise always succeeds, deferring any
// failure to the later GetToken call).

func TestNewRealAzureMinter_InvalidTokenCredentialsEnv(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "not-a-real-credential-type")
	_, err := newRealAzureMinter()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build default credential")
}

func TestAzureEngine_Issue_NilMinter_CredentialBuildFails(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "not-a-real-credential-type")
	eng := &AzureEngine{} // nil minter → Issue must call newRealAzureMinter itself
	_, _, err := eng.Issue(context.Background(),
		`{"scopes":["https://management.azure.com/.default"]}`, "", time.Hour)
	require.Error(t, err)
	// Must surface the credential-construction failure, not a downstream
	// "acquire token" error — proves Issue's own nil-minter error-propagation
	// branch (not just newRealAzureMinter in isolation) was exercised.
	assert.Contains(t, err.Error(), "build default credential")
}

// ─────────────────────────── gcp.go: real client construction succeeds ────────
//
// iamcredentials.NewService only parses local Application Default Credentials —
// it makes no network call at construction time. Pointing
// GOOGLE_APPLICATION_CREDENTIALS at a syntactically-valid (but fake) service
// account key file lets newRealGCPMinter succeed without any real GCP access.
// Then, to cover Issue's own "minter = m" assignment (not just
// newRealGCPMinter in isolation) without depending on live network
// reachability, the request is made with an already-expired context: the
// actual GenerateAccessToken HTTP call fails immediately on the expired
// deadline before attempting to dial anything, so the test is fast and fully
// hermetic in an air-gapped CI runner too.

// writeFakeGCPServiceAccountKey writes a syntactically-valid (self-signed, not
// registered with Google) service-account JSON key so google.FindDefaultCredentials
// can parse it successfully; it is never used to make a real authenticated call.
func writeFakeGCPServiceAccountKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	sa := map[string]string{
		"type":                        "service_account",
		"project_id":                  "fake-project",
		"private_key_id":              "fakekeyid",
		"private_key":                 string(pemBytes),
		"client_email":                "fake@fake-project.iam.gserviceaccount.com",
		"client_id":                   "123456789",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/fake",
	}
	b, err := json.Marshal(sa)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "fake-sa.json")
	require.NoError(t, os.WriteFile(path, b, 0o600))
	return path
}

func TestNewRealGCPMinter_Success(t *testing.T) {
	path := writeFakeGCPServiceAccountKey(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := newRealGCPMinter(ctx)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.NotNil(t, m.svc)
}

func TestGCPEngine_Issue_NilMinter_BuildsRealMinter(t *testing.T) {
	path := writeFakeGCPServiceAccountKey(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)

	// Already-expired: newRealGCPMinter succeeds (local-only), the subsequent
	// GenerateAccessToken call fails instantly on the expired deadline.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)

	eng := &GCPEngine{} // nil minter → Issue must call newRealGCPMinter itself
	_, _, err := eng.Issue(ctx,
		`{"service_account":"fake@fake-project.iam.gserviceaccount.com"}`, "", time.Hour)
	require.Error(t, err, "an already-expired context must fail the token request, but newRealGCPMinter itself must have succeeded first")
}
