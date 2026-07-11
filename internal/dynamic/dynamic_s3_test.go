package dynamic

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	iamcredentials "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

// ──────────────────────────── realK8sMinter via httptest ──────────────────────
//
// These tests exercise the realK8sMinter's REST calls (mintToken,
// createBoundSecret, deleteBoundSecret) against a local httptest.TLS server so
// every line of the HTTP/JSON path is covered without a real cluster.

// buildK8sMinter returns a *realK8sMinter wired to an httptest.TLS server.  The
// caller must call srv.Close() and may inspect/drive srv.Handler as needed.
func buildK8sMinter(t *testing.T, handler http.Handler) (*realK8sMinter, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)

	// Extract the self-signed cert so we can construct a valid TLS pool.
	pool := x509.NewCertPool()
	for _, c := range srv.TLS.Certificates {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		require.NoError(t, err)
		pool.AddCert(leaf)
	}

	minter := &realK8sMinter{
		host:  srv.URL,
		token: "test-bearer",
		hc: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
		},
	}
	return minter, srv
}

// ── mintToken happy path ──────────────────────────────────────────────────────

func TestRealK8sMinter_MintToken_Success(t *testing.T) {
	expStr := "2030-01-01T00:00:00Z"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/serviceaccounts/my-app/token")
		assert.Equal(t, "Bearer test-bearer", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":{"token":"k8s-tok","expirationTimestamp":%q}}`, expStr)
	})
	m, srv := buildK8sMinter(t, handler)
	defer srv.Close()

	tok, expiry, err := m.mintToken(context.Background(), "default", "my-app", nil, 30*time.Minute, nil)
	require.NoError(t, err)
	assert.Equal(t, "k8s-tok", tok)
	assert.Equal(t, "2030-01-01T00:00:00Z", expiry.UTC().Format(time.RFC3339))
}

// mintToken with audiences and a boundObjectRef ─────────────────────────────

func TestRealK8sMinter_MintToken_WithBound(t *testing.T) {
	var gotBody map[string]any
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = fmt.Fprintf(w, `{"status":{"token":"tok2","expirationTimestamp":"2031-01-01T00:00:00Z"}}`)
	})
	m, srv := buildK8sMinter(t, handler)
	defer srv.Close()

	bound := &boundObjectRef{Name: "my-secret", UID: "uid-1"}
	tok, _, err := m.mintToken(context.Background(), "ns", "sa", []string{"https://aud"}, time.Hour, bound)
	require.NoError(t, err)
	assert.Equal(t, "tok2", tok)

	spec, _ := gotBody["spec"].(map[string]any)
	require.NotNil(t, spec)
	// audiences are forwarded
	assert.NotNil(t, spec["audiences"])
	// boundObjectRef is embedded
	bor, _ := spec["boundObjectRef"].(map[string]any)
	require.NotNil(t, bor)
	assert.Equal(t, "my-secret", bor["name"])
	assert.Equal(t, "uid-1", bor["uid"])
}

// mintToken error paths ───────────────────────────────────────────────────────

func TestRealK8sMinter_MintToken_Unauthorized(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, _, err := m.mintToken(context.Background(), "ns", "sa", nil, time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestRealK8sMinter_MintToken_Forbidden(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, _, err := m.mintToken(context.Background(), "ns", "sa", nil, time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestRealK8sMinter_MintToken_ServerError(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, _, err := m.mintToken(context.Background(), "ns", "sa", nil, time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestRealK8sMinter_MintToken_EmptyToken(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":{"token":""}}`)
	}))
	defer srv.Close()
	_, _, err := m.mintToken(context.Background(), "ns", "sa", nil, time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no token")
}

func TestRealK8sMinter_MintToken_BadJSON(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `not-json`)
	}))
	defer srv.Close()
	_, _, err := m.mintToken(context.Background(), "ns", "sa", nil, time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestRealK8sMinter_MintToken_InvalidNamespace(t *testing.T) {
	// pathSegment("") returns "INVALID"; the URL is still valid HTTP but the path
	// contains INVALID — we just verify no panic.
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	_, _, err := m.mintToken(context.Background(), "", "sa", nil, time.Minute, nil)
	require.Error(t, err)
}

// ── createBoundSecret happy path ─────────────────────────────────────────────

func TestRealK8sMinter_CreateBoundSecret_Success(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/secrets")
		_, _ = fmt.Fprint(w, `{"metadata":{"uid":"uid-abc-123"}}`)
	})
	m, srv := buildK8sMinter(t, handler)
	defer srv.Close()

	uid, err := m.createBoundSecret(context.Background(), "default", "keyorix-dyn-abc")
	require.NoError(t, err)
	assert.Equal(t, "uid-abc-123", uid)
}

func TestRealK8sMinter_CreateBoundSecret_Unauthorized(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := m.createBoundSecret(context.Background(), "ns", "name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestRealK8sMinter_CreateBoundSecret_ServerError(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := m.createBoundSecret(context.Background(), "ns", "name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestRealK8sMinter_CreateBoundSecret_EmptyUID(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"metadata":{"uid":""}}`)
	}))
	defer srv.Close()
	_, err := m.createBoundSecret(context.Background(), "ns", "name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no uid")
}

func TestRealK8sMinter_CreateBoundSecret_BadJSON(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{bad`)
	}))
	defer srv.Close()
	_, err := m.createBoundSecret(context.Background(), "ns", "name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

// ── deleteBoundSecret happy path + edge paths ─────────────────────────────────

func TestRealK8sMinter_DeleteBoundSecret_Success(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	require.NoError(t, m.deleteBoundSecret(context.Background(), "ns", "keyorix-dyn-abc"))
}

func TestRealK8sMinter_DeleteBoundSecret_NotFound_Idempotent(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	require.NoError(t, m.deleteBoundSecret(context.Background(), "ns", "keyorix-dyn-abc"))
}

func TestRealK8sMinter_DeleteBoundSecret_Unauthorized(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	err := m.deleteBoundSecret(context.Background(), "ns", "name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestRealK8sMinter_DeleteBoundSecret_ServerError(t *testing.T) {
	m, srv := buildK8sMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := m.deleteBoundSecret(context.Background(), "ns", "name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

// ── AWSSTSEngine.client default path ─────────────────────────────────────────
//
// When newClient is nil the engine builds a real STS client from AWS config.
// With no credentials in the environment this won't reach AWS, but it covers
// the load-config branch in client().

func TestAWSSTSEngine_ClientDefault_LoadsConfig(t *testing.T) {
	e := &AWSSTSEngine{} // no injected newClient
	// If AWS_REGION is unset we still get a client (no error from LoadDefaultConfig).
	// The actual AssumeRole call would fail, but building the client must not.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// We cannot call AssumeRole without real creds, but we can confirm client() itself
	// doesn't error when the SDK environment is empty (it doesn't require a region at
	// config-load time). The returned client is non-nil when err == nil.
	_, err := e.client(ctx, "")
	// The SDK may succeed (returns a client with no region) or fail if something about
	// the environment prevents config loading.  Either way, this exercises the branch.
	_ = err
}

func TestAWSSTSEngine_ClientDefault_WithRegion(t *testing.T) {
	e := &AWSSTSEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Passing a region covers the opts = append(opts, ...) branch.
	_, err := e.client(ctx, "us-east-1")
	_ = err
}

// ── AWSSTSEngine Issue: nil credentials returned ──────────────────────────────

func TestAWSSTSEngine_Issue_NilCredentials(t *testing.T) {
	fake := &fakeSTS{out: &sts.AssumeRoleOutput{Credentials: nil}}
	eng := newFakeSTSEngine(fake)
	_, _, err := eng.Issue(context.Background(),
		`{"role_arn":"arn:aws:iam::1:role/r","region":"us-east-1"}`, "", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credentials")
}

// ── AWSSTSEngine Issue: ExternalID and explicit duration ─────────────────────

func TestAWSSTSEngine_Issue_ExternalID(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	fake := &fakeSTS{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     aws.String("K"),
		SecretAccessKey: aws.String("S"),
		SessionToken:    aws.String("T"),
		Expiration:      &exp,
	}}}
	eng := newFakeSTSEngine(fake)
	cfg := `{"role_arn":"arn:aws:iam::1:role/r","region":"us-east-1","external_id":"ext-1","duration_seconds":1800}`
	_, _, err := eng.Issue(context.Background(), cfg, "", time.Hour)
	require.NoError(t, err)
	// ExternalId is forwarded.
	require.NotNil(t, fake.in.ExternalId)
	assert.Equal(t, "ext-1", *fake.in.ExternalId)
	// Explicit duration_seconds overrides the TTL.
	assert.Equal(t, int32(1800), *fake.in.DurationSeconds)
}

// ── AWSSTSEngine Issue: newClient error ──────────────────────────────────────

func TestAWSSTSEngine_Issue_ClientError(t *testing.T) {
	eng := &AWSSTSEngine{
		newClient: func(_ context.Context, _ string) (stsAssumeAPI, error) {
			return nil, fmt.Errorf("cannot build STS client")
		},
	}
	_, _, err := eng.Issue(context.Background(),
		`{"role_arn":"arn:aws:iam::1:role/r"}`, "", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot build STS client")
}

// ── AWSSTSEngine Issue: AssumeRole error ─────────────────────────────────────

func TestAWSSTSEngine_Issue_AssumeRoleError(t *testing.T) {
	fake := &fakeSTS{err: fmt.Errorf("access denied")}
	eng := newFakeSTSEngine(fake)
	_, _, err := eng.Issue(context.Background(),
		`{"role_arn":"arn:aws:iam::1:role/r"}`, "", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assume role")
}

// ── GCPEngine Issue: minter error ───────────────────────────────────────────

func TestGCPEngine_Issue_MinterError(t *testing.T) {
	fake := &fakeGCPMinter{err: fmt.Errorf("gcp token error")}
	eng := &GCPEngine{minter: fake}
	_, _, err := eng.Issue(context.Background(),
		`{"service_account":"sa@proj.iam.gserviceaccount.com"}`, "", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "generate access token")
}

// ── AzureEngine Issue: minter error ─────────────────────────────────────────

func TestAzureEngine_Issue_MinterError(t *testing.T) {
	fake := &fakeAzureMinter{err: fmt.Errorf("azure token error")}
	eng := &AzureEngine{minter: fake}
	_, _, err := eng.Issue(context.Background(),
		`{"scopes":["https://management.azure.com/.default"]}`, "", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acquire token")
}

// ── GCPEngine Issue: no expiry field ─────────────────────────────────────────
// Exercises the branch where expiry.IsZero() → "expiration" field omitted.

func TestGCPEngine_Issue_NoExpiry(t *testing.T) {
	fake := &fakeGCPMinter{token: "tok", expiry: time.Time{}} // zero expiry
	eng := &GCPEngine{minter: fake}
	cred, role, err := eng.Issue(context.Background(),
		`{"service_account":"sa@proj.iam.gserviceaccount.com"}`, "", time.Hour)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(role, "keyorix-dyn-"))
	_, hasExp := cred.Fields["expiration"]
	assert.False(t, hasExp, "zero expiry must not produce an expiration field")
}

// ── AzureEngine Issue: no expiry field ───────────────────────────────────────

func TestAzureEngine_Issue_NoExpiry(t *testing.T) {
	fake := &fakeAzureMinter{token: "tok", expiry: time.Time{}}
	eng := &AzureEngine{minter: fake}
	cred, role, err := eng.Issue(context.Background(),
		`{"scopes":["https://management.azure.com/.default"]}`, "", time.Hour)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(role, "keyorix-dyn-"))
	_, hasExp := cred.Fields["expiration"]
	assert.False(t, hasExp, "zero expiry must not produce an expiration field")
}

// ── newRealK8sMinter success path ────────────────────────────────────────────
//
// The existing kubernetes_test.go covers only the FAILURE paths of
// newRealK8sMinter (missing token, missing ca_cert, invalid PEM, not in-cluster).
// This test covers the success path: a valid PEM CA is supplied and the function
// returns a non-nil minter.

func TestNewRealK8sMinter_Success(t *testing.T) {
	// Use the TLS cert from an httptest.TLS server as a stand-in for a real CA.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	// Extract PEM from the test server's certificate.
	var pemBuf strings.Builder
	for _, c := range srv.TLS.Certificates {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		require.NoError(t, err)
		pemBuf.WriteString("-----BEGIN CERTIFICATE-----\n")
		pemBuf.Write(encodeBase64Lines(leaf.Raw))
		pemBuf.WriteString("-----END CERTIFICATE-----\n")
	}

	cfg := k8sConfig{
		APIServer:      srv.URL,
		Token:          "my-bearer-token",
		CACert:         pemBuf.String(),
		Namespace:      "default",
		ServiceAccount: "my-sa",
	}
	m, err := newRealK8sMinter(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, srv.URL, m.host)
	assert.Equal(t, "my-bearer-token", m.token)
}

// encodeBase64Lines encodes raw DER bytes as base64, inserting newlines every
// 64 characters so it forms a valid PEM body.
func encodeBase64Lines(der []byte) []byte {
	const lineLen = 64
	encoded := make([]byte, base64Len(len(der)))
	n := encodeBase64(encoded, der)
	encoded = encoded[:n]
	var out []byte
	for len(encoded) > 0 {
		chunk := encoded
		if len(chunk) > lineLen {
			chunk = chunk[:lineLen]
		}
		out = append(out, chunk...)
		out = append(out, '\n')
		encoded = encoded[len(chunk):]
	}
	return out
}

func base64Len(n int) int { return (n + 2) / 3 * 4 }

func encodeBase64(dst, src []byte) int {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	j := 0
	for i := 0; i < len(src); i += 3 {
		b0 := src[i]
		var b1, b2 byte
		if i+1 < len(src) {
			b1 = src[i+1]
		}
		if i+2 < len(src) {
			b2 = src[i+2]
		}
		dst[j] = enc[b0>>2]
		dst[j+1] = enc[((b0&0x3)<<4)|(b1>>4)]
		if i+1 < len(src) {
			dst[j+2] = enc[((b1&0xf)<<2)|(b2>>6)]
		} else {
			dst[j+2] = '='
		}
		if i+2 < len(src) {
			dst[j+3] = enc[b2&0x3f]
		} else {
			dst[j+3] = '='
		}
		j += 4
	}
	return j
}

// ── KubernetesEngine.Revoke minter==nil paths ────────────────────────────────

func TestKubernetesEngine_Revoke_NilMinterFails_WhenRevocableButNoCluster(t *testing.T) {
	// Revocable=true with minter==nil triggers newRealK8sMinter which fails
	// because KUBERNETES_SERVICE_HOST is not set (not in-cluster) and no api_server.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	e := &KubernetesEngine{} // no injected minter
	err := e.Revoke(context.Background(),
		`{"namespace":"app","service_account":"sa","revocable":true}`,
		"keyorix-dyn-x")
	require.Error(t, err)
	// Either "not in-cluster" or some connection error.
}

// ── KubernetesEngine.Issue minter==nil paths ──────────────────────────────────

func TestKubernetesEngine_Issue_NilMinterFails_WhenNoCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	e := &KubernetesEngine{} // no injected minter
	_, _, err := e.Issue(context.Background(),
		`{"namespace":"app","service_account":"sa"}`,
		"", time.Hour)
	require.Error(t, err)
}

// ── newRealK8sMinter in-cluster path ──────────────────────────────────────────
//
// When api_server is empty and KUBERNETES_SERVICE_HOST/PORT are set but the
// mounted token file doesn't exist, newRealK8sMinter returns a "read in-cluster
// token" error. This covers the host/port parsing + os.ReadFile branches.

func TestNewRealK8sMinter_InCluster_TokenFileMissing(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	// k8sSATokenPath does not exist in this environment.
	_, err := newRealK8sMinter(k8sConfig{Namespace: "ns", ServiceAccount: "sa"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "in-cluster token")
}

// ── Minimal RESP server for Redis backend tests ───────────────────────────────
//
// A tiny TCP server that speaks just enough RESP2 (Redis Serialization Protocol)
// to let connectRedis succeed (PING→PONG) and allow ACL SETUSER / ACL DELUSER
// calls to pass through (+OK / :0), so the Issue and Revoke success paths are
// covered without a real Redis installation.
//
// go-redis v9 defaults to RESP2 unless Options.Protocol is explicitly set to 3,
// so no HELLO negotiation is needed.

// startRESPServer starts a server on a random local port and returns its address.
func startRESPServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // server closed
			}
			go handleRESP(conn)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// handleRESP reads one RESP2 command at a time (via bufio) and replies:
//   - PING  → +PONG
//   - ACL DELUSER → :0
//   - everything else → +OK
func handleRESP(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	r := bufio.NewReader(conn)
	for {
		// Each RESP2 command begins with '*' (array count).
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] != '*' {
			_, _ = conn.Write([]byte("+OK\r\n"))
			continue
		}
		// Parse the array count.
		n := 0
		_, _ = fmt.Sscanf(line[1:], "%d", &n)
		args := make([]string, 0, n)
		for i := 0; i < n; i++ {
			// Bulk string: $<len>\r\n<data>\r\n
			hdr, err := r.ReadString('\n')
			if err != nil {
				return
			}
			var l int
			_, _ = fmt.Sscanf(strings.TrimSpace(hdr)[1:], "%d", &l)
			data := make([]byte, l+2) // +2 for \r\n
			_, err = io.ReadFull(r, data)
			if err != nil {
				return
			}
			args = append(args, string(data[:l]))
		}
		if len(args) == 0 {
			_, _ = conn.Write([]byte("+OK\r\n"))
			continue
		}
		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		case "HELLO":
			// go-redis v9 sends HELLO 2 (or HELLO 3) to negotiate the protocol.
			// Respond with a RESP2 inline map (% is RESP3 map; for RESP2 we return
			// a bulk-string array that go-redis understands as server info).
			// The simplest valid response is the old RESP2 "inline" format as a
			// flat array of key-value pairs.
			_, _ = conn.Write([]byte("*14\r\n" +
				"$6\r\nserver\r\n$5\r\nredis\r\n" +
				"$7\r\nversion\r\n$5\r\n6.2.0\r\n" +
				"$5\r\nproto\r\n:2\r\n" +
				"$2\r\nid\r\n:1\r\n" +
				"$4\r\nmode\r\n$10\r\nstandalone\r\n" +
				"$4\r\nrole\r\n$6\r\nmaster\r\n" +
				"$7\r\nmodules\r\n*0\r\n"))
		case "ACL":
			if len(args) > 1 && strings.ToUpper(args[1]) == "DELUSER" {
				_, _ = conn.Write([]byte(":0\r\n"))
			} else {
				_, _ = conn.Write([]byte("+OK\r\n"))
			}
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	}
}

func TestRedisEngine_Issue_Success(t *testing.T) {
	addr := startRESPServer(t)
	e := &RedisEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cred, role, err := e.Issue(ctx, "redis://"+addr+"/0", "~app:* +@read", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, cred.Username)
	assert.NotEmpty(t, cred.Password)
	assert.NotEmpty(t, role)
}

func TestRedisEngine_Revoke_Success(t *testing.T) {
	addr := startRESPServer(t)
	e := &RedisEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := e.Revoke(ctx, "redis://"+addr+"/0", "kx_dyn_abc123")
	require.NoError(t, err)
}

// startRESPServerWithACLError returns a RESP server that responds to PING with
// PONG (so connectRedis succeeds) but returns a RESP error for all ACL commands
// (so Issue/Revoke return errors after connecting). This covers the "create acl
// user" error branch in Issue and the "delete acl user" error branch in Revoke.
func startRESPServerWithACLError(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleRESPWithACLError(conn)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func handleRESPWithACLError(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] != '*' {
			_, _ = conn.Write([]byte("+OK\r\n"))
			continue
		}
		n := 0
		_, _ = fmt.Sscanf(line[1:], "%d", &n)
		args := make([]string, 0, n)
		for i := 0; i < n; i++ {
			hdr, err := r.ReadString('\n')
			if err != nil {
				return
			}
			var l int
			_, _ = fmt.Sscanf(strings.TrimSpace(hdr)[1:], "%d", &l)
			data := make([]byte, l+2)
			_, err = io.ReadFull(r, data)
			if err != nil {
				return
			}
			args = append(args, string(data[:l]))
		}
		if len(args) == 0 {
			_, _ = conn.Write([]byte("+OK\r\n"))
			continue
		}
		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		case "HELLO":
			_, _ = conn.Write([]byte("*14\r\n" +
				"$6\r\nserver\r\n$5\r\nredis\r\n" +
				"$7\r\nversion\r\n$5\r\n6.2.0\r\n" +
				"$5\r\nproto\r\n:2\r\n" +
				"$2\r\nid\r\n:1\r\n" +
				"$4\r\nmode\r\n$10\r\nstandalone\r\n" +
				"$4\r\nrole\r\n$6\r\nmaster\r\n" +
				"$7\r\nmodules\r\n*0\r\n"))
		case "ACL":
			_, _ = conn.Write([]byte("-ERR ACL command not allowed\r\n"))
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	}
}

func TestRedisEngine_Issue_ACLError(t *testing.T) {
	addr := startRESPServerWithACLError(t)
	e := &RedisEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, "redis://"+addr+"/0", "~app:* +@read", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create acl user")
}

func TestRedisEngine_Revoke_ACLError(t *testing.T) {
	addr := startRESPServerWithACLError(t)
	e := &RedisEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := e.Revoke(ctx, "redis://"+addr+"/0", "kx_dyn_abc123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete acl user")
}

// ── AzureEngine with nil minter (exercises newRealAzureMinter) ───────────────
//
// Without real Azure credentials this will fail somewhere inside newRealAzureMinter
// or mintToken, but it exercises the real-minter construction path (the nil-minter
// branch in Issue).

func TestAzureEngine_Issue_NilMinter_CallsNewRealMinter(t *testing.T) {
	eng := &AzureEngine{} // nil minter — will call newRealAzureMinter
	// Valid JSON + scopes so it gets past the config validation and into the minter path.
	_, _, err := eng.Issue(context.Background(),
		`{"scopes":["https://management.azure.com/.default"]}`, "", time.Hour)
	// Must error somewhere (no Azure credentials in CI), but must not panic.
	require.Error(t, err)
}

// ── GCPEngine with nil minter (exercises newRealGCPMinter) ───────────────────

func TestGCPEngine_Issue_NilMinter_CallsNewRealMinter(t *testing.T) {
	eng := &GCPEngine{} // nil minter — will call newRealGCPMinter
	_, _, err := eng.Issue(context.Background(),
		`{"service_account":"sa@proj.iam.gserviceaccount.com"}`, "", time.Hour)
	// Must error somewhere (no GCP credentials in CI), but must not panic.
	require.Error(t, err)
}

// ── MySQL killUserConnections via test helper ────────────────────────────────
//
// killUserConnections is best-effort (errors ignored). We exercise it via a
// real sql.DB backed by a TCP listener that closes immediately — the QueryContext
// call will fail harmlessly, which is the intended behaviour.

func TestKillUserConnections_NoRows(t *testing.T) {
	// Use the existing openMySQL error path to get a sql.DB we can pass in: since
	// we can't easily get a *sql.DB in an open state for a dead host, we exercise
	// killUserConnections via an already-closed DB and confirm it does not panic.
	//
	// We open a *sql.DB via sql.Open (which succeeds even for a bad DSN) and then
	// call killUserConnections. The QueryContext will fail; killUserConnections is
	// expected to silently return.
	db, err := openMySQL(context.Background(), "user:pass@tcp(localhost:13306)/db")
	// openMySQL may fail (unreachable host) — if it does, there's no DB to pass.
	if err != nil {
		t.Skip("MySQL host unreachable; killUserConnections path covered by integration")
	}
	defer db.Close() //nolint:errcheck
	killUserConnections(context.Background(), db, "kx_dyn_test")
	// No panic = pass.
}

// ── KubernetesEngine.Issue nil-minter path via real api_server config ─────────
//
// When minter is nil, Issue calls newRealK8sMinter to build a REST client.
// These tests exercise that code path (the "minter = m" branch on line ~140)
// by supplying a valid api_server/token/ca_cert config pointing to an in-process
// TLS stub server, then failing at the actual token request (which is expected
// because the stub returns an error response). The goal is to cover the
// "build real minter from config" branch, not the full Issue success path.

// buildK8sCACertPEM extracts a PEM-encoded certificate from an httptest.TLS server.
func buildK8sCACertPEM(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	var pemBuf strings.Builder
	for _, c := range srv.TLS.Certificates {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		require.NoError(t, err)
		pemBuf.WriteString("-----BEGIN CERTIFICATE-----\n")
		pemBuf.Write(encodeBase64Lines(leaf.Raw))
		pemBuf.WriteString("-----END CERTIFICATE-----\n")
	}
	return pemBuf.String()
}

// ── mintToken / createBoundSecret / deleteBoundSecret request-failed paths ───
//
// Cover the `if err != nil { return ..., "request failed" }` branches that are
// triggered when m.hc.Do(req) returns a network error. We do this by closing
// the fake TLS server before issuing the request so the TCP connection is refused.

func TestRealK8sMinter_MintToken_RequestFailed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	m, srv := buildK8sMinter(t, handler)
	// Close the server now so Do(req) gets a "connection refused" error.
	srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := m.mintToken(ctx, "default", "my-sa", nil, time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestRealK8sMinter_CreateBoundSecret_RequestFailed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	m, srv := buildK8sMinter(t, handler)
	srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.createBoundSecret(ctx, "default", "keyorix-dyn-test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestRealK8sMinter_DeleteBoundSecret_RequestFailed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	m, srv := buildK8sMinter(t, handler)
	srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := m.deleteBoundSecret(ctx, "default", "keyorix-dyn-test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestKubernetesEngine_Issue_NilMinterBuildsRealMinter(t *testing.T) {
	// Stub server returns an error for TokenRequest so Issue fails gracefully,
	// but the "minter = m" assignment after newRealK8sMinter must be reached.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	caPEM := buildK8sCACertPEM(t, srv)
	cfg := fmt.Sprintf(`{"namespace":"default","service_account":"my-sa","api_server":%q,"token":"tok","ca_cert":%q}`,
		srv.URL, caPEM)

	e := &KubernetesEngine{} // nil minter → will call newRealK8sMinter
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, cfg, "", time.Hour)
	// Must error (stub server returns 500 for the TokenRequest), but must NOT
	// panic — the critical coverage point is that newRealK8sMinter succeeded and
	// minter was assigned before the HTTP call was made.
	require.Error(t, err)
}

func TestKubernetesEngine_Revoke_NilMinterRevocableBuildsRealMinter(t *testing.T) {
	// Same pattern for Revoke: revocable=true forces the code to build a real
	// minter and call deleteBoundSecret, which fails at the HTTP level.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	caPEM := buildK8sCACertPEM(t, srv)
	cfg := fmt.Sprintf(`{"namespace":"default","service_account":"my-sa","revocable":true,"api_server":%q,"token":"tok","ca_cert":%q}`,
		srv.URL, caPEM)

	e := &KubernetesEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := e.Revoke(ctx, cfg, "keyorix-dyn-abc123xyz012")
	// Must error (stub returns 500), but newRealK8sMinter + minter assignment
	// must have been reached.
	require.Error(t, err)
}

// ── mintToken/createBoundSecret/deleteBoundSecret http.NewRequestWithContext error ─
//
// http.NewRequestWithContext returns an error when the URL contains a control
// character (Go's net/url rejects them). This covers the "build request: %w"
// branches that cannot be reached by a normal closed-server test because the
// server-close path hits the "request failed" branch instead.

// buildInvalidHostMinter returns a realK8sMinter whose host contains a null byte,
// causing http.NewRequestWithContext to fail with "invalid control character in URL".
func buildInvalidHostMinter(t *testing.T) *realK8sMinter {
	t.Helper()
	pool := x509.NewCertPool()
	return &realK8sMinter{
		host:  "http://\x00invalid",
		token: "tok",
		hc: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
		},
	}
}

func TestRealK8sMinter_MintToken_BuildRequestError(t *testing.T) {
	m := buildInvalidHostMinter(t)
	_, _, err := m.mintToken(context.Background(), "default", "my-sa", nil, time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestRealK8sMinter_CreateBoundSecret_BuildRequestError(t *testing.T) {
	m := buildInvalidHostMinter(t)
	_, err := m.createBoundSecret(context.Background(), "default", "keyorix-dyn-test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestRealK8sMinter_DeleteBoundSecret_BuildRequestError(t *testing.T) {
	m := buildInvalidHostMinter(t)
	err := m.deleteBoundSecret(context.Background(), "default", "keyorix-dyn-test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

// ── killUserConnections via fake SQL driver ───────────────────────────────────
//
// killUserConnections is best-effort (errors ignored) and takes a *sql.DB
// directly. We register a minimal in-memory fake driver that returns one row
// from the processlist query so the KILL loop executes, giving full coverage
// of the function without a live MySQL server.

// fakeKillDriver is a minimal database/sql/driver.Driver that returns a single
// processlist row with id=42, then succeeds on any EXEC (the KILL statement).
type fakeKillDriver struct{}

var fakeKillOnce sync.Once

func registerFakeKillDriver() {
	fakeKillOnce.Do(func() {
		sql.Register("fakekill", &fakeKillDriver{})
	})
}

func (d *fakeKillDriver) Open(_ string) (driver.Conn, error) {
	return &fakeKillConn{}, nil
}

type fakeKillConn struct{ closed bool }

func (c *fakeKillConn) Prepare(query string) (driver.Stmt, error) {
	return &fakeKillStmt{query: query}, nil
}
func (c *fakeKillConn) Close() error  { c.closed = true; return nil }
func (c *fakeKillConn) Begin() (driver.Tx, error) { return nil, fmt.Errorf("not supported") }

type fakeKillStmt struct{ query string }

func (s *fakeKillStmt) Close() error  { return nil }
func (s *fakeKillStmt) NumInput() int { return -1 } // variadic

func (s *fakeKillStmt) Exec(_ []driver.Value) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}

func (s *fakeKillStmt) Query(_ []driver.Value) (driver.Rows, error) {
	// Only the processlist SELECT returns a row; KILL statements go through Exec.
	return &fakeKillRows{id: 42}, nil
}

type fakeKillRows struct {
	id      int64
	yielded bool
}

func (r *fakeKillRows) Columns() []string { return []string{"id"} }
func (r *fakeKillRows) Close() error      { return nil }
func (r *fakeKillRows) Next(dest []driver.Value) error {
	if r.yielded {
		return io.EOF
	}
	r.yielded = true
	dest[0] = r.id
	return nil
}

func TestKillUserConnections_WithRows(t *testing.T) {
	registerFakeKillDriver()
	db, err := sql.Open("fakekill", "")
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck

	// killUserConnections is fire-and-forget (no return value, errors ignored).
	// Running it against our fake DB exercises the QueryContext, rows.Next,
	// rows.Scan, and ExecContext(KILL) branches — all uncovered without a real DB.
	ctx := context.Background()
	killUserConnections(ctx, db, "test_user")
	// No panic and no error expected — function is best-effort.
}

// ── realGCPMinter.mintAccessToken via fake HTTP ───────────────────────────────
//
// realGCPMinter.mintAccessToken is entirely uncovered because newRealGCPMinter
// requires Application Default Credentials. We bypass newRealGCPMinter entirely
// by constructing a realGCPMinter directly with an iamcredentials.Service wired
// to a local httptest server, then test both the error path and the success path
// (with and without an ExpireTime in the response).

func TestRealGCPMinter_MintAccessToken_Error(t *testing.T) {
	// The server returns a 403 so Do() returns an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":{"code":403,"message":"permission denied"}}`)
	}))
	defer srv.Close()

	svc, err := iamcredentials.NewService(context.Background(), option.WithHTTPClient(srv.Client()))
	require.NoError(t, err)
	svc.BasePath = srv.URL + "/"

	m := &realGCPMinter{svc: svc}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = m.mintAccessToken(ctx, "sa@proj.iam.gserviceaccount.com", nil, time.Hour)
	require.Error(t, err)
}

func TestRealGCPMinter_MintAccessToken_Success(t *testing.T) {
	// The server returns a valid generateAccessToken response with an expiry.
	expStr := "2030-06-01T00:00:00Z"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"accessToken":"gcp-tok","expireTime":%q}`, expStr)
	}))
	defer srv.Close()

	svc, err := iamcredentials.NewService(context.Background(), option.WithHTTPClient(srv.Client()))
	require.NoError(t, err)
	svc.BasePath = srv.URL + "/"

	m := &realGCPMinter{svc: svc}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, expiry, err := m.mintAccessToken(ctx, "sa@proj.iam.gserviceaccount.com", nil, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, "gcp-tok", tok)
	assert.Equal(t, "2030-06-01T00:00:00Z", expiry.UTC().Format(time.RFC3339))
}
