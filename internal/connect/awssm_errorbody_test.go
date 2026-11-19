//go:build !noaws

package connect

// awssm_errorbody_test.go — measures allocations when AWSSecretsManagerConnector.GetSecret
// receives hostile response bodies (deeply nested, large, or on unexpected status codes).
// Mirrors azurekv_errorbody_test.go's approach and verifies the O4 bounded-work oracle
// (256 MiB + 16 × bytes-on-wire) holds for all tested shapes. This protects against a
// regression to the Azure-class amplification: a hostile ~40 KB deeply-nested body
// allocated ~574 MiB before errorBodyScrubRoundTripper was added for Azure.
//
// What this test does NOT cover: the smithy-go JSON deserializer's allocation behaviour
// for success (200) responses with hostile bodies beyond the 1 MiB size cap — that path
// is exercised by FuzzAWSSMHostileEndpoint (O4 oracle there); this test focuses on the
// error-status and 2xx-non-200 paths that are structurally different from success.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// awssmNestedBody returns a JSON body with the given depth of `[` nesting.
// A depth of 20000 produces a ~20 KB body — the same shape that caused
// ~574 MiB of allocations in the Azure connector before the fix.
func awssmNestedBody(depth int) string {
	return strings.Repeat("[", depth) + "1" + strings.Repeat("]", depth)
}

// awssmNestedObjBody returns a JSON body with depth levels of `{"Code":...}` nesting.
// This exercises the ProtocolErrorInfo.Code (type any) field in the SDK's error decoder,
// which is the most likely amplification path for the awsJson1_1 error deserializer.
func awssmNestedObjBody(depth int) string {
	return strings.Repeat(`{"Code":`, depth) + `1` + strings.Repeat(`}`, depth)
}

// awssmO4Budget is the O4 oracle limit: 256 MiB + 16 × bytes-written.
// For a body of n bytes: limit = 256<<20 + 16*n.
func awssmO4Budget(bodyBytes int) uint64 {
	return uint64(256<<20) + 16*uint64(bodyBytes) // #nosec G115
}

// awssmHardenedClient builds the real secretsmanager.Client with the SAME
// hardened transport production installs (awssm.go:client), pointed at srv.
func awssmHardenedClient(srv *httptest.Server) *secretsmanager.Client {
	return secretsmanager.New(secretsmanager.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "example-secret-key", ""),
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient: &http.Client{
			Transport:     newConnectHardenedTransport(awsBaseTransport()),
			CheckRedirect: refuseRedirect,
		},
		Retryer: aws.NopRetryer{},
	})
}

// TestAWSSM_NestedErrorBodyDoesNotAmplifyMemory measures allocations for a range of
// hostile response bodies and asserts the O4 oracle (256 MiB + 16 × wire-bytes).
// It also records a measurement table (printed on -v) so a human can inspect the
// actual amplification factors.
func TestAWSSM_NestedErrorBodyDoesNotAmplifyMemory(t *testing.T) {
	type cas struct {
		name   string
		status int
		body   string
	}
	const depth20k = 20000
	const depth100k = 100000

	body20kArr := awssmNestedBody(depth20k)    // ~20 KB array nesting
	body20kObj := awssmNestedObjBody(depth20k) // ~20 KB object nesting {"Code":{...}}
	body1mib := strings.Repeat("A", 1<<20)     // 1 MiB flat body (at the size cap)
	bodyManyKeys := func() string {            // body with many repeated top-level keys
		var sb strings.Builder
		sb.WriteString("{")
		for i := range 10000 {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `"k%d":"v"`, i)
		}
		sb.WriteString("}")
		return sb.String()
	}()

	cases := []cas{
		// --- error statuses with deep nesting ---
		{name: "400/array-20k", status: 400, body: body20kArr},
		{name: "500/array-20k", status: 500, body: body20kArr},
		{name: "502/array-20k", status: 502, body: body20kArr},
		{name: "400/obj-20k", status: 400, body: body20kObj},
		{name: "500/obj-20k", status: 500, body: body20kObj},
		// --- 100k depth (would be ~100 KB; still under size cap) ---
		{name: "400/array-100k", status: 400, body: awssmNestedBody(depth100k)},
		{name: "400/obj-100k", status: 400, body: awssmNestedObjBody(depth100k)},
		// --- 2xx non-200: body must be closed before SDK parses it ---
		{name: "201/array-20k", status: 201, body: body20kArr},
		{name: "202/array-20k", status: 202, body: body20kArr},
		{name: "204/no-body", status: 204, body: ""},
		// --- 1 MiB body at the size cap ---
		{name: "400/1mib-flat", status: 400, body: body1mib},
		{name: "500/1mib-flat", status: 500, body: body1mib},
		// --- many repeated keys ---
		{name: "400/many-keys", status: 400, body: bodyManyKeys},
	}

	t.Log("case | wire-bytes | alloc-bytes | amplification | pass-O4")
	t.Log("-----|-----------|-------------|---------------|--------")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				w.WriteHeader(tc.status)
				if tc.body != "" {
					_, _ = w.Write([]byte(tc.body))
				}
			}))
			defer srv.Close()

			cl := awssmHardenedClient(srv)
			c := NewAWSSecretsManagerConnector("t", "us-east-1", "", nil)
			c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return cl, nil }

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, err := c.GetSecret(t.Context(), "fuzz/secret")
			runtime.ReadMemStats(&after)

			if err == nil {
				t.Fatalf("expected an error for status %d, got success", tc.status)
			}

			wireBytes := len(tc.body)
			allocBytes := after.TotalAlloc - before.TotalAlloc
			budget := awssmO4Budget(wireBytes)
			var ampFactor float64
			if wireBytes > 0 {
				ampFactor = float64(allocBytes) / float64(wireBytes)
			}
			passO4 := allocBytes <= budget

			t.Logf("%-25s | %10d | %11d | %13.1fx | %v",
				tc.name, wireBytes, allocBytes, ampFactor, passO4)

			if !passO4 {
				t.Errorf("O4 BOUNDED-WORK: status %d, body %d bytes: allocated %d bytes, budget %d (256 MiB + 16×wire)",
					tc.status, wireBytes, allocBytes, budget)
			}
		})
	}
}

// TestAWSSM_Non200TwoxxBodyIsNotParsedBySDK verifies that for 2xx non-200 responses,
// the body is closed by status200Client before the SDK's deserializeError path runs.
// A large allocation here would indicate status200Client is not intercepting correctly.
func TestAWSSM_Non200TwoxxBodyIsNotParsedBySDK(t *testing.T) {
	body := awssmNestedObjBody(20000) // ~20 KB deeply nested

	for _, status := range []int{201, 202, 203, 204, 206} {
		t.Run(fmt.Sprintf("status-%d", status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				w.WriteHeader(status)
				if status != 204 {
					_, _ = w.Write([]byte(body))
				}
			}))
			defer srv.Close()

			cl := awssmHardenedClient(srv)
			c := NewAWSSecretsManagerConnector("t", "us-east-1", "", nil)
			c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return cl, nil }

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, err := c.GetSecret(t.Context(), "fuzz/secret")
			runtime.ReadMemStats(&after)

			if err == nil {
				t.Fatalf("status %d: expected an error", status)
			}
			// Verify the error is unexpectedSuccessStatusError (body was intercepted
			// before SDK parsing), not an SDK deserialization error.
			if !strings.Contains(err.Error(), "unexpected success status") {
				t.Errorf("status %d: expected unexpectedSuccessStatusError, got: %v", status, err)
			}

			allocBytes := after.TotalAlloc - before.TotalAlloc
			wireBytes := len(body)
			if status == 204 {
				wireBytes = 0
			}
			budget := awssmO4Budget(wireBytes)
			if allocBytes > budget {
				t.Errorf("O4 violated for 2xx non-200 status %d: alloc %d > budget %d", status, allocBytes, budget)
			}
			// A 2xx non-200 body should never be parsed: allocations should be small
			// (well under 1 MiB, mostly HTTP transport overhead). If this exceeds
			// 2 MiB the status200Client intercept is not working.
			const maxExpected = 2 << 20
			if allocBytes > maxExpected {
				t.Errorf("status %d: alloc %d bytes suggests body was parsed (budget for intercept = %d)",
					status, allocBytes, maxExpected)
			}
		})
	}
}
