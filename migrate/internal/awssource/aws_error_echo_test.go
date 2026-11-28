package awssource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// echoCanary stands for a real secret value: it is returned as GetSecretValue's body in a
// shape the SDK cannot decode, which makes the SDK put the offending text in its error.
const echoCanary = "kx-aws-echo-canary-5b2c91"

// TestList_SDKErrorDoesNotEchoResponseBody pins the error text List returns when the
// endpoint answers a call with a body the SDK cannot decode (KFZ-2026-191). The SDK's
// deserialization error quotes the body, and for GetSecretValue that body is the secret
// value: List must report the status only. The assertion is on the returned error text
// (the effect), with a positive check that the status is still reported.
func TestList_SDKErrorDoesNotEchoResponseBody(t *testing.T) {
	for _, tc := range []struct{ name, target string }{
		{"GetSecretValue", "secretsmanager.GetSecretValue"},
		{"ListSecrets", "secretsmanager.ListSecrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				switch r.Header.Get("X-Amz-Target") {
				case "secretsmanager.ListSecrets":
					if tc.target == "secretsmanager.ListSecrets" {
						_, _ = w.Write([]byte(`"` + echoCanary + `"`))
						return
					}
					_, _ = w.Write([]byte(`{"SecretList":[{"Name":"team/db"}]}`))
				case "secretsmanager.GetSecretValue":
					_, _ = w.Write([]byte(`"` + echoCanary + `"`))
				default:
					http.Error(w, "unexpected target", http.StatusBadRequest)
				}
			}))
			defer srv.Close()

			c := New(Config{Region: "us-east-1"})
			c.newClient = func(context.Context) (smAPI, error) {
				return secretsmanager.New(secretsmanager.Options{
					Region:           "us-east-1",
					BaseEndpoint:     aws.String(srv.URL),
					Credentials:      staticCreds{},
					HTTPClient:       srv.Client(),
					RetryMaxAttempts: 1,
				}), nil
			}
			_, _, err := c.List(t.Context())
			if err == nil {
				t.Fatal("List succeeded against an undecodable response")
			}
			if strings.Contains(err.Error(), echoCanary) {
				t.Fatalf("the response body was echoed into the returned error: %v", err)
			}
			if !strings.Contains(err.Error(), "status 200") {
				t.Fatalf("the status is no longer reported: %v", err)
			}
		})
	}
}

func realClientFor(url string) func(context.Context) (smAPI, error) {
	return func(context.Context) (smAPI, error) {
		return secretsmanager.New(secretsmanager.Options{
			Region:           "us-east-1",
			BaseEndpoint:     aws.String(url),
			Credentials:      staticCreds{},
			HTTPClient:       &http.Client{Timeout: 5 * time.Second},
			RetryMaxAttempts: 1,
		}), nil
	}
}

// TestList_TransportFailuresStayDiagnosable: the SDK wraps send failures in a response error
// with status 0, so the status-only rule must not flatten them. A refused connection keeps its
// cause, and a deadline keeps errors.Is(context.DeadlineExceeded).
func TestList_TransportFailuresStayDiagnosable(t *testing.T) {
	t.Run("connection refused keeps its cause", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close() // nothing listens any more
		c := New(Config{Region: "us-east-1"})
		c.newClient = realClientFor(url)
		_, _, err := c.List(t.Context())
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("a refused connection must stay diagnosable, got: %v", err)
		}
	})
	t.Run("deadline keeps errors.Is", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		defer srv.Close()
		defer close(release)
		c := New(Config{Region: "us-east-1"})
		c.newClient = realClientFor(srv.URL)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		_, _, err := c.List(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("errors.Is(err, DeadlineExceeded) lost: %v", err)
		}
	})
}
