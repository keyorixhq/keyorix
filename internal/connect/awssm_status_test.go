//go:build !noaws

package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAWSSM_GetSecret_SuccessOnlyOn200 drives the real SDK client against a
// local server that answers every request with a complete, valid body and the
// given status. Secrets Manager answers GetSecretValue with 200 only, so any
// other 2xx must be refused even though the smithy client would accept it.
func TestAWSSM_GetSecret_SuccessOnlyOn200(t *testing.T) {
	const body = `{"ARN":"arn:aws:secretsmanager:us-east-1:123456789012:secret:app/db-AbCdEf","Name":"app/db","SecretString":"s3cr3t","VersionId":"v1"}`
	cases := []struct {
		status  int
		wantErr bool
	}{
		{http.StatusOK, false},
		{http.StatusCreated, true},
		{http.StatusAccepted, true},
		{http.StatusNoContent, true},
		{http.StatusPartialContent, true},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				w.WriteHeader(tc.status)
				if tc.status != http.StatusNoContent {
					_, _ = w.Write([]byte(body))
				}
			}))
			defer srv.Close()

			cl := secretsmanager.New(secretsmanager.Options{
				Region:       "us-east-1",
				Credentials:  credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "example-secret-key", ""),
				BaseEndpoint: aws.String(srv.URL),
				HTTPClient:   srv.Client(),
				Retryer:      aws.NopRetryer{},
			})
			c := NewAWSSecretsManagerConnector("t", "us-east-1", "", nil)
			c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return cl, nil }

			val, err := c.GetSecret(context.Background(), "app/db")
			if tc.wantErr {
				require.Error(t, err)
				assert.Empty(t, val)
				assert.Contains(t, err.Error(), "unexpected success status "+strconv.Itoa(tc.status))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "s3cr3t", val)
		})
	}
}

// TestAWSSM_GetSecret_NonOK2xxIsNotRetried pins that the refusal is final: with
// the SDK's standard retryer allowing 3 attempts, a 202 must reach the server
// exactly once (unexpectedSuccessStatusError.RetryableError() == false).
func TestAWSSM_GetSecret_NonOK2xxIsNotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"Name":"app/db","SecretString":"s3cr3t"}`))
	}))
	defer srv.Close()

	cl := secretsmanager.New(secretsmanager.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "example-secret-key", ""),
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
		Retryer:      retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 3 }),
	})
	c := NewAWSSecretsManagerConnector("t", "us-east-1", "", nil)
	c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return cl, nil }

	_, err := c.GetSecret(context.Background(), "app/db")
	require.Error(t, err)
	assert.EqualValues(t, 1, hits.Load(), "a refused 2xx must not be retried")
}
