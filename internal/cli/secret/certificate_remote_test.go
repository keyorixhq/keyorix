package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchCertificate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets/7/certificate" {
			_, _ = w.Write([]byte(`{"data":{"secret_id":7,"secret_name":"tls-cert","subject":"CN=example.com","issuer":"CN=example.com","serial_number":"4242","not_before":"2025-06-23T00:00:00Z","not_after":"2026-09-21T00:00:00Z","days_until_expiry":90,"is_expired":false,"is_ca":false,"self_signed":true,"dns_names":["example.com"],"signature_algorithm":"ECDSA-SHA256","public_key_algorithm":"ECDSA"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	var v certView
	require.NoError(t, rc.Get(context.Background(), "/api/v1/secrets/7/certificate", &v))
	assert.Equal(t, "tls-cert", v.SecretName)
	assert.Equal(t, "CN=example.com", v.Subject)
	assert.True(t, v.SelfSigned)
	assert.Equal(t, 90, v.DaysUntilExpiry)
	assert.Equal(t, []string{"example.com"}, v.DNSNames)
}
