//go:build !noazure

package connect

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// A 2xx other than 200 is not scrubbed by errorBodyScrubRoundTripper (it only
// rewrites error statuses) and azsecrets reports it as a *azcore.ResponseError whose
// Error() text embeds the response headers and body verbatim. GetSecret must turn
// that into a fixed message plus the status code (#4061).
func TestAzureKV_Non200SuccessReplyDoesNotEchoServerText(t *testing.T) {
	const marker = "LEAKMARKER-4061"
	for _, status := range []int{201, 202, 203, 206} {
		hdr := http.Header{}
		hdr.Set("X-Ms-Marker", marker)
		hdr.Set("Content-Type", "application/json")
		cl := azureClientAgainst(t, status, hdr, `{"error":{"code":"`+marker+`","message":"`+marker+`"}}`)
		c := NewAzureKeyVaultConnector("kv", "https://kv.example", nil)
		c.newClient = func(context.Context) (azSecretGetter, error) { return cl, nil }
		_, err := c.GetSecret(context.Background(), "name")
		if err == nil {
			t.Fatalf("status %d: expected an error", status)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("status %d: server-controlled text reached the error: %v", status, err)
		}
		if !strings.Contains(err.Error(), strconv.Itoa(status)) {
			t.Fatalf("status %d: status code missing from error: %v", status, err)
		}
	}
}
