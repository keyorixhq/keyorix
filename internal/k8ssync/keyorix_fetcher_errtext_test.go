package k8ssync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Server-controlled bytes must never reach an error returned by Fetch or
// FetchWithExpiry (#4062). encoding/json and time.Time put the offending input into
// their own error texts (`parsing time "<input>"`, `cannot unmarshal number <n>`), so
// a decode failure has to be reported without wrapping the decoder's error.
func TestKeyorixFetcher_ServerFieldsNeverReachErrorText(t *testing.T) {
	const canary = "CANARY4062"
	cases := map[string]string{
		"expiration not a time": `{"data":{"value":"v","secret":{"expiration":"` + canary + `"}}}`,
		"value wrong type":      `{"data":{"value":{"` + canary + `":1}}}`,
		"expiration wrong type": `{"data":{"value":"v","secret":{"expiration":{"` + canary + `":1}}}}`,
		"not json":              canary + canary,
		"data not an object":    `{"data":"` + canary + `"}`,
	}
	for name, valueBody := range cases {
		for _, via := range []string{"FetchWithExpiry", "Fetch"} {
			t.Run(name+"/"+via, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case strings.HasSuffix(r.URL.Path, "/environments"):
						_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":3,"Name":"prod"}]}}`))
					case r.URL.Path == "/api/v1/secrets":
						_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":7,"Name":"db"}],"total_pages":1}}`))
					default:
						_, _ = w.Write([]byte(valueBody))
					}
				}))
				defer srv.Close()

				f := NewKeyorixFetcher(srv.URL, "tok", 1)
				var err error
				if via == "Fetch" {
					_, err = f.Fetch(context.Background(), "prod/db")
				} else {
					_, _, err = f.FetchWithExpiry(context.Background(), "prod/db")
				}
				if err == nil {
					t.Fatalf("expected an error")
				}
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("server-controlled text reached the error: %v", err)
				}
			})
		}
	}
}
