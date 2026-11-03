package dynamic

import (
	"strings"
	"testing"
)

// A configured api_server can carry userinfo or a query; validateAPIServerHost's
// errors name the destination and must not echo either.
func TestValidateAPIServerHost_ErrorsCarryNoCredentials(t *testing.T) {
	const secret = "S3CRET-LEAK-MARKER"
	cases := map[string]string{
		"not https":      "http://admin:" + secret + "@k8s.internal:6443/?token=" + secret,
		"missing host":   "https:///?token=" + secret,
		"unparsable url": "https://admin:" + secret + "/x@k8s.internal:6443",
	}
	for name, host := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateAPIServerHost(host)
			if err == nil {
				t.Fatalf("validateAPIServerHost(%q) = nil, want an error", host)
			}
			msg := err.Error()
			for _, leaked := range []string{secret, "admin", "token=", "?"} {
				if strings.Contains(msg, leaked) {
					t.Errorf("error %q contains %q", msg, leaked)
				}
			}
		})
	}
}
