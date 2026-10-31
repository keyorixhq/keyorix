package connect

import (
	"strings"
	"testing"
)

// A configured Vault address can carry userinfo or a ?token= query; the
// validation errors name the destination, so they must never echo either.
func TestValidateConnectorURL_ErrorsCarryNoCredentials(t *testing.T) {
	const secret = "S3CRET-LEAK-MARKER"
	cases := map[string]string{
		"bad scheme with userinfo and query": "ftp://admin:" + secret + "@vault.internal:8200/v1?token=" + secret,
		"missing host with query":            "https:///v1?token=" + secret,
		"unparsable, password in port":       "https://admin:" + secret + "/x@vault.internal:8200",
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateConnectorURL(addr)
			if err == nil {
				t.Fatalf("validateConnectorURL(%q) = nil, want an error", addr)
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
