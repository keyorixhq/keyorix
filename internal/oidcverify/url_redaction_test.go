package oidcverify

import (
	"strings"
	"testing"
)

// #3805: a jwks_uri can carry a token; the scheme-validation error names the host only.
func TestValidateJWKSScheme_ErrorsNeverCarryPathOrUserinfo(t *testing.T) {
	const secret = "tok-SECRET-123"
	for name, raw := range map[string]string{
		"plain http to a public host": "http://user:" + secret + "@idp.example.com/jwks?key=" + secret,
		"wrong scheme":                "ftp://idp.example.com/jwks?key=" + secret,
		"unparseable":                 "https://idp.example.com/jwks?key=" + secret + "\x7f",
	} {
		err := validateJWKSScheme(raw)
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s leaks the URL: %v", name, err)
		}
	}
}
