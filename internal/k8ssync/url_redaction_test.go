package k8ssync

import (
	"strings"
	"testing"
)

// #3805: a configured keyorix_url can carry a token (userinfo, a path token or
// ?key=); the validation errors name the host only.
func TestKeyorixURLValidationErrors_NeverCarryPathOrUserinfo(t *testing.T) {
	const secret = "tok-SECRET-123"
	for name, raw := range map[string]string{
		"plain http to a public host": "http://user:" + secret + "@keyorix.example.com/p/" + secret,
		"wrong scheme":                "ftp://keyorix.example.com/p/" + secret,
		"no host":                     "https:///p/" + secret,
		"unparseable":                 "https://keyorix.example.com/p/" + secret + "\x7f",
	} {
		for fn, validate := range map[string]func(string) error{
			"validateKeyorixURL":     validateKeyorixURL,
			"validateFetcherBaseURL": validateFetcherBaseURL,
		} {
			err := validate(raw)
			if err == nil {
				t.Errorf("%s/%s: want an error", fn, name)
				continue
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s/%s leaks the URL: %v", fn, name, err)
			}
		}
	}
}
