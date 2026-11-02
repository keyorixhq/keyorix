package mcp

import (
	"strings"
	"testing"
)

// #3805: KEYORIX_URL can carry a token; the validation error names the host only.
func TestValidateKeyorixClientURL_ErrorsNeverCarryPathOrUserinfo(t *testing.T) {
	const secret = "tok-SECRET-123"
	for name, raw := range map[string]string{
		"plain http to a public host": "http://user:" + secret + "@keyorix.example.com/p/" + secret,
		"wrong scheme":                "ftp://keyorix.example.com/p/" + secret,
		"no host":                     "https:///p/" + secret,
		"unparseable":                 "https://keyorix.example.com/p/" + secret + "\x7f",
	} {
		err := validateKeyorixClientURL(raw)
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s leaks the URL: %v", name, err)
		}
	}
}
