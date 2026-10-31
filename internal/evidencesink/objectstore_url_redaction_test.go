//go:build !lean && !noaws

package evidencesink

import (
	"strings"
	"testing"
)

// #3805: an object-store endpoint can carry a token; the validation error names the host only.
func TestValidateObjectStoreEndpoint_ErrorsNeverCarryPathOrUserinfo(t *testing.T) {
	const secret = "tok-SECRET-123"
	for name, raw := range map[string]string{
		"wrong scheme": "ftp://s3.example.com/b/" + secret,
		"no host":      "https:///b/" + secret,
		"unparseable":  "https://s3.example.com/b/" + secret + "\x7f",
	} {
		_, err := validateObjectStoreEndpoint(raw)
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s leaks the URL: %v", name, err)
		}
	}
}
