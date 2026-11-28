package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCLIEmailAddress(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string // the address that must be sent; "" when an error is expected
		wantErr string
	}{
		{name: "plain", in: "alice@example.com", want: "alice@example.com"},
		{name: "surrounding space is trimmed", in: "  alice@example.com ", want: "alice@example.com"},
		{name: "plus tag", in: "alice+ops@example.com", want: "alice+ops@example.com"},
		{name: "quoted local part", in: quotedLocalPartEmail, wantErr: "--email must be a plain name@domain.tld address"},
		{name: "display name", in: "Alice <alice@example.com>", wantErr: "--email must be a plain name@domain.tld address"},
		{name: "not an address", in: "alice", wantErr: "--email is not a valid email address"},
		{name: "empty domain", in: "alice@", wantErr: "--email is not a valid email address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cliEmailAddress("email", tc.in, "")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("returned %q alongside an error", got)
				}
				if code, _ := classifyError(err, true); code != exitUsage {
					t.Fatalf("exit code = %d, want usage (%d)", code, exitUsage)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			b, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("returned address does not marshal: %v", err)
			}
			if string(b) != `"`+tc.want+`"` {
				t.Fatalf("sent %s, want %q", b, tc.want)
			}
		})
	}
}
