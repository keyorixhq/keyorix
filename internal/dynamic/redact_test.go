package dynamic

import (
	"errors"
	"strings"
	"testing"
)

func TestRedactSensitive_URLUserinfo(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"postgres dsn", `failed to connect to "postgres://admin:hunter2@db.internal:5432/app": dial tcp: connection refused`},
		{"mysql dsn", `parse error: mysql://root:s3cr3t@10.0.0.5:3306/mydb`},
		{"mongodb dsn", `connstring: mongodb://svc_acct:p@ssnotreally@cluster0.mongo.net/admin`},
		{"redis tls dsn", `dial error: rediss://default:topsecret@cache.example.com:6380`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSensitive(tc.input)
			if strings.Contains(got, "hunter2") || strings.Contains(got, "s3cr3t") ||
				strings.Contains(got, "p@ssnotreally") || strings.Contains(got, "topsecret") {
				t.Fatalf("RedactSensitive(%q) = %q, still contains a credential", tc.input, got)
			}
			if !strings.Contains(got, redactedPlaceholder) {
				t.Fatalf("RedactSensitive(%q) = %q, expected redaction placeholder", tc.input, got)
			}
		})
	}
}

func TestRedactSensitive_KeyValueCredentials(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"odbc pwd", `Server=db1;Uid=admin;Pwd=hunter2;Database=app`},
		{"query password", `bad request to https://api.example.com/x?user=svc&password=hunter2&region=us`},
		{"secret kv", `config error: secret=abc123XYZ is invalid`},
		{"access key", `AccessDenied: access_key_id=AKIAEXAMPLE access_key=abcdefghijklmnop`},
		{"case insensitive PASSWORD", `PASSWORD=hunter2;other=1`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSensitive(tc.input)
			for _, secret := range []string{"hunter2", "abc123XYZ", "AKIAEXAMPLE", "abcdefghijklmnop"} {
				if strings.Contains(got, secret) {
					t.Fatalf("RedactSensitive(%q) = %q, still contains credential %q", tc.input, got, secret)
				}
			}
		})
	}
}

func TestRedactSensitive_PreservesNonSensitiveText(t *testing.T) {
	input := "connection refused: SQLSTATE 08006, no pg_hba.conf entry for host"
	got := RedactSensitive(input)
	if got != input {
		t.Fatalf("RedactSensitive altered non-sensitive text: got %q, want %q", got, input)
	}
}

func TestSanitizeErrorMessage_NilError(t *testing.T) {
	if got := SanitizeErrorMessage(nil); got != "" {
		t.Fatalf("SanitizeErrorMessage(nil) = %q, want empty string", got)
	}
}

func TestSanitizeErrorMessage_RedactsWrappedError(t *testing.T) {
	inner := errors.New(`dial postgres://admin:hunter2@10.0.0.9:5432/app: i/o timeout`)
	wrapped := errors.New("issue credential: " + inner.Error())
	got := SanitizeErrorMessage(wrapped)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("SanitizeErrorMessage(%v) = %q, still contains the password", wrapped, got)
	}
	if !strings.Contains(got, "issue credential") {
		t.Fatalf("SanitizeErrorMessage(%v) = %q, lost non-sensitive context", wrapped, got)
	}
}
