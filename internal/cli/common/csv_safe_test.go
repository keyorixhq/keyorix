package common

import "testing"

func TestCSVSafe(t *testing.T) {
	cases := map[string]string{
		"":                         "",
		"db-password":              "db-password",
		"=HYPERLINK(\"http://x\")": "'=HYPERLINK(\"http://x\")",
		"+1+1":                     "'+1+1",
		"-2+3":                     "'-2+3",
		"@SUM(A1)":                 "'@SUM(A1)",
		"\tlead-tab":               "'\tlead-tab",
		"normal=mid":               "normal=mid", // only a LEADING formula char is defanged
	}
	for in, want := range cases {
		if got := CSVSafe(in); got != want {
			t.Errorf("CSVSafe(%q) = %q, want %q", in, got, want)
		}
	}
}
