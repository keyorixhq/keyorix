package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden test of the "config" line of `keyorix doctor`: where the token came from, for every
// source, and what a bad KEYORIX_TOKEN_FILE looks like. The wording is part of the CLI's
// output (scripts and the docs quote it), so refactoring how the label is derived must not
// change it, and no case may print the token.
func TestDoctor_ConfigTokenLabelGolden(t *testing.T) {
	const srv = "http://127.0.0.1:1" // the config check does not contact the server
	cases := []struct {
		name       string
		setup      func(t *testing.T)
		wantStatus string
		wantDetail string
	}{
		{"no token", func(t *testing.T) {}, doctorPass,
			"server http://127.0.0.1:1 (from KEYORIX_SERVER); no token"},
		{"token from KEYORIX_TOKEN", func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN", tokenFileCanary)
		}, doctorPass,
			"server http://127.0.0.1:1 (from KEYORIX_SERVER); token from KEYORIX_TOKEN"},
		{"token from KEYORIX_TOKEN_FILE", func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o600, tokenFileCanary+"\n"))
		}, doctorPass,
			"server http://127.0.0.1:1 (from KEYORIX_SERVER); token from KEYORIX_TOKEN_FILE"},
		{"token from the credentials file", func(t *testing.T) {
			store, err := resolveCredStore()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(store.Path()), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(store.Path(), []byte("server_url: "+srv+"\ntoken: "+tokenFileCanary+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, doctorPass,
			"server http://127.0.0.1:1 (from KEYORIX_SERVER); token from the credentials file"},
		{"token file too permissive", func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o644, tokenFileCanary))
		}, doctorFail, "cannot read the token: KEYORIX_TOKEN_FILE"},
		{"token file unreadable", func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN_FILE", filepath.Join(t.TempDir(), "nope"))
		}, doctorFail, "cannot read the token: KEYORIX_TOKEN_FILE"},
		{"token file empty", func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o600, "\n"))
		}, doctorFail, "cannot read the token: KEYORIX_TOKEN_FILE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			useServer(t, srv, "")
			t.Setenv("KEYORIX_TOKEN", "")
			t.Setenv("KEYORIX_TOKEN_FILE", "")
			c.setup(t)
			rep := runDoctorReport(t)
			got := rep.check(t, "config")
			if got.Status != c.wantStatus {
				t.Errorf("status %q, want %q (%+v)", got.Status, c.wantStatus, got)
			}
			if c.wantStatus == doctorPass {
				if got.Detail != c.wantDetail {
					t.Errorf("detail\n got: %q\nwant: %q", got.Detail, c.wantDetail)
				}
			} else if !strings.HasPrefix(got.Detail, c.wantDetail) || !strings.Contains(got.NextStep, "KEYORIX_TOKEN_FILE") {
				t.Errorf("a bad token file must be named, with a way out: %+v", got)
			}
			for _, ch := range rep.Checks {
				if strings.Contains(ch.Detail, tokenFileCanary) || strings.Contains(ch.NextStep, tokenFileCanary) {
					t.Errorf("check %q printed the token: %+v", ch.Name, ch)
				}
			}
		})
	}
}
