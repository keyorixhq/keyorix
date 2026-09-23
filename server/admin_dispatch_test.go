package main

import "testing"

// TestIsAdminDispatch pins the exact routing decision ADR-108 §B (PR 11)
// depends on: only `os.Args[1] == "admin"` diverts to `server/admin`, so the
// plain `keyorix-server` flag set (--passphrase-fd/--passphrase-file/
// --passphrase-stdin) and startup sequence stay reachable, byte-for-byte
// unchanged, for every other invocation shape.
func TestIsAdminDispatch(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"no args", []string{"keyorix-server"}, false},
		{"admin subcommand", []string{"keyorix-server", "admin"}, true},
		{"admin subcommand with args", []string{"keyorix-server", "admin", "init", "--config", "x.yaml"}, true},
		{"passphrase-fd flag", []string{"keyorix-server", "-passphrase-fd", "3"}, false},
		{"passphrase-stdin flag", []string{"keyorix-server", "-passphrase-stdin"}, false},
		{"long-form passphrase flag", []string{"keyorix-server", "--passphrase-file", "/run/secrets/pw"}, false},
		{"unrelated first arg", []string{"keyorix-server", "-admin"}, false},
		{"help flag", []string{"keyorix-server", "-h"}, false},
		{"admin-looking but not exact", []string{"keyorix-server", "administrate"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAdminDispatch(tc.args); got != tc.want {
				t.Errorf("isAdminDispatch(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}
