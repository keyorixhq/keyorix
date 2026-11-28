//go:build e2e

package e2e

import (
	"reflect"
	"testing"
)

// The upgrade leg provisions with the OLD release binary, over plain HTTP. A
// binary with --dev writes the TLS baseline without it (v0.96.3 does), so the
// flag must be passed whenever the binary advertises it, and only then (a
// release that predates the flag rejects an unknown one).
func TestInitArgsForHelp(t *testing.T) {
	const cfg = "./keyorix.yaml"
	withDev := "Usage:\n  keyorix-server admin init [flags]\n\nFlags:\n      --dev   Write the relaxed DEV-ONLY config\n  -h, --help  help for init\n"
	noDev := "Usage:\n  keyorix-server admin init [flags]\n\nFlags:\n  -h, --help  help for init\n"

	if got, want := initArgsForHelp(withDev, cfg), []string{"init", "--dev", "--config", cfg}; !reflect.DeepEqual(got, want) {
		t.Errorf("binary with --dev: got %v, want %v", got, want)
	}
	if got, want := initArgsForHelp(noDev, cfg), []string{"init", "--config", cfg}; !reflect.DeepEqual(got, want) {
		t.Errorf("binary without --dev: got %v, want %v", got, want)
	}
}
