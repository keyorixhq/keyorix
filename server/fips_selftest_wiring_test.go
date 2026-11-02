package main

import (
	"os"
	"strings"
	"testing"
)

// TestMain_RunsFIPSSelfTestBeforeKeysAreLoaded pins the boot hook of
// INV-ENCRYPTION-fips140-boot-self-test: main() calls
// encryption.BootFIPSSelfTest, refuses to start on its error, and does so before
// runStartupValidation (the first step that touches key files). A source check,
// because main() cannot be driven in-process; it does not prove the call is
// reachable on every boot path, only that it sits in main() ahead of that step.
func TestMain_RunsFIPSSelfTestBeforeKeysAreLoaded(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	mainAt := strings.Index(s, "\nfunc main() {")
	hook := strings.Index(s, "if err := encryption.BootFIPSSelfTest(); err != nil {\n\t\tlog.Fatalf(")
	validate := strings.Index(s, "runStartupValidation(cfg)")
	if mainAt < 0 || hook < 0 || validate < 0 {
		t.Fatalf("main.go: func main at %d, BootFIPSSelfTest+log.Fatalf at %d, runStartupValidation at %d; want all present", mainAt, hook, validate)
	}
	if hook < mainAt || hook > validate {
		t.Fatalf("BootFIPSSelfTest (offset %d) must be inside main() (offset %d) and before runStartupValidation (offset %d)", hook, mainAt, validate)
	}
}
