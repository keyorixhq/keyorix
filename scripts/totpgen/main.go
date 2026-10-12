//go:build ignore

// totpgen computes the current TOTP code for a base32 secret, the way a
// human would read a code off an authenticator app -- for test/CI harnesses
// (scripts/smoke.sh and any other e2e script that must enrol and activate
// MFA for a bootstrap admin non-interactively) that have no human to prompt.
// Deliberately NOT part of the shipped keyorix/keyorix-server binaries or
// any `go build ./...` target (see the //go:build ignore tag above,
// matching scripts/fuzzing/autofuzzgen/main.go's precedent) -- real users
// get their code from their own authenticator app; this exists only to
// stand in for that app in automated testing.
//
// Usage: go run scripts/totpgen/main.go <base32-secret> [step-offset-seconds]
//
// step-offset-seconds (default 0) shifts which 30s time-step the code is
// computed for -- e.g. 30 for "the next step after now." Needed because
// ActivateMFA marks the TOTP step its activation code matched as used
// (anti-replay, internal/core/mfa.go); a caller that enrols, activates, and
// then immediately logs in again within the same real-world 30s window
// would otherwise compute the IDENTICAL code for both calls and have the
// second one rejected as a replay.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 || os.Args[1] == "" {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/totpgen/main.go <base32-secret> [step-offset-seconds]")
		os.Exit(1)
	}
	offset := 0
	if len(os.Args) == 3 {
		o, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "totpgen: invalid step-offset-seconds:", err)
			os.Exit(1)
		}
		offset = o
	}
	code, err := totp.GenerateCode(os.Args[1], time.Now().Add(time.Duration(offset)*time.Second))
	if err != nil {
		fmt.Fprintln(os.Stderr, "totpgen:", err)
		os.Exit(1)
	}
	fmt.Println(code)
}
