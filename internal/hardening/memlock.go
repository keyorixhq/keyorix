/*
Keyorix Server - Enterprise Secret Management System
Copyright (C) 2025 Keyorix Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

// Package hardening applies process-level memory hardening at server
// startup: locking pages against swap (mlockall) and disabling core dumps
// (RLIMIT_CORE=0). See docs/adr-098-process-memory-hardening.md for the
// design rationale and, importantly, what this does NOT protect against —
// the transient in-process exposure of decrypted secret values documented
// alongside #1653 remains, unchanged, by design.
package hardening

import (
	"fmt"
	"log"

	"golang.org/x/sys/unix"
)

// mlockallFn and setrlimitFn are indirections over the real syscalls, swapped
// out in tests so every branch below (success, failure-warns,
// failure-is-fatal, disabled) is exercised deterministically regardless of
// the test host's actual capabilities -- CI's CAP_IPC_LOCK/RLIMIT_MEMLOCK
// posture is not something a unit test should depend on.
var (
	mlockallFn  = unix.Mlockall
	setrlimitFn = unix.Setrlimit
)

// MemoryConfig is the subset of config.MlockConfig this package needs. It is
// a plain struct (not config.MlockConfig itself) so this package stays
// independently testable without importing internal/config.
type MemoryConfig struct {
	// Disabled opts out of the mlockall attempt. Core dump suppression is
	// unaffected by this field — see ApplyMemoryHardening's doc comment.
	Disabled bool
	// RequireSuccess makes a failed mlockall attempt fatal (ApplyMemoryHardening
	// returns a non-nil error) instead of a logged warning.
	RequireSuccess bool
}

// ApplyMemoryHardening disables core dumps and, unless disabled, locks the
// process's memory pages against swap. It must run once, as early as
// possible in process startup — before any key material or decrypted
// secret value is allocated — since mlockall(MCL_FUTURE) only covers pages
// mapped AFTER the call, and a core dump captures whatever is resident at
// the moment of the crash regardless of when RLIMIT_CORE was lowered.
//
// Core dump suppression is unconditional: lowering RLIMIT_CORE has no
// operator prerequisite and, unlike mlockall, essentially cannot fail for a
// process operating on its own limits, so there is no reason to gate it
// behind config. mlockall DOES have a real operator prerequisite
// (CAP_IPC_LOCK or a raised RLIMIT_MEMLOCK) and can fail on hosts that
// don't grant it — many containers don't — so it is opt-out via cfg.Disabled,
// and its failure mode (warn vs. fatal) is controlled by cfg.RequireSuccess,
// mirroring HashiCorp Vault's own mlock behavior (warn by default, can be
// configured to refuse to start).
//
// Every outcome — success, skipped-by-config, or failure — produces exactly
// one startup log line, so the operator never has to infer whether secret
// memory is protected: silent failure is the one unacceptable outcome here.
func ApplyMemoryHardening(cfg MemoryConfig) error {
	if err := disableCoreDumps(); err != nil {
		// Lowering a limit the process already holds essentially never
		// fails; if it does, that's a real, actionable misconfiguration
		// (not a missing-capability case like mlockall) — fail loud rather
		// than let the operator believe core dumps are off when they
		// aren't.
		return fmt.Errorf("hardening: disable core dumps: %w", err)
	}
	log.Printf("hardening: core dumps disabled (RLIMIT_CORE=0)")

	if cfg.Disabled {
		log.Printf("hardening: mlock disabled by config (security.mlock.disabled=true) -- " +
			"decrypted secret memory CAN be swapped to disk")
		return nil
	}

	if err := mlockallFn(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		msg := fmt.Sprintf("hardening: mlockall failed (%v) -- decrypted secret memory CAN be swapped "+
			"to disk. Grant CAP_IPC_LOCK or raise RLIMIT_MEMLOCK (systemd unit: LimitMEMLOCK=infinity) "+
			"to fix, or set security.mlock.disabled=true to silence this warning", err)
		if cfg.RequireSuccess {
			return fmt.Errorf("%s (refusing to start: security.mlock.require_success=true)", msg)
		}
		log.Printf("WARNING: %s", msg)
		return nil
	}

	log.Printf("hardening: mlockall succeeded -- process memory locked against swap")
	return nil
}

func disableCoreDumps() error {
	return setrlimitFn(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
