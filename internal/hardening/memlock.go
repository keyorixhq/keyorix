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
// startup: disabling core dumps (RLIMIT_CORE=0). See
// docs/adr-098-process-memory-hardening.md for the original design (mlock +
// core dump suppression) and docs/adr-100-mlockall-removal-deployment-swap-control.md
// for why the mlockall half was removed (measured to pin gigabytes of RSS
// with no ceiling on the shipped 512Mi Helm default, and to be structurally
// incompatible with a garbage-collected runtime — the GC moves and copies
// memory, so locking one buffer's address does not protect the copies the
// runtime scatters elsewhere). Core dump suppression is unaffected: it has
// no such gap and stays.
package hardening

import (
	"fmt"
	"log"

	"golang.org/x/sys/unix"
)

// setrlimitFn is an indirection over the real syscall, swapped out in tests
// so the failure branch is exercised deterministically regardless of the
// test host's actual limits posture.
var setrlimitFn = unix.Setrlimit

// ApplyMemoryHardening disables core dumps. It must run once, as early as
// possible in process startup — before any key material or decrypted secret
// value is allocated — since a core dump captures whatever is resident at
// the moment of the crash regardless of when RLIMIT_CORE was lowered.
//
// Lowering RLIMIT_CORE has no operator prerequisite and, unlike the mlockall
// step this function previously also performed (see the package doc
// comment), essentially cannot fail for a process operating on its own
// limits — so failure here is always fatal, not a warning.
func ApplyMemoryHardening() error {
	if err := disableCoreDumps(); err != nil {
		// Lowering a limit the process already holds essentially never
		// fails; if it does, that's a real, actionable misconfiguration —
		// fail loud rather than let the operator believe core dumps are
		// off when they aren't.
		return fmt.Errorf("hardening: disable core dumps: %w", err)
	}
	log.Printf("hardening: core dumps disabled (RLIMIT_CORE=0)")
	return nil
}

func disableCoreDumps() error {
	return setrlimitFn(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
