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

package hardening

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// withFakeSetrlimit swaps setrlimitFn for the duration of the test and
// restores the real one on cleanup -- this must never depend on the CI
// host's actual limits posture.
func withFakeSetrlimit(t *testing.T, setrlimit func(int, *unix.Rlimit) error) {
	t.Helper()
	orig := setrlimitFn
	setrlimitFn = setrlimit
	t.Cleanup(func() { setrlimitFn = orig })
}

func TestApplyMemoryHardening_DisablesCoreDumps(t *testing.T) {
	var gotResource int
	var gotRlimit unix.Rlimit
	withFakeSetrlimit(t, func(resource int, rlim *unix.Rlimit) error {
		gotResource, gotRlimit = resource, *rlim
		return nil
	})

	require.NoError(t, ApplyMemoryHardening())
	assert.Equal(t, unix.RLIMIT_CORE, gotResource)
	assert.Equal(t, unix.Rlimit{Cur: 0, Max: 0}, gotRlimit, "Max must also be 0, not just Cur, or a later privileged action can raise it back")
}

func TestApplyMemoryHardening_CoreDumpDisableFailureIsFatal(t *testing.T) {
	withFakeSetrlimit(t, func(int, *unix.Rlimit) error { return errors.New("setrlimit boom") })

	err := ApplyMemoryHardening()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "setrlimit boom")
}
