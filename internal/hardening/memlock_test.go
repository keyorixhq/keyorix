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

// withFakeSyscalls swaps mlockallFn/setrlimitFn for the duration of the test
// and restores the real ones on cleanup -- these tests must never depend on
// the CI host's actual CAP_IPC_LOCK/RLIMIT_MEMLOCK posture, which is
// unpredictable and would make the failure-path branches flaky.
func withFakeSyscalls(t *testing.T, mlockall func(int) error, setrlimit func(int, *unix.Rlimit) error) {
	t.Helper()
	origMlockall, origSetrlimit := mlockallFn, setrlimitFn
	mlockallFn, setrlimitFn = mlockall, setrlimit
	t.Cleanup(func() { mlockallFn, setrlimitFn = origMlockall, origSetrlimit })
}

func TestApplyMemoryHardening_CoreDumpsAlwaysDisabledRegardlessOfMlockConfig(t *testing.T) {
	for _, cfg := range []MemoryConfig{
		{Disabled: false, RequireSuccess: false},
		{Disabled: true, RequireSuccess: false},
		{Disabled: true, RequireSuccess: true},
	} {
		var gotResource int
		var gotRlimit unix.Rlimit
		withFakeSyscalls(t,
			func(int) error { return nil },
			func(resource int, rlim *unix.Rlimit) error {
				gotResource, gotRlimit = resource, *rlim
				return nil
			},
		)

		require.NoError(t, ApplyMemoryHardening(cfg))
		assert.Equal(t, unix.RLIMIT_CORE, gotResource, "cfg=%+v", cfg)
		assert.Equal(t, unix.Rlimit{Cur: 0, Max: 0}, gotRlimit, "cfg=%+v -- Max must also be 0, not just Cur, or a later privileged action can raise it back", cfg)
	}
}

func TestApplyMemoryHardening_CoreDumpDisableFailureIsAlwaysFatal(t *testing.T) {
	withFakeSyscalls(t,
		func(int) error {
			t.Fatal("mlockall must not be attempted when core-dump suppression itself failed")
			return nil
		},
		func(int, *unix.Rlimit) error { return errors.New("setrlimit boom") },
	)

	err := ApplyMemoryHardening(MemoryConfig{Disabled: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "setrlimit boom")
}

func TestApplyMemoryHardening_DisabledSkipsMlockallEntirely(t *testing.T) {
	mlockallCalled := false
	withFakeSyscalls(t,
		func(int) error { mlockallCalled = true; return nil },
		func(int, *unix.Rlimit) error { return nil },
	)

	require.NoError(t, ApplyMemoryHardening(MemoryConfig{Disabled: true}))
	assert.False(t, mlockallCalled, "security.mlock.disabled=true must skip the mlockall attempt entirely, not just ignore its result")
}

func TestApplyMemoryHardening_SuccessLocksWithCurrentAndFuture(t *testing.T) {
	var gotFlags int
	withFakeSyscalls(t,
		func(flags int) error { gotFlags = flags; return nil },
		func(int, *unix.Rlimit) error { return nil },
	)

	require.NoError(t, ApplyMemoryHardening(MemoryConfig{Disabled: false}))
	assert.Equal(t, unix.MCL_CURRENT|unix.MCL_FUTURE, gotFlags, "must lock both already-mapped pages (MCL_CURRENT) and pages mapped after this call (MCL_FUTURE) -- decrypted secret values are allocated throughout the process lifetime, not just at startup")
}

func TestApplyMemoryHardening_FailureWarnsAndContinuesByDefault(t *testing.T) {
	withFakeSyscalls(t,
		func(int) error { return errors.New("operation not permitted") },
		func(int, *unix.Rlimit) error { return nil },
	)

	err := ApplyMemoryHardening(MemoryConfig{Disabled: false, RequireSuccess: false})
	assert.NoError(t, err, "mlockall failure must not be fatal when require_success is unset -- matches Vault's default of warn, not refuse")
}

func TestApplyMemoryHardening_FailureIsFatalWhenRequireSuccessSet(t *testing.T) {
	withFakeSyscalls(t,
		func(int) error { return errors.New("operation not permitted") },
		func(int, *unix.Rlimit) error { return nil },
	)

	err := ApplyMemoryHardening(MemoryConfig{Disabled: false, RequireSuccess: true})
	require.Error(t, err, "mlockall failure must be fatal when require_success=true -- the whole point of the setting is to refuse to run with plaintext swappable")
	assert.Contains(t, err.Error(), "operation not permitted")
}
