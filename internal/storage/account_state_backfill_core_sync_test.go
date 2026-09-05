// account_state_backfill_core_sync_test.go — external storage_test package
// (not the production storage package, which cannot import internal/core:
// core already imports storage) guarding against ValidAccountStateSQLValues
// drifting from core's own ADR-025 account-state registry. If a new account
// state is ever added to internal/core/account_state.go without updating
// guardAccountStateValid's SQL list, this fails CI instead of silently
// leaving Postgres's CHECK constraint rejecting a value the Go code
// considers perfectly valid.
package storage_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage"
)

func TestValidAccountStateSQLValues_MatchesCoreRegistry(t *testing.T) {
	coreSideList := []string{
		core.AccountActive,
		core.AccountPendingFirstLogin,
		core.AccountPasswordResetRequired,
		core.AccountSuspended,
		core.AccountDeprovisioned,
	}
	storageSideList := append([]string(nil), storage.ValidAccountStateSQLValues...)
	sort.Strings(coreSideList)
	sort.Strings(storageSideList)
	assert.Equal(t, coreSideList, storageSideList,
		"internal/storage/account_state_backfill.go's ValidAccountStateSQLValues must list exactly "+
			"core's AccountXxx constants -- update both together")
}
