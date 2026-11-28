package admin

// admin_exit_code_test.go -- BOOT-REFUSAL-TRUTH-NOV-1: `keyorix-server admin ...`
// exits 78 for the session_replication_role refusal, like the server.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage"
)

func TestAdminExitCode(t *testing.T) {
	replica := &storage.NonOriginReplicationRoleError{Role: "replica"}
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"replication role refusal", replica, 78},
		{"wrapped as migrate wraps it", fmt.Errorf("migration failed: %w", replica), 78},
		{"wrapped twice", fmt.Errorf("open the database: %w", fmt.Errorf("failed to initialize storage: %w", replica)), 78},
		{"any other failure stays 1", errors.New("migration failed: disk full"), 1},
		{"fold collision stays 1 here", fmt.Errorf("migration failed: %w", &storage.FoldCollisionError{Table: "projects", Column: "name_folded", Groups: 1}), 1},
		// The text is %v-flattened: the type is gone and so is the mark. Only an
		// error chain that keeps the type is classified.
		{"flattened text stays 1", fmt.Errorf("migration failed: %v", replica), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := adminExitCode(tt.err); got != tt.want {
				t.Errorf("adminExitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
