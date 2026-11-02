package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"gorm.io/gorm"
)

// STORAGE-ERR-CLASS-3 item 3: a failed bulk-delete item reports one fixed class and
// never the error text, whatever the error says.
func TestBulkDeleteFailureMessage_FixedClasses(t *testing.T) {
	leak := `UPDATE "secret_nodes" SET "deleted_at"=?: no such column: cache_epoch`
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"permission refusal", permissionDeniedf("insufficient permissions on %s", leak), "permission denied"},
		{"positive not-found", fmt.Errorf("delete: %w", storage.ErrSecretNotFound), "secret not found"},
		{"gorm not-found", fmt.Errorf("%s: %w", leak, gorm.ErrRecordNotFound), "secret not found"},
		{"classified read fault", classifyReadError(errors.New(leak), "secret not found"), StorageReadUnavailableMessage},
		{"transient driver error", fmt.Errorf("%s: %w", leak, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}), StorageReadUnavailableMessage},
		{"anything else", errors.New(leak), "internal error"},
	}
	for _, tc := range cases {
		if got := bulkDeleteFailureMessage(context.Background(), tc.err); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
