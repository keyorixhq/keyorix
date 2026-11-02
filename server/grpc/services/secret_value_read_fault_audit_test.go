package services

// secret_value_read_fault_audit_test.go -- STORAGE-ERR-CLASS-4 review fix (#3899).
//
// GetSecretValue audits every refusal as a failed secret.read (#3273), with the
// reason authorizeSecretScoped notes on ctx. A READ FAULT on the target fetch is
// an outage on a secret that may exist, so the row must say internal_error, for
// every caller, as REST's handleScopeResolutionError notes it. It used to say
// not_found while the client was told Unavailable. A true miss stays not_found.

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestSecretValueRPC_TargetReadFault_AuditsInternalError(t *testing.T) {
	r := newSecretTestRig(t)
	created := r.createSecret(t, authCtx(1, "owner", "secrets.write", "secrets.read"), "fault-audit-target", "v1")
	require.NoError(t, r.db.Create(&models.User{ID: 2, Username: "nobody", Email: "nobody@example.com"}).Error)
	scanFault := errors.New(`sql: Scan error on column index 3, name "project_id": converting NULL to uint is unsupported`)

	// refusalReason calls GetSecretValue on a fresh core (its own denial
	// aggregator, so every call writes a first-of-window row) and returns the
	// answer's code and the reason on the one secret.read Success=false row.
	refusalReason := func(t *testing.T, userID uint, username string, id uint32, fault bool) (codes.Code, string) {
		t.Helper()
		fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(r.db), nil)
		svc := NewSecretService(core.NewKeyorixCore(fs))
		var before uint
		require.NoError(t, r.db.Model(&models.AuditEvent{}).Select("COALESCE(MAX(id), 0)").Scan(&before).Error)
		if fault {
			fs.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: scanFault})
		}
		_, err := svc.GetSecretValue(authCtx(userID, username), &pb.GetSecretRequest{Id: id})
		if fault {
			require.True(t, fs.Fired(), "precondition: the target fetch must hit the injected fault")
			fs.Arm(nil)
		}
		require.Error(t, err)
		var rows []models.AuditEvent
		require.NoError(t, r.db.Where("event_type = ? AND success = ? AND id > ?", "secret.read", false, before).Find(&rows).Error)
		require.Len(t, rows, 1, "exactly one refused-read audit row")
		var diff struct {
			Reason string `json:"reason"`
		}
		require.NoError(t, json.Unmarshal([]byte(rows[0].Diff), &diff), "diff: %s", rows[0].Diff)
		return status.Code(err), diff.Reason
	}

	t.Run("global holder", func(t *testing.T) {
		code, reason := refusalReason(t, 1, "owner", created.GetId(), true)
		assert.Equal(t, codes.Unavailable, code)
		assert.Equal(t, string(core.SecretReadDeniedInternalError), reason, "a read fault is audited as an outage, not a miss")
	})
	t.Run("caller without global standing", func(t *testing.T) {
		code, reason := refusalReason(t, 2, "nobody", created.GetId(), true)
		assert.Equal(t, codes.PermissionDenied, code, "no existence signal in the answer")
		assert.Equal(t, string(core.SecretReadDeniedInternalError), reason, "the audit row records the truth either way")
	})
	t.Run("true miss stays not_found", func(t *testing.T) {
		code, reason := refusalReason(t, 1, "owner", 999999, false)
		assert.Equal(t, codes.NotFound, code)
		assert.Equal(t, string(core.SecretReadDeniedNotFound), reason)
	})
}
