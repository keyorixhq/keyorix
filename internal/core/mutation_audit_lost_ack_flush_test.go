package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// PARTIAL-COMMIT-TAILS-NOV-3 item 3: withAuditedMutation forwarded its committed
// audit rows off box (auditForwardSink.Flush) only after a clean commit. When the
// commit's acknowledgement was lost, a create path that read the row back and
// delivered the mutation (#3225: userCreateLanded) left its user.created row in the
// database and never forwarded it, so the SIEM mirror missed a committed,
// delivered user creation. A delivered mutation's rows are forwarded exactly once;
// a rolled-back one forwards nothing.

type eventTypeForwarder struct{ types []string }

func (f *eventTypeForwarder) Forward(e *models.AuditEvent) { f.types = append(f.types, e.EventType) }

func auditedCreateUnderFault(t *testing.T, kind faultstorage.FaultKind, create func(c *KeyorixCore, adminID uint) (*models.User, error)) (*models.User, *eventTypeForwarder, error) {
	t.Helper()
	ctx := context.Background()
	_, st := newBootstrappedCore(t)
	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	fs := faultstorage.NewFaultyStorage(st, &faultstorage.FaultSpec{
		Method: "WithTransaction", NthCall: 1, Kind: kind, Err: errors.New("commit acknowledgement lost"),
	})
	c := NewKeyorixCore(fs)
	fwd := &eventTypeForwarder{}
	c.auditForwarder = fwd
	u, err := create(c, admin.ID)
	require.True(t, fs.Fired(), "premise: the create transaction was faulted")
	return u, fwd, err
}

func TestWithAuditedMutation_LostAckDeliveredCreateForwardsItsAudit(t *testing.T) {
	creates := map[string]func(c *KeyorixCore, adminID uint) (*models.User, error){
		"CreateUserAudited": func(c *KeyorixCore, adminID uint) (*models.User, error) {
			return c.CreateUserAudited(context.Background(), &CreateUserRequest{
				Username: "lostack", Email: "lostack@example.com", Password: "Kx7!Lost-Ack-Pwd#1",
			}, adminID, false)
		},
		"CreateUserWithAssignments": func(c *KeyorixCore, adminID uint) (*models.User, error) {
			return c.CreateUserWithAssignments(context.Background(), &CreateUserRequest{
				Username: "lostack", Email: "lostack@example.com", Password: "Kx7!Lost-Ack-Pwd#1",
			}, "viewer", nil, adminID, false)
		},
	}
	for name, create := range creates {
		t.Run(name+"/lost ack", func(t *testing.T) {
			u, fwd, err := auditedCreateUnderFault(t, faultstorage.KindEffectThenError, create)
			require.NoError(t, err, "premise: the committed create is delivered (#3225)")
			require.NotNil(t, u)
			assert.Equal(t, 1, countType(fwd.types, EventUserCreated),
				"the delivered create's user.created must be forwarded exactly once, got %v", fwd.types)
		})
		t.Run(name+"/rollback", func(t *testing.T) {
			_, fwd, err := auditedCreateUnderFault(t, faultstorage.KindError, create)
			require.Error(t, err)
			assert.Zero(t, countType(fwd.types, EventUserCreated),
				"a rolled-back create must forward nothing, got %v", fwd.types)
		})
	}
}

func countType(types []string, want string) int {
	n := 0
	for _, ty := range types {
		if ty == want {
			n++
		}
	}
	return n
}
