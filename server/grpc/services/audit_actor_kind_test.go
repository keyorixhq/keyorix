package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// #2951 review (1): gRPC GetAuditLogs shows the same actor kind as HTTP and as
// the actor_type filter. Before, it filtered by the displayed kind but returned
// the raw stored actor_type, so actor_type=system returned scheduler rows
// labelled "user" (the #2951 bug). Both directions: a failed login (no acting
// user, client address) stays kind "user" with actor "unknown".
func TestAuditService_GetAuditLogs_ActorKindMatchesFilter(t *testing.T) {
	svc := newAuditService(t) // seeds one secret.read by alice (kind user)
	st := svc.core.Storage()
	now := time.Now().UTC()
	for i, e := range []models.AuditEvent{
		{EventType: "secret.auto_rotated", ActorType: "user"},
		{EventType: "data.retention_purged", ActorType: "system"},
		{EventType: "auth.login_failed", ActorType: "user", IPAddress: "198.51.100.7"},
	} {
		ev := e
		ev.EventTime = now.Add(time.Duration(i+1) * time.Second)
		require.NoError(t, st.LogAuditEvent(context.Background(), &ev))
	}

	list := func(kind string) map[string]*pb.AuditLog {
		t.Helper()
		k := kind
		resp, err := svc.GetAuditLogs(auditCtx(), &pb.GetAuditLogsRequest{ActorType: &k})
		require.NoError(t, err)
		out := map[string]*pb.AuditLog{}
		for _, l := range resp.GetLogs() {
			assert.Equal(t, kind, l.GetActorType(), "%s returned by actor_type=%s but shown as kind %q", l.GetEventType(), kind, l.GetActorType())
			out[l.GetEventType()] = l
		}
		return out
	}

	sys := list("system")
	assert.Len(t, sys, 2)
	require.Contains(t, sys, "secret.auto_rotated")
	assert.Equal(t, "system", sys["secret.auto_rotated"].GetActor())
	assert.Contains(t, sys, "data.retention_purged")

	usr := list("user")
	assert.Len(t, usr, 2)
	require.Contains(t, usr, "auth.login_failed", "a failed login must stay findable under actor_type=user")
	assert.Equal(t, "unknown", usr["auth.login_failed"].GetActor())
	require.Contains(t, usr, "secret.read")
	assert.Equal(t, "alice", usr["secret.read"].GetActor())
}
