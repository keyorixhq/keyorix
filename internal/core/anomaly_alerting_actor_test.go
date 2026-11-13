// anomaly_alerting_actor_test.go — #4187: security.anomaly_detected rows are
// written by the detector, so they carry actor system / type system on every
// path, with the real accessor in the description. Before, a run on a request
// context stored type user, no user id and the accessor's IP, shown as "unknown".
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertNewAnomalies_AuditRowIsSystemActor_BothPaths(t *testing.T) {
	paths := []struct {
		name string
		ctx  func() context.Context
	}{
		{"scheduler (untagged context)", func() context.Context { return context.Background() }},
		{"on-demand admin trigger (request context tagged user)", func() context.Context {
			return WithAuditActor(WithActorType(context.Background(), ActorTypeUser), 5)
		}},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			c, db := newActivityFeedCore(t)
			require.NoError(t, db.Create(&models.AnomalyAlert{
				AlertType: "new_user", Severity: "high", AccessedBy: "mallory", IPAddress: "203.0.113.9",
				Description: "Secret accessed by user with no prior access history: mallory",
				CreatedAt:   time.Now(),
			}).Error)

			n, err := c.AlertNewAnomalies(p.ctx())
			require.NoError(t, err)
			require.Equal(t, 1, n)

			var ev models.AuditEvent
			require.NoError(t, db.Where("event_type = ?", EventAnomalyDetected).First(&ev).Error)
			assert.Equal(t, ActorTypeSystem, ev.ActorType)
			assert.Nil(t, ev.UserID, "the detector is the actor, not a user")
			assert.Equal(t, "system", storage.AuditActorKind(&ev))
			assert.Equal(t, "203.0.113.9", ev.IPAddress)
			assert.Contains(t, ev.Description, "mallory", "the real accessor stays in the description")
		})
	}
}
