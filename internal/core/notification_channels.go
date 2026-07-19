// notification_channels.go — runtime CRUD for outbound notification channels.
// Channels are DB-backed destinations (webhook/slack/teams/email) that can be
// managed at runtime without editing config files.
package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// validChannelTypes is the set of accepted channel type values.
var validChannelTypes = map[string]struct{}{
	"webhook": {},
	"slack":   {},
	"teams":   {},
	"email":   {},
}

// ListNotificationChannels returns all configured notification channels.
func (c *KeyorixCore) ListNotificationChannels(ctx context.Context) ([]*models.NotificationChannel, error) {
	return c.storage.ListNotificationChannels(ctx)
}

// GetNotificationChannel returns the channel with the given id.
func (c *KeyorixCore) GetNotificationChannel(ctx context.Context, id uint) (*models.NotificationChannel, error) {
	return c.storage.GetNotificationChannel(ctx, id)
}

// CreateNotificationChannel validates and persists a new notification channel.
// Validation:
//   - Name must be non-empty.
//   - Type must be one of: webhook, slack, teams, email.
//   - URL is required for webhook/slack/teams types.
//   - Email is required for email type.
func (c *KeyorixCore) CreateNotificationChannel(ctx context.Context, ch *models.NotificationChannel, createdBy string) (*models.NotificationChannel, error) {
	if err := validateNotificationChannel(ch); err != nil {
		return nil, err
	}
	ch.CreatedBy = createdBy
	ch.CreatedAt = time.Now().UTC()
	ch.UpdatedAt = ch.CreatedAt
	if err := c.storage.CreateNotificationChannel(ctx, ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// UpdateNotificationChannel applies the given map of field updates to the channel
// identified by id and returns the updated channel.
func (c *KeyorixCore) UpdateNotificationChannel(ctx context.Context, id uint, updates map[string]interface{}) (*models.NotificationChannel, error) {
	ch, err := c.storage.GetNotificationChannel(ctx, id)
	if err != nil {
		return nil, err
	}
	if v, ok := updates["name"].(string); ok && v != "" {
		ch.Name = v
	}
	if v, ok := updates["type"].(string); ok && v != "" {
		ch.Type = v
	}
	if v, ok := updates["url"].(string); ok {
		ch.URL = v
	}
	if v, ok := updates["email"].(string); ok {
		ch.Email = v
	}
	if v, ok := updates["events"].(string); ok {
		ch.Events = v
	}
	if v, ok := updates["enabled"].(bool); ok {
		ch.Enabled = v
	}
	if err := validateNotificationChannel(ch); err != nil {
		return nil, err
	}
	ch.UpdatedAt = time.Now().UTC()
	if err := c.storage.UpdateNotificationChannel(ctx, ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// DeleteNotificationChannel permanently removes the channel with the given id.
func (c *KeyorixCore) DeleteNotificationChannel(ctx context.Context, id uint) error {
	return c.storage.DeleteNotificationChannel(ctx, id)
}

// validateNotificationChannel enforces invariants for create and update paths.
func validateNotificationChannel(ch *models.NotificationChannel) error {
	if strings.TrimSpace(ch.Name) == "" {
		return fmt.Errorf("notification channel name is required")
	}
	if _, ok := validChannelTypes[ch.Type]; !ok {
		return fmt.Errorf("invalid notification channel type %q: must be one of webhook, slack, teams, email", ch.Type)
	}
	switch ch.Type {
	case "webhook", "slack", "teams":
		if strings.TrimSpace(ch.URL) == "" {
			return fmt.Errorf("notification channel URL is required for type %q", ch.Type)
		}
	case "email":
		if strings.TrimSpace(ch.Email) == "" {
			return fmt.Errorf("notification channel email is required for type \"email\"")
		}
	}
	return nil
}
