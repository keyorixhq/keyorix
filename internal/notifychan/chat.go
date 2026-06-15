// chat.go — Slack / Microsoft Teams notification channels. Both accept an incoming
// webhook URL that carries its own secret token; the only per-platform difference is
// the JSON payload shape (Slack: {text}; Teams: a MessageCard). Like the other sinks
// it delivers asynchronously off a bounded queue so a slow chat endpoint never blocks
// the triggering action.
package notifychan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

const (
	chatTimeout   = 10 * time.Second
	chatQueueSize = 256
)

// ChatKind selects the payload format for the chat webhook.
type ChatKind string

const (
	ChatSlack ChatKind = "slack"
	ChatTeams ChatKind = "teams"
)

// ChatConfig configures a Slack/Teams channel: the platform and its incoming-webhook
// URL (which embeds the platform's secret token).
type ChatConfig struct {
	Kind       ChatKind
	WebhookURL string
}

// ChatSink delivers notifications to a Slack or Teams incoming webhook.
type ChatSink struct {
	cfg     ChatConfig
	client  *http.Client
	queue   chan core.NotificationEvent
	wg      sync.WaitGroup
	mu      sync.Mutex
	dropped int
}

// NewChat builds a chat sink and starts its worker. The kind must be slack|teams and
// the webhook URL is required. Close() drains in-flight events at shutdown.
func NewChat(cfg ChatConfig) (*ChatSink, error) {
	switch cfg.Kind {
	case ChatSlack, ChatTeams:
	default:
		return nil, fmt.Errorf("notifychan: unknown chat kind %q (want slack|teams)", cfg.Kind)
	}
	if cfg.WebhookURL == "" {
		return nil, fmt.Errorf("notifychan: chat webhook_url is required")
	}
	s := &ChatSink{
		cfg:    cfg,
		client: &http.Client{Timeout: chatTimeout},
		queue:  make(chan core.NotificationEvent, chatQueueSize),
	}
	s.wg.Add(1)
	go s.worker()
	return s, nil
}

// Deliver enqueues the event. Non-blocking; drops (and counts) when the queue is full.
func (s *ChatSink) Deliver(ev core.NotificationEvent) {
	if s == nil {
		return
	}
	select {
	case s.queue <- ev:
	default:
		s.mu.Lock()
		s.dropped++
		dropped := s.dropped
		s.mu.Unlock()
		log.Printf("notifychan: %s queue full, dropped notification (total dropped: %d)", s.cfg.Kind, dropped)
	}
}

func (s *ChatSink) worker() {
	defer s.wg.Done()
	for ev := range s.queue {
		if err := s.send(context.Background(), ev); err != nil {
			log.Printf("notifychan: %s delivery failed: %v", s.cfg.Kind, err)
		}
	}
}

func (s *ChatSink) send(ctx context.Context, ev core.NotificationEvent) error {
	body, err := json.Marshal(chatPayload(s.cfg.Kind, ev))
	if err != nil {
		return fmt.Errorf("marshal %s payload: %w", s.cfg.Kind, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s webhook returned %s", s.cfg.Kind, strings.TrimSpace(resp.Status))
	}
	return nil
}

// chatText renders the notification as a single plain-text message (no remote
// resources), shared by both platforms.
func chatText(ev core.NotificationEvent) string {
	var b strings.Builder
	if ev.Title != "" {
		fmt.Fprintf(&b, "*%s*\n", ev.Title)
	}
	b.WriteString(ev.Message)
	if ev.Link != "" {
		fmt.Fprintf(&b, "\n%s", ev.Link)
	}
	return b.String()
}

// chatPayload builds the platform-specific JSON body. Slack incoming webhooks take
// {text}; Teams connectors take a MessageCard.
func chatPayload(kind ChatKind, ev core.NotificationEvent) interface{} {
	text := chatText(ev)
	if kind == ChatTeams {
		title := ev.Title
		if title == "" {
			title = "Keyorix notification"
		}
		return map[string]interface{}{
			"@type":    "MessageCard",
			"@context": "https://schema.org/extensions",
			"summary":  title,
			"title":    title,
			"text":     ev.Message,
		}
	}
	return map[string]string{"text": text}
}

// Close stops the worker after draining queued events.
func (s *ChatSink) Close() {
	if s == nil {
		return
	}
	close(s.queue)
	s.wg.Wait()
}
