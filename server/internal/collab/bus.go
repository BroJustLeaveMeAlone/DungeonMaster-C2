package collab

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	channelPrefix = "dm:campaign:"

	EventSessionCheckin  = "SESSION_CHECKIN"
	EventSessionRevoked  = "SESSION_REVOKED"
	EventTaskQueued      = "TASK_QUEUED"
	EventTaskOutput      = "TASK_OUTPUT"
	EventEvasionDetected = "EVASION_DETECTED"
	EventAISuggestion    = "AI_SUGGESTION"
	EventEvidenceAdded   = "EVIDENCE_ADDED"
	EventTTPMapped       = "TTP_MAPPED"
	EventOperatorJoined  = "OPERATOR_JOINED"
	EventOperatorLeft    = "OPERATOR_LEFT"
	EventBuildComplete   = "BUILD_COMPLETE"
)

// Event is the envelope that flows across the collaboration bus.
type Event struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	CampaignID string          `json:"campaign_id"`
	SessionID  string          `json:"session_id,omitempty"`
	OperatorID string          `json:"operator_id,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	OccurredAt time.Time       `json:"occurred_at"`
}

// Subscriber is a channel that receives events for a campaign.
// The web API layer writes these to the operator's WebSocket connection.
type Subscriber struct {
	CampaignID string
	OperatorID string
	C          chan Event
}

// Bus manages Redis pub/sub and local subscriber fan-out.
// It is the single source of truth for real-time operator collaboration.
//
// Architecture:
//   Publish(event) → Redis pub/sub channel → all team server instances
//     → local subscriber map → each operator's WebSocket channel
//
// This means the collaboration bus works correctly even with multiple
// team server instances behind a load balancer (e.g., multi-region deployment).
type Bus struct {
	rdb  *redis.Client
	log  *zap.Logger
	mu   sync.RWMutex
	subs map[string][]*Subscriber // campaign_id → subscribers
}

func NewBus(rdb *redis.Client, log *zap.Logger) *Bus {
	return &Bus{
		rdb:  rdb,
		log:  log,
		subs: make(map[string][]*Subscriber),
	}
}

// Start begins listening on all campaign channels.
// This must be called once at server startup; run it in a goroutine.
// It automatically reconnects if the Redis channel closes.
func (b *Bus) Start(ctx context.Context) error {
	backoff := time.Second
	for {
		err := b.subscribe(ctx)
		if err == nil {
			return nil // clean shutdown via ctx
		}
		b.log.Warn("collab: redis pubsub disconnected, reconnecting",
			zap.Error(err), zap.Duration("backoff", backoff))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (b *Bus) subscribe(ctx context.Context) error {
	pubsub := b.rdb.PSubscribe(ctx, channelPrefix+"*")
	defer pubsub.Close()

	b.log.Info("collaboration bus started")
	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			b.log.Info("collaboration bus stopped")
			return nil
		case msg, ok := <-ch:
			if !ok {
				return fmt.Errorf("redis channel closed")
			}
			var ev Event
			if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
				b.log.Error("collab: unmarshal event", zap.Error(err))
				continue
			}
			b.fanOut(ev)
		}
	}
}

// Publish sends an event to all subscribers of the given campaign.
// The event is persisted to Redis and fanned out to all connected operators.
func (b *Bus) Publish(ctx context.Context, ev Event) error {
	if ev.ID == "" {
		ev.ID = uuid.New().String()
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("collab: marshal event: %w", err)
	}

	channel := channelPrefix + ev.CampaignID
	if err := b.rdb.Publish(ctx, channel, data).Err(); err != nil {
		return fmt.Errorf("collab: redis publish: %w", err)
	}
	return nil
}

// Subscribe registers an operator to receive events for a campaign.
// Returns a Subscriber whose channel will receive events until Unsubscribe is called.
func (b *Bus) Subscribe(campaignID, operatorID string) *Subscriber {
	sub := &Subscriber{
		CampaignID: campaignID,
		OperatorID: operatorID,
		C:          make(chan Event, 64),
	}
	b.mu.Lock()
	b.subs[campaignID] = append(b.subs[campaignID], sub)
	b.mu.Unlock()

	b.log.Info("operator subscribed to campaign",
		zap.String("operator_id", operatorID),
		zap.String("campaign_id", campaignID),
	)
	return sub
}

// Unsubscribe removes an operator's subscription and closes their channel.
func (b *Bus) Unsubscribe(sub *Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()

	subs := b.subs[sub.CampaignID]
	updated := make([]*Subscriber, 0, len(subs))
	for _, s := range subs {
		if s != sub {
			updated = append(updated, s)
		}
	}
	b.subs[sub.CampaignID] = updated
	close(sub.C)

	b.log.Info("operator unsubscribed from campaign",
		zap.String("operator_id", sub.OperatorID),
		zap.String("campaign_id", sub.CampaignID),
	)
}

// fanOut delivers an event to all local subscribers of a campaign.
// Non-blocking: if a subscriber's buffer is full, the event is dropped for that subscriber
// and a warning is logged. The subscriber should increase its buffer or consume faster.
func (b *Bus) fanOut(ev Event) {
	b.mu.RLock()
	subs := b.subs[ev.CampaignID]
	b.mu.RUnlock()

	for _, sub := range subs {
		select {
		case sub.C <- ev:
		default:
			b.log.Warn("collab: subscriber buffer full, dropping event",
				zap.String("operator_id", sub.OperatorID),
				zap.String("event_type", ev.Type),
			)
		}
	}
}

// --- convenience constructors for common event types -----------------------

func NewSessionCheckinEvent(campaignID, sessionID string) Event {
	return Event{
		Type:       EventSessionCheckin,
		CampaignID: campaignID,
		SessionID:  sessionID,
	}
}

func NewTaskOutputEvent(campaignID, sessionID, taskID string, output []byte) Event {
	payload, _ := json.Marshal(map[string]any{
		"task_id": taskID,
		"output":  string(output),
	})
	return Event{
		Type:       EventTaskOutput,
		CampaignID: campaignID,
		SessionID:  sessionID,
		Payload:    payload,
	}
}

func NewEvasionEvent(campaignID, sessionID, taskID, description string) Event {
	payload, _ := json.Marshal(map[string]string{
		"task_id":     taskID,
		"description": description,
	})
	return Event{
		Type:       EventEvasionDetected,
		CampaignID: campaignID,
		SessionID:  sessionID,
		Payload:    payload,
	}
}

func NewAISuggestionEvent(campaignID, sessionID string, suggestions json.RawMessage) Event {
	return Event{
		Type:       EventAISuggestion,
		CampaignID: campaignID,
		SessionID:  sessionID,
		Payload:    suggestions,
	}
}

func NewBuildCompleteEvent(campaignID, buildID, artifactURL string) Event {
	payload, _ := json.Marshal(map[string]string{
		"build_id":     buildID,
		"artifact_url": artifactURL,
	})
	return Event{
		Type:       EventBuildComplete,
		CampaignID: campaignID,
		Payload:    payload,
	}
}
