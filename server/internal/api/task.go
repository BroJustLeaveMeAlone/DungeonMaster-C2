package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/BroJustLeaveMeAlone/C2-Adversary/server/internal/collab"
	"github.com/BroJustLeaveMeAlone/C2-Adversary/server/internal/db"
	"go.uber.org/zap"
)

type taskView struct {
	ID                   string     `json:"id"`
	SessionID            string     `json:"session_id"`
	OperatorID           string     `json:"operator_id"`
	Type                 string     `json:"type"`
	Args                 []byte     `json:"args,omitempty"`
	Status               string     `json:"status"`
	Output               []byte     `json:"output,omitempty"`
	MITRETechniqueID     string     `json:"mitre_technique_id,omitempty"`
	RequiresConfirmation bool       `json:"requires_confirmation"`
	CreatedAt            time.Time  `json:"created_at"`
	SentAt               *time.Time `json:"sent_at,omitempty"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
}

func (g *gateway) handleQueueTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID            string `json:"session_id"`
		Type                 string `json:"type"`
		Args                 []byte `json:"args"`
		MITRETechniqueID     string `json:"mitre_technique_id"`
		RequiresConfirmation bool   `json:"requires_confirmation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SessionID == "" || req.Type == "" {
		writeError(w, http.StatusBadRequest, "session_id and type required")
		return
	}

	operatorID := operatorIDFromCtx(r.Context())

	var taskID string
	err := db.Pool.QueryRow(r.Context(), `
		INSERT INTO tasks (session_id, operator_id, type, args, mitre_technique_id, requires_confirmation)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`,
		req.SessionID, operatorID, req.Type, req.Args, req.MITRETechniqueID, req.RequiresConfirmation,
	).Scan(&taskID)
	if err != nil {
		g.log.Error("queue task", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "queue failed")
		return
	}

	var campaignID string
	db.Pool.QueryRow(r.Context(), `SELECT campaign_id FROM sessions WHERE id = $1`, req.SessionID).Scan(&campaignID)
	if campaignID != "" {
		payload, _ := json.Marshal(map[string]string{"task_id": taskID, "type": req.Type})
		go g.bus.Publish(context.Background(), collab.Event{
			Type:       collab.EventTaskQueued,
			CampaignID: campaignID,
			SessionID:  req.SessionID,
			OperatorID: operatorID,
			Payload:    payload,
		})
	}

	writeJSON(w, http.StatusCreated, map[string]string{"task_id": taskID})
}

func (g *gateway) handleGetTask(w http.ResponseWriter, r *http.Request) {
	var t taskView
	err := db.Pool.QueryRow(r.Context(), `
		SELECT id, session_id, operator_id, type, args, status, output,
		       mitre_technique_id, requires_confirmation, created_at, sent_at, completed_at
		FROM tasks WHERE id = $1`, r.PathValue("id"),
	).Scan(
		&t.ID, &t.SessionID, &t.OperatorID, &t.Type, &t.Args, &t.Status, &t.Output,
		&t.MITRETechniqueID, &t.RequiresConfirmation, &t.CreatedAt, &t.SentAt, &t.CompletedAt,
	)
	if err != nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (g *gateway) handleListTasks(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	pendingOnly := r.URL.Query().Get("pending_only") == "true"

	query := `
		SELECT id, session_id, operator_id, type, args, status, output,
		       mitre_technique_id, requires_confirmation, created_at, sent_at, completed_at
		FROM tasks WHERE session_id = $1`
	if pendingOnly {
		query += ` AND status = 'queued'`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := db.Pool.Query(r.Context(), query, sessionID)
	if err != nil {
		g.log.Error("list tasks", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	defer rows.Close()

	var tasks []taskView
	for rows.Next() {
		var t taskView
		if err := rows.Scan(
			&t.ID, &t.SessionID, &t.OperatorID, &t.Type, &t.Args, &t.Status, &t.Output,
			&t.MITRETechniqueID, &t.RequiresConfirmation, &t.CreatedAt, &t.SentAt, &t.CompletedAt,
		); err != nil {
			g.log.Error("scan task", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		tasks = append(tasks, t)
	}
	if tasks == nil {
		tasks = []taskView{}
	}
	writeJSON(w, http.StatusOK, tasks)
}

func (g *gateway) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	tag, err := db.Pool.Exec(r.Context(),
		`UPDATE tasks SET status = 'cancelled' WHERE id = $1 AND status = 'queued'`,
		taskID,
	)
	if err != nil {
		g.log.Error("cancel task", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "cancel failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusConflict, "task not cancellable (already sent or complete)")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
