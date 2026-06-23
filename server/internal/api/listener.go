package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
	"go.uber.org/zap"
)

type listenerView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	BindHost string    `json:"bind_host"`
	BindPort int       `json:"bind_port"`
	Type     string    `json:"type"`
	IsActive bool      `json:"is_active"`
	Created  time.Time `json:"created_at"`
}

func (g *gateway) handleListListeners(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Pool.Query(r.Context(), `
		SELECT id, name, bind_host, bind_port, type, is_active, created_at
		FROM listeners WHERE is_active = TRUE ORDER BY created_at DESC`)
	if err != nil {
		g.log.Error("list listeners", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	defer rows.Close()

	var out []listenerView
	for rows.Next() {
		var l listenerView
		if err := rows.Scan(&l.ID, &l.Name, &l.BindHost, &l.BindPort, &l.Type, &l.IsActive, &l.Created); err != nil {
			g.log.Error("scan listener", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		out = append(out, l)
	}
	if out == nil {
		out = []listenerView{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *gateway) handleCreateListener(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		BindHost string `json:"bind_host"`
		BindPort int    `json:"bind_port"`
		Type     string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" || req.BindHost == "" || req.BindPort == 0 {
		writeError(w, http.StatusBadRequest, "name, bind_host, bind_port required")
		return
	}
	if req.Type == "" {
		req.Type = "https"
	}

	var l listenerView
	err := db.Pool.QueryRow(r.Context(), `
		INSERT INTO listeners (name, bind_host, bind_port, type)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, bind_host, bind_port, type, is_active, created_at`,
		req.Name, req.BindHost, req.BindPort, req.Type,
	).Scan(&l.ID, &l.Name, &l.BindHost, &l.BindPort, &l.Type, &l.IsActive, &l.Created)
	if err != nil {
		g.log.Error("create listener", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}
	writeJSON(w, http.StatusCreated, l)
}
