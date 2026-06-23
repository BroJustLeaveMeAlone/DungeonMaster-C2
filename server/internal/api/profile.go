package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
	"go.uber.org/zap"
)

var validPath = regexp.MustCompile(`^/[a-zA-Z0-9/_\-]+$`)

type profileView struct {
	Name         string          `json:"name"`
	UserAgent    string          `json:"user_agent"`
	RegisterPath string          `json:"register_path"`
	PollPath     string          `json:"poll_path"`
	ExtraHeaders json.RawMessage `json:"extra_headers"`
	CreatedAt    time.Time       `json:"created_at"`
}

func (g *gateway) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Pool.Query(r.Context(), `
		SELECT name, user_agent, register_path, poll_path, extra_headers, created_at
		FROM c2_profiles ORDER BY created_at DESC`)
	if err != nil {
		g.log.Error("list profiles", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	defer rows.Close()

	var out []profileView
	for rows.Next() {
		var p profileView
		if err := rows.Scan(&p.Name, &p.UserAgent, &p.RegisterPath, &p.PollPath,
			&p.ExtraHeaders, &p.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		out = append(out, p)
	}
	if out == nil {
		out = []profileView{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *gateway) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string          `json:"name"`
		UserAgent    string          `json:"user_agent"`
		RegisterPath string          `json:"register_path"`
		PollPath     string          `json:"poll_path"`
		ExtraHeaders json.RawMessage `json:"extra_headers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if req.RegisterPath == "" {
		req.RegisterPath = "/r"
	}
	if req.PollPath == "" {
		req.PollPath = "/c"
	}
	if !validPath.MatchString(req.RegisterPath) || !validPath.MatchString(req.PollPath) {
		writeError(w, http.StatusBadRequest, "paths must start with / and contain only [a-zA-Z0-9/_-]")
		return
	}
	if req.ExtraHeaders == nil {
		req.ExtraHeaders = json.RawMessage("[]")
	}

	var p profileView
	err := db.Pool.QueryRow(r.Context(), `
		INSERT INTO c2_profiles (name, user_agent, register_path, poll_path, extra_headers)
		VALUES ($1, $2, $3, $4, $5::jsonb)
		ON CONFLICT (name) DO UPDATE SET
			user_agent = EXCLUDED.user_agent,
			register_path = EXCLUDED.register_path,
			poll_path = EXCLUDED.poll_path,
			extra_headers = EXCLUDED.extra_headers
		RETURNING name, user_agent, register_path, poll_path, extra_headers, created_at`,
		req.Name, req.UserAgent, req.RegisterPath, req.PollPath, req.ExtraHeaders,
	).Scan(&p.Name, &p.UserAgent, &p.RegisterPath, &p.PollPath, &p.ExtraHeaders, &p.CreatedAt)
	if err != nil {
		g.log.Error("create profile", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (g *gateway) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	var p profileView
	err := db.Pool.QueryRow(r.Context(), `
		SELECT name, user_agent, register_path, poll_path, extra_headers, created_at
		FROM c2_profiles WHERE name = $1`, r.PathValue("name"),
	).Scan(&p.Name, &p.UserAgent, &p.RegisterPath, &p.PollPath, &p.ExtraHeaders, &p.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (g *gateway) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	ct, err := db.Pool.Exec(r.Context(),
		`DELETE FROM c2_profiles WHERE name = $1`, r.PathValue("name"))
	if err != nil || ct.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
