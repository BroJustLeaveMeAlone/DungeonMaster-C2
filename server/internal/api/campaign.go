package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/BroJustLeaveMeAlone/C2-Adversary/server/internal/db"
	"go.uber.org/zap"
)

type campaignView struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	ClientName   string     `json:"client_name"`
	Objective    string     `json:"objective"`
	ScopeCIDRs   []string   `json:"scope_cidrs"`
	ScopeDomains []string   `json:"scope_domains"`
	IsActive     bool       `json:"is_active"`
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
}

func (g *gateway) handleCreateCampaign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string   `json:"name"`
		Description  string   `json:"description"`
		ClientName   string   `json:"client_name"`
		Objective    string   `json:"objective"`
		ScopeCIDRs   []string `json:"scope_cidrs"`
		ScopeDomains []string `json:"scope_domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if req.ScopeCIDRs == nil {
		req.ScopeCIDRs = []string{}
	}
	if req.ScopeDomains == nil {
		req.ScopeDomains = []string{}
	}

	var c campaignView
	err := db.Pool.QueryRow(r.Context(), `
		INSERT INTO campaigns (name, description, client_name, objective, scope_cidrs, scope_domains)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, description, client_name, objective, scope_cidrs, scope_domains,
		          is_active, created_at, started_at, ended_at`,
		req.Name, req.Description, req.ClientName, req.Objective, req.ScopeCIDRs, req.ScopeDomains,
	).Scan(
		&c.ID, &c.Name, &c.Description, &c.ClientName, &c.Objective,
		&c.ScopeCIDRs, &c.ScopeDomains, &c.IsActive, &c.CreatedAt, &c.StartedAt, &c.EndedAt,
	)
	if err != nil {
		g.log.Error("create campaign", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (g *gateway) handleGetCampaign(w http.ResponseWriter, r *http.Request) {
	var c campaignView
	err := db.Pool.QueryRow(r.Context(), `
		SELECT id, name, description, client_name, objective, scope_cidrs, scope_domains,
		       is_active, created_at, started_at, ended_at
		FROM campaigns WHERE id = $1`, r.PathValue("id"),
	).Scan(
		&c.ID, &c.Name, &c.Description, &c.ClientName, &c.Objective,
		&c.ScopeCIDRs, &c.ScopeDomains, &c.IsActive, &c.CreatedAt, &c.StartedAt, &c.EndedAt,
	)
	if err != nil {
		writeError(w, http.StatusNotFound, "campaign not found")
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (g *gateway) handleListCampaigns(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active_only") == "true"

	query := `
		SELECT id, name, description, client_name, objective, scope_cidrs, scope_domains,
		       is_active, created_at, started_at, ended_at
		FROM campaigns`
	if activeOnly {
		query += ` WHERE is_active = TRUE`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := db.Pool.Query(r.Context(), query)
	if err != nil {
		g.log.Error("list campaigns", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	defer rows.Close()

	var campaigns []campaignView
	for rows.Next() {
		var c campaignView
		if err := rows.Scan(
			&c.ID, &c.Name, &c.Description, &c.ClientName, &c.Objective,
			&c.ScopeCIDRs, &c.ScopeDomains, &c.IsActive, &c.CreatedAt, &c.StartedAt, &c.EndedAt,
		); err != nil {
			g.log.Error("scan campaign", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		campaigns = append(campaigns, c)
	}
	if campaigns == nil {
		campaigns = []campaignView{}
	}
	writeJSON(w, http.StatusOK, campaigns)
}

func (g *gateway) handleUpdateCampaign(w http.ResponseWriter, r *http.Request) {
	campaignID := r.PathValue("id")
	var req struct {
		Name         string   `json:"name"`
		Description  string   `json:"description"`
		ClientName   string   `json:"client_name"`
		Objective    string   `json:"objective"`
		ScopeCIDRs   []string `json:"scope_cidrs"`
		ScopeDomains []string `json:"scope_domains"`
		IsActive     *bool    `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var c campaignView
	err := db.Pool.QueryRow(r.Context(), `
		UPDATE campaigns
		SET name         = COALESCE(NULLIF($2, ''), name),
		    description  = COALESCE(NULLIF($3, ''), description),
		    client_name  = COALESCE(NULLIF($4, ''), client_name),
		    objective    = COALESCE(NULLIF($5, ''), objective),
		    scope_cidrs  = COALESCE($6, scope_cidrs),
		    scope_domains = COALESCE($7, scope_domains),
		    is_active    = COALESCE($8, is_active),
		    started_at   = CASE WHEN $8 = TRUE  AND started_at IS NULL THEN NOW() ELSE started_at END,
		    ended_at     = CASE WHEN $8 = FALSE AND ended_at   IS NULL THEN NOW() ELSE ended_at   END
		WHERE id = $1
		RETURNING id, name, description, client_name, objective, scope_cidrs, scope_domains,
		          is_active, created_at, started_at, ended_at`,
		campaignID, req.Name, req.Description, req.ClientName, req.Objective,
		req.ScopeCIDRs, req.ScopeDomains, req.IsActive,
	).Scan(
		&c.ID, &c.Name, &c.Description, &c.ClientName, &c.Objective,
		&c.ScopeCIDRs, &c.ScopeDomains, &c.IsActive, &c.CreatedAt, &c.StartedAt, &c.EndedAt,
	)
	if err != nil {
		g.log.Error("update campaign", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, c)
}
