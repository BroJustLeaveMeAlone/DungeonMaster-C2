package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
	"go.uber.org/zap"
)

type credentialView struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"`
	CampaignID string    `json:"campaign_id"`
	Hostname   string    `json:"hostname"`
	Username   string    `json:"username"`
	Domain     string    `json:"domain"`
	Secret     string    `json:"secret"`
	Kind       string    `json:"kind"`
	Source     string    `json:"source"`
	Notes      string    `json:"notes"`
	CreatedAt  time.Time `json:"created_at"`
}

func (g *gateway) handleVaultList(w http.ResponseWriter, r *http.Request) {
	campaignID := r.URL.Query().Get("campaign_id")
	kind := r.URL.Query().Get("kind")
	search := r.URL.Query().Get("search")

	query := `SELECT id, session_id, campaign_id, hostname, username, domain, secret, kind, source, notes, created_at
	          FROM vault_credentials WHERE 1=1`
	args := []any{}
	n := 1
	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", n)
		args = append(args, campaignID)
		n++
	}
	if kind != "" {
		query += fmt.Sprintf(" AND kind = $%d", n)
		args = append(args, kind)
		n++
	}
	if search != "" {
		query += fmt.Sprintf(" AND (username ILIKE $%d OR hostname ILIKE $%d OR domain ILIKE $%d)", n, n, n)
		args = append(args, "%"+search+"%")
		n++
	}
	_ = n
	query += " ORDER BY created_at DESC"

	rows, err := db.Pool.Query(r.Context(), query, args...)
	if err != nil {
		g.log.Error("vault list", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	defer rows.Close()

	out := []credentialView{}
	for rows.Next() {
		var c credentialView
		if err := rows.Scan(&c.ID, &c.SessionID, &c.CampaignID, &c.Hostname, &c.Username,
			&c.Domain, &c.Secret, &c.Kind, &c.Source, &c.Notes, &c.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *gateway) handleVaultCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID  string `json:"session_id"`
		CampaignID string `json:"campaign_id"`
		Hostname   string `json:"hostname"`
		Username   string `json:"username"`
		Domain     string `json:"domain"`
		Secret     string `json:"secret"`
		Kind       string `json:"kind"`
		Source     string `json:"source"`
		Notes      string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Kind == "" {
		req.Kind = "other"
	}
	if req.Source == "" {
		req.Source = "manual"
	}

	var c credentialView
	err := db.Pool.QueryRow(r.Context(), `
		INSERT INTO vault_credentials (session_id, campaign_id, hostname, username, domain, secret, kind, source, notes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, session_id, campaign_id, hostname, username, domain, secret, kind, source, notes, created_at`,
		req.SessionID, req.CampaignID, req.Hostname, req.Username, req.Domain,
		req.Secret, req.Kind, req.Source, req.Notes,
	).Scan(&c.ID, &c.SessionID, &c.CampaignID, &c.Hostname, &c.Username,
		&c.Domain, &c.Secret, &c.Kind, &c.Source, &c.Notes, &c.CreatedAt)
	if err != nil {
		g.log.Error("vault create", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (g *gateway) handleVaultDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tag, err := db.Pool.Exec(r.Context(), `DELETE FROM vault_credentials WHERE id = $1`, id)
	if err != nil {
		g.log.Error("vault delete", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *gateway) handleVaultExport(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Pool.Query(r.Context(), `
		SELECT id, session_id, campaign_id, hostname, username, domain, secret, kind, source, notes, created_at
		FROM vault_credentials ORDER BY created_at DESC`)
	if err != nil {
		g.log.Error("vault export", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Disposition", `attachment; filename="vault_credentials.csv"`)
	w.Header().Set("Content-Type", "text/csv")
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ID", "SessionID", "CampaignID", "Hostname", "Username", "Domain", "Secret", "Kind", "Source", "Notes", "CreatedAt"})

	for rows.Next() {
		var c credentialView
		if err := rows.Scan(&c.ID, &c.SessionID, &c.CampaignID, &c.Hostname, &c.Username,
			&c.Domain, &c.Secret, &c.Kind, &c.Source, &c.Notes, &c.CreatedAt); err != nil {
			break
		}
		_ = cw.Write([]string{
			c.ID, c.SessionID, c.CampaignID, c.Hostname, c.Username,
			c.Domain, c.Secret, c.Kind, c.Source, c.Notes,
			c.CreatedAt.Format(time.RFC3339),
		})
	}
	cw.Flush()
}
