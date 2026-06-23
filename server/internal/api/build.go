package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/BroJustLeaveMeAlone/C2-Adversary/server/internal/db"
	"github.com/BroJustLeaveMeAlone/C2-Adversary/server/internal/storage"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type buildView struct {
	ID          string     `json:"id"`
	CampaignID  string     `json:"campaign_id,omitempty"`
	Status      string     `json:"status"`
	TargetOS    string     `json:"target_os"`
	TargetArch  string     `json:"target_arch"`
	ArtifactURL string     `json:"artifact_url,omitempty"`
	SHA256      string     `json:"sha256,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

func (g *gateway) handleCreateBuild(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config struct {
			CampaignID   string `json:"campaign_id"`
			ListenerID   string `json:"listener_id"`
			TargetOS     string `json:"target_os"`
			TargetArch   string `json:"target_arch"`
			SleepSeconds int    `json:"sleep_seconds"`
			JitterPct    int    `json:"jitter_pct"`
			Ephemeral    bool   `json:"ephemeral"`
		} `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	cfg := req.Config
	if cfg.SleepSeconds == 0 {
		cfg.SleepSeconds = 30
	}
	if cfg.JitterPct == 0 {
		cfg.JitterPct = 20
	}
	if cfg.TargetOS == "" {
		cfg.TargetOS = "windows"
	}
	if cfg.TargetArch == "" {
		cfg.TargetArch = "x64"
	}

	// Resolve listener host/port from DB
	listenerHost := "host.docker.internal"
	listenerPort := 4443
	if cfg.ListenerID != "" {
		var host string
		var port int
		err := db.Pool.QueryRow(r.Context(),
			`SELECT bind_host, bind_port FROM listeners WHERE id = $1`, cfg.ListenerID,
		).Scan(&host, &port)
		if err == nil {
			listenerHost = host
			listenerPort = port
		}
	}

	operatorID := operatorIDFromCtx(r.Context())
	buildUUID := uuid.New().String()

	var campaignID *string
	if cfg.CampaignID != "" && cfg.CampaignID != "00000000-0000-0000-0000-000000000000" {
		campaignID = &cfg.CampaignID
	}

	evasionFlags := fmt.Sprintf(`{"ephemeral":%v}`, cfg.Ephemeral)

	var b buildView
	err := db.Pool.QueryRow(r.Context(), `
		INSERT INTO builds (campaign_id, operator_id, target_os, target_arch,
		                    listener_id, sleep_seconds, jitter_pct, evasion_flags, ephemeral, build_uuid)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
		RETURNING id, COALESCE(campaign_id::text,''), status, target_os, target_arch,
		          COALESCE(artifact_url,''), COALESCE(sha256,''), created_at, completed_at`,
		campaignID, operatorID, cfg.TargetOS, cfg.TargetArch,
		nilIfEmpty(cfg.ListenerID), cfg.SleepSeconds, cfg.JitterPct,
		evasionFlags, cfg.Ephemeral, buildUUID,
	).Scan(&b.ID, &b.CampaignID, &b.Status, &b.TargetOS, &b.TargetArch,
		&b.ArtifactURL, &b.SHA256, &b.CreatedAt, &b.CompletedAt)
	if err != nil {
		g.log.Error("create build record", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}

	// Kick off the build in the background
	go g.runBuild(b.ID, buildUUID, cfg.CampaignID, listenerHost, strconv.Itoa(listenerPort),
		cfg.SleepSeconds, cfg.JitterPct)

	writeJSON(w, http.StatusCreated, b)
}

func (g *gateway) handleGetBuild(w http.ResponseWriter, r *http.Request) {
	var b buildView
	err := db.Pool.QueryRow(r.Context(), `
		SELECT id, COALESCE(campaign_id::text,''), status, target_os, target_arch,
		       COALESCE(artifact_url,''), COALESCE(sha256,''), created_at, completed_at
		FROM builds WHERE id = $1`, r.PathValue("id"),
	).Scan(&b.ID, &b.CampaignID, &b.Status, &b.TargetOS, &b.TargetArch,
		&b.ArtifactURL, &b.SHA256, &b.CreatedAt, &b.CompletedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "build not found")
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (g *gateway) handleListBuilds(w http.ResponseWriter, r *http.Request) {
	campaignID := r.URL.Query().Get("campaign_id")

	query := `
		SELECT id, COALESCE(campaign_id::text,''), status, target_os, target_arch,
		       COALESCE(artifact_url,''), COALESCE(sha256,''), created_at, completed_at
		FROM builds WHERE 1=1`
	args := []any{}
	n := 1
	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", n)
		args = append(args, campaignID)
		n++
	}
	query += " ORDER BY created_at DESC LIMIT 50"

	rows, err := db.Pool.Query(r.Context(), query, args...)
	if err != nil {
		g.log.Error("list builds", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	defer rows.Close()

	var out []buildView
	for rows.Next() {
		var b buildView
		if err := rows.Scan(&b.ID, &b.CampaignID, &b.Status, &b.TargetOS, &b.TargetArch,
			&b.ArtifactURL, &b.SHA256, &b.CreatedAt, &b.CompletedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		out = append(out, b)
	}
	if out == nil {
		out = []buildView{}
	}
	writeJSON(w, http.StatusOK, out)
}

// runBuild executes the Docker build in a background goroutine and updates the build record.
func (g *gateway) runBuild(buildID, buildUUID, campaignID, c2Host, c2Port string, sleepSecs, jitterPct int) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	setBuildStatus := func(status string, artifactURL, sha256 string) {
		_, err := db.Pool.Exec(context.Background(), `
			UPDATE builds SET status = $2, artifact_url = NULLIF($3,''), sha256 = NULLIF($4,''), completed_at = NOW()
			WHERE id = $1`, buildID, status, artifactURL, sha256)
		if err != nil {
			g.log.Error("update build status", zap.String("build_id", buildID), zap.Error(err))
		}
	}

	_, _ = db.Pool.Exec(context.Background(), `UPDATE builds SET status = 'building' WHERE id = $1`, buildID)

	imageTag := "dm-agent-build-" + buildID

	// docker build
	buildArgs := []string{
		"build",
		"-f", "/workspace/deploy/docker/Dockerfile.agent",
		"--build-arg", "DM_C2_HOST=" + c2Host,
		"--build-arg", "DM_C2_PORT=" + c2Port,
		"--build-arg", "DM_SLEEP_SECS=" + strconv.Itoa(sleepSecs),
		"--build-arg", "DM_JITTER_PCT=" + strconv.Itoa(jitterPct),
		"--build-arg", "DM_BUILD_UUID=" + buildUUID,
		"--build-arg", "DM_TLS_SKIP_VERIFY=false",
		"--build-arg", "DM_NO_EVASION=false",
	}
	if campaignID != "" && campaignID != "00000000-0000-0000-0000-000000000000" {
		buildArgs = append(buildArgs, "--build-arg", "DM_CAMPAIGN_ID="+campaignID)
	}
	buildArgs = append(buildArgs, "-t", imageTag, "/workspace")

	buildCmd := exec.CommandContext(ctx, "docker", buildArgs...)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		g.log.Error("docker build failed", zap.String("build_id", buildID), zap.Error(err))
		setBuildStatus("failed", "", "")
		return
	}

	// Extract binary from image into the shared artifacts volume.
	// The volume name must match the Compose-managed volume (project_build_artifacts).
	buildVolume := os.Getenv("DM_BUILD_VOLUME")
	if buildVolume == "" {
		buildVolume = "dungeonmaster_build_artifacts"
	}
	outPath := "/artifacts/" + buildID + ".exe"
	extractCmd := exec.CommandContext(ctx,
		"docker", "run", "--rm",
		"-v", buildVolume+":/out",
		imageTag, "sh", "-c", "cp /dm-agent.exe /out/"+buildID+".exe",
	)
	if err := extractCmd.Run(); err != nil {
		g.log.Error("docker extract failed", zap.String("build_id", buildID), zap.Error(err))
		setBuildStatus("failed", "", "")
		return
	}

	// Clean up the build image
	exec.Command("docker", "rmi", imageTag).Run() //nolint

	// Upload to MinIO
	artifactURL, err := storage.UploadFile(ctx, storage.BucketArtifacts, buildID+".exe", outPath, "application/octet-stream")
	if err != nil {
		g.log.Error("minio upload failed", zap.String("build_id", buildID), zap.Error(err))
		// Fall back to local path URL so it's still accessible
		setBuildStatus("complete", "file:///artifacts/"+buildID+".exe", "")
		return
	}

	// Get a presigned download URL
	downloadURL, _ := storage.PresignedDownloadURL(ctx, storage.BucketArtifacts, buildID+".exe")
	if downloadURL == "" {
		downloadURL = artifactURL
	}

	setBuildStatus("complete", downloadURL, "")
	g.log.Info("build complete", zap.String("build_id", buildID), zap.String("url", downloadURL))

	// Clean up local artifact file
	os.Remove(outPath)
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
