package storage

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// hostRouteTransport signs requests for publicAddr but routes TCP connections to internalAddr.
// This allows the presign client to generate URLs valid for the operator-facing hostname
// while its bucket-lookup HTTP calls still reach MinIO inside Docker.
type hostRouteTransport struct {
	internalAddr string
	inner        http.RoundTripper
}

func (t *hostRouteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	r2.URL.Host = t.internalAddr
	return t.inner.RoundTrip(r2)
}

const (
	BucketEvidence  = "evidence"
	BucketArtifacts = "artifacts"
)

var (
	Client       *minio.Client // for data operations (internal network)
	publicClient *minio.Client // for presigned URL generation (operator-facing address)
)

func Init(ctx context.Context) error {
	endpoint   := envOr("DM_MINIO_ADDR", "minio:9000")
	publicAddr := envOr("DM_MINIO_PUBLIC_ADDR", "localhost:9000")
	accessKey  := os.Getenv("DM_MINIO_ACCESS_KEY")
	secretKey  := os.Getenv("DM_MINIO_SECRET_KEY")
	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("minio: DM_MINIO_ACCESS_KEY and DM_MINIO_SECRET_KEY must be set")
	}

	opts := &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	}

	c, err := minio.New(endpoint, opts)
	if err != nil {
		return fmt.Errorf("minio: new client: %w", err)
	}
	Client = c

	// Presign client generates URLs for publicAddr but routes bucket-lookup
	// HTTP calls to the internal endpoint so they succeed from within Docker.
	publicOpts := &minio.Options{
		Creds:     credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:    false,
		Transport: &hostRouteTransport{internalAddr: endpoint, inner: http.DefaultTransport},
	}
	publicClient, _ = minio.New(publicAddr, publicOpts)

	for _, bucket := range []string{BucketEvidence, BucketArtifacts} {
		exists, err := c.BucketExists(ctx, bucket)
		if err != nil {
			return fmt.Errorf("minio: check bucket %s: %w", bucket, err)
		}
		if !exists {
			if err := c.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
				return fmt.Errorf("minio: make bucket %s: %w", bucket, err)
			}
		}
	}

	return nil
}

// UploadBytes stores raw bytes and returns a MinIO object path.
func UploadBytes(ctx context.Context, bucket, objectName string, data []byte, contentType string) (string, error) {
	if Client == nil {
		return "", fmt.Errorf("minio: not initialized")
	}
	_, err := Client.PutObject(ctx, bucket, objectName, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return "", fmt.Errorf("minio: put %s/%s: %w", bucket, objectName, err)
	}
	return fmt.Sprintf("minio://%s/%s", bucket, objectName), nil
}

// UploadFile uploads a file from the local filesystem.
func UploadFile(ctx context.Context, bucket, objectName, filePath, contentType string) (string, error) {
	if Client == nil {
		return "", fmt.Errorf("minio: not initialized")
	}
	_, err := Client.FPutObject(ctx, bucket, objectName, filePath,
		minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return "", fmt.Errorf("minio: fput %s/%s: %w", bucket, objectName, err)
	}
	return fmt.Sprintf("minio://%s/%s", bucket, objectName), nil
}

// PresignedDownloadURL returns a 24-hour download URL signed for the operator-facing address.
func PresignedDownloadURL(ctx context.Context, bucket, objectName string) (string, error) {
	pc := publicClient
	if pc == nil {
		pc = Client
	}
	if pc == nil {
		return "", fmt.Errorf("minio: not initialized")
	}
	u, err := pc.PresignedGetObject(ctx, bucket, objectName, 24*time.Hour, nil)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
