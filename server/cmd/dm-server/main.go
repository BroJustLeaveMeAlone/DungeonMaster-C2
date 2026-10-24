package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/api"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/collab"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/session"
	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/storage"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	log, _ := zap.NewProduction()
	defer log.Sync()

	if err := run(log); err != nil {
		log.Fatal("server error", zap.Error(err))
	}
}

func run(log *zap.Logger) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// --- Database -----------------------------------------------------------
	if err := db.Init(ctx); err != nil {
		return fmt.Errorf("database init: %w", err)
	}
	log.Info("database connected")

	// --- Seed default listener if none exist --------------------------------
	c2Addr := envOr("DM_C2_ADDR", ":4443")
	if err := db.SeedDefaultListener(ctx, c2Addr); err != nil {
		log.Warn("seed default listener", zap.Error(err))
	}

	// --- MinIO (evidence + build artifacts) ---------------------------------
	if err := storage.Init(ctx); err != nil {
		log.Warn("minio init failed â€” evidence upload disabled", zap.Error(err))
	} else {
		log.Info("minio connected")
	}

	// --- Redis --------------------------------------------------------------
	rdb := redis.NewClient(&redis.Options{
		Addr:     envOr("DM_REDIS_ADDR", "localhost:6379"),
		Password: os.Getenv("DM_REDIS_PASSWORD"),
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis connect: %w", err)
	}
	log.Info("redis connected")

	// --- Collaboration bus --------------------------------------------------
	bus := collab.NewBus(rdb, log)
	go func() {
		if err := bus.Start(ctx); err != nil {
			log.Error("collaboration bus error", zap.Error(err))
		}
	}()

	// --- Session manager ----------------------------------------------------
	sessionMgr := session.NewManager(log)

	// Mark stale sessions periodically
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := sessionMgr.MarkStaleSessions(ctx)
				if err != nil {
					log.Error("mark stale sessions", zap.Error(err))
				} else if n > 0 {
					log.Info("marked sessions as stale", zap.Int64("count", n))
				}
			}
		}
	}()

	// --- gRPC server (Phase 2 — not started yet) ----------------------------
	// dm.proto defines the full service contracts; RegisterAll is the stub.
	// Set DM_GRPC_ADDR to enable the listener once services are wired.
	grpcAddr := os.Getenv("DM_GRPC_ADDR")
	if grpcAddr != "" {
		log.Warn("DM_GRPC_ADDR is set but gRPC services are not yet implemented — listener skipped")
	}

	// --- HTTP gateway (REST + SSE for the web UI) --------------------------
	httpAddr := envOr("DM_HTTP_ADDR", ":8080")
	httpServer := &http.Server{
		Addr:         httpAddr,
		Handler:      api.NewHTTPGateway(grpcAddr, sessionMgr, bus, rdb, log),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // 0 = no timeout; needed for streaming endpoints
		IdleTimeout:  120 * time.Second,
	}

	log.Info("HTTP gateway listening", zap.String("addr", httpAddr))
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http serve", zap.Error(err))
		}
	}()

	// --- C2 listener (agent callbacks) ------------------------------------
	// The C2 listener runs on a separate port and handles raw agent HTTP callbacks.
	// It is separate from the operator API so it can be exposed on a different
	// network interface or behind a redirector.
	c2Addr = envOr("DM_C2_ADDR", ":4443")
	c2Server := api.NewC2Server(sessionMgr, bus, log)
	go func() {
		certFile := envOr("DM_TLS_CERT", "tls/server.crt")
		keyFile  := envOr("DM_TLS_KEY",  "tls/server.key")
		log.Info("C2 listener starting", zap.String("addr", c2Addr))
		if err := serveC2TLS(c2Server, c2Addr, certFile, keyFile, log); err != nil {
			log.Error("c2 listener error", zap.Error(err))
		}
	}()

	// --- TCP C2 listener (optional raw TCP channel) -----------------------
	if tcpAddr := os.Getenv("DM_TCP_C2_ADDR"); tcpAddr != "" {
		tcpServer := api.NewTCPServer(sessionMgr, bus, log)
		go func() {
			if err := tcpServer.Serve(ctx, tcpAddr); err != nil {
				log.Error("TCP C2 error", zap.Error(err))
			}
		}()
	}

	// --- Wait for shutdown --------------------------------------------------
	<-ctx.Done()
	log.Info("shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("http shutdown", zap.Error(err))
	}

	db.Pool.Close()
	rdb.Close()
	log.Info("server stopped cleanly")
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// serveC2TLS wraps the C2 http.Server with a logging TCP listener so every
// inbound connection attempt is recorded before TLS negotiation begins.
// This makes it possible to distinguish "agent never connected" (abort_if_sandboxed
// or pre-network exit) from "agent connected but TLS failed" (cert/verify mismatch).
func serveC2TLS(srv *http.Server, addr, certFile, keyFile string, log *zap.Logger) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load tls cert: %w", err)
	}
	cfg := srv.TLSConfig.Clone()
	cfg.Certificates = []tls.Certificate{cert}

	raw, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp listen %s: %w", addr, err)
	}
	return srv.Serve(tls.NewListener(tcpLogListener{raw, log}, cfg))
}

type tcpLogListener struct {
	net.Listener
	log *zap.Logger
}

func (l tcpLogListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.log.Info("c2 tcp connect", zap.String("remote", conn.RemoteAddr().String()))
	}
	return conn, err
}
