package main

import (
	"context"
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
	"google.golang.org/grpc"
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

	// --- gRPC server (agent + operator API) --------------------------------
	grpcAddr := envOr("DM_GRPC_ADDR", ":50051")
	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", grpcAddr, err)
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			api.AuthInterceptor(log),
			api.AuditInterceptor(log),
		),
		grpc.ChainStreamInterceptor(
			api.StreamAuthInterceptor(log),
		),
	)
	api.RegisterAll(grpcServer, sessionMgr, bus, log)

	log.Info("gRPC server listening", zap.String("addr", grpcAddr))
	go func() {
		if err := grpcServer.Serve(grpcLis); err != nil {
			log.Error("grpc serve", zap.Error(err))
		}
	}()

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
		c2Server.Addr = c2Addr
		log.Info("C2 listener starting", zap.String("addr", c2Addr))
		if err := c2Server.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Error("c2 listener error", zap.Error(err))
		}
	}()

	// --- Wait for shutdown --------------------------------------------------
	<-ctx.Done()
	log.Info("shutdown signal received")

	grpcServer.GracefulStop()

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
